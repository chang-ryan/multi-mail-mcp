/**
 * IMAP operations — READ ONLY — for Proton (via Bridge) and Gmail.
 *
 * Every mailbox is opened with readOnly:true (IMAP EXAMINE), hard-wired in openRO(), and
 * imapflow fetches bodies with BODY.PEEK. Nothing here can flag, move, delete, append,
 * mark read, or send. Messages are addressed as (folder, uid); UIDs are stable per folder.
 */

import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { ImapFlow } from 'imapflow';
import { simpleParser } from 'mailparser';
import { getPassword, saveRoot } from './config.js';
import { logoutBounded, withOperationSlot } from './runtime.js';
import { HIDDEN_CHARS } from './security.js';

export { stripHidden } from './security.js';

const MAX_INLINE_ATTACHMENT_BYTES = 2 * 1024 * 1024;
const MAX_SAVE_BYTES = 25 * 1024 * 1024;
const MAX_SAVE_COUNT = 20;
const MAX_MESSAGE_BYTES = 40 * 1024 * 1024; // larger raw messages are not downloaded or parsed
const MAX_THREAD_MESSAGES = 25;
const OPERATION_TIMEOUT_MS = 120000;

/**
 * Attachment types that may be written to disk. Executables, scripts, installers, disk
 * images, archives, macro-enabled Office formats and HTML (which can script) are refused.
 */
const SAVE_EXTENSIONS = new Set([
  'pdf',
  'png',
  'jpg',
  'jpeg',
  'gif',
  'webp',
  'heic',
  'tif',
  'tiff',
  'txt',
  'csv',
  'tsv',
  'md',
  'rtf',
  'eml',
  'ics',
  'docx',
  'xlsx',
  'pptx',
  'odt',
  'ods',
  'odp',
  'pages',
  'numbers',
  'key',
]);

/** imapflow methods that change server state. None is used; all are disabled per connection. */
const MUTATING_METHODS = [
  'append',
  'messageFlagsSet',
  'messageFlagsAdd',
  'messageFlagsRemove',
  'setFlagColor',
  'messageDelete',
  'messageCopy',
  'messageMove',
  'mailboxCreate',
  'mailboxRename',
  'mailboxDelete',
  'mailboxSubscribe',
  'mailboxUnsubscribe',
  'mailboxClose', // IMAP CLOSE can implicitly expunge messages flagged Deleted
];

// --- Connection ---------------------------------------------------------------

/**
 * Belt and braces for read-only: even if a future edit called a mutating imapflow method,
 * it would throw before reaching the wire.
 */
function disableWrites(client) {
  if (typeof client.mailboxOpen === 'function') {
    const open = client.mailboxOpen.bind(client);
    Object.defineProperty(client, 'mailboxOpen', {
      value: (folder, options) => {
        if (options?.readOnly !== true)
          throw new Error('read-only server: writable mailboxOpen is disabled');
        return open(folder, options);
      },
      writable: false,
      configurable: false,
    });
  }
  for (const name of MUTATING_METHODS) {
    Object.defineProperty(client, name, {
      value: () => {
        throw new Error(`read-only server: ${name} is disabled`);
      },
      writable: false,
      configurable: false,
    });
  }
}

function createReadOnlyClient(account, password) {
  const client = new ImapFlow({
    host: account.host,
    port: account.port,
    secure: account.secure,
    ...(account.doSTARTTLS === false ? { doSTARTTLS: false } : {}),
    ...(account.tls ? { tls: account.tls } : {}),
    auth: { user: account.user, pass: password },
    logger: false,
    emitLogs: false,
    connectionTimeout: 15000,
    greetingTimeout: 15000,
    socketTimeout: 60000,
    disableAutoIdle: true,
    disableCompression: true,
    // Enforce limits in the wire parser, before a literal can be allocated or MIME-parsed.
    maxLiteralSize: MAX_MESSAGE_BYTES + 1,
    maxResponseSize: MAX_MESSAGE_BYTES + 1024 * 1024,
    maxLineLength: 1024 * 1024,
    maxResponseTokens: 50000,
  });
  disableWrites(client);
  // imapflow emits 'error' for socket faults after connect; without a listener node would crash.
  client.on('error', () => {});
  return client;
}

async function withClient(account, fn) {
  return withOperationSlot(() => withClientConnection(account, fn));
}

async function withClientConnection(account, fn) {
  const client = createReadOnlyClient(account, await getPassword(account));
  try {
    await client.connect();
  } catch (err) {
    client.close();
    throw new Error(connectHint(account, err));
  }

  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      client.close();
      reject(
        new Error(`[${account.id}] operation timed out after ${OPERATION_TIMEOUT_MS / 1000}s`),
      );
    }, OPERATION_TIMEOUT_MS);
  });
  try {
    return await Promise.race([fn(client), deadline]);
  } finally {
    clearTimeout(timer);
    await logoutBounded(client);
  }
}

function connectHint(account, err) {
  const reason = String(err.responseText || err.message || 'unknown error').slice(0, 200);
  const base = `[${account.id}] IMAP login failed: ${reason}.`;
  if (account.type === 'proton') {
    return (
      `${base} Is Proton Mail Bridge running, and is ${account.user} signed in to it? ` +
      'The password is the Bridge-generated one, not the Proton account password.'
    );
  }
  return (
    `${base} Gmail needs an app password (Google Account > Security > 2-Step Verification > ` +
    'App passwords). Workspace accounts also need IMAP enabled by the admin.'
  );
}

/**
 * The single place a mailbox is opened. readOnly is a literal (IMAP EXAMINE). If the server
 * answers that the mailbox is READ-WRITE anyway, refuse to use it.
 */
async function openRO(client, folder) {
  const lock = await client.getMailboxLock(folder, { readOnly: true });
  if (client.mailbox?.readOnly !== true) {
    lock.release();
    throw new Error(
      `Server opened "${folder}" without confirmed read-only mode despite EXAMINE; refusing`,
    );
  }
  return lock;
}

// --- Helpers -------------------------------------------------------------------

const addr = (list) =>
  (list || []).map((a) => (a.name ? `${a.name} <${a.address}>` : a.address)).join(', ');

function summary(msg, folder) {
  const e = msg.envelope || {};
  return {
    folder,
    uid: msg.uid,
    date: (e.date || msg.internalDate)?.toISOString?.() || null,
    from: addr(e.from),
    to: addr(e.to),
    ...(e.cc?.length ? { cc: addr(e.cc) } : {}),
    subject: e.subject || '(no subject)',
    unread: msg.flags ? !msg.flags.has('\\Seen') : undefined,
    ...(msg.labels ? { labels: [...msg.labels] } : {}),
    ...(msg.threadId ? { thread_id: msg.threadId } : {}),
    message_id: e.messageId || null,
  };
}

async function fetchSummaries(client, account, uids, folder) {
  if (!uids.length) return [];
  const query = { uid: true, envelope: true, flags: true, internalDate: true };
  if (account.type === 'gmail') Object.assign(query, { labels: true, threadId: true });
  const out = [];
  for await (const m of client.fetch(uids, query, { uid: true })) out.push(summary(m, folder));
  return out;
}

async function selectableFolders(client) {
  const boxes = await client.list();
  return boxes.filter((b) => !b.flags?.has('\\Noselect') && !b.flags?.has('\\NonExistent'));
}

async function allMailPath(client) {
  const boxes = await selectableFolders(client);
  const all =
    boxes.find((b) => b.specialUse === '\\All') ||
    boxes.find((b) => /^(\[Gmail\]\/)?All Mail$/i.test(b.path));
  if (!all) throw new Error('This account has no All Mail folder');
  return all.path;
}

const byDateDesc = (a, b) => new Date(b.date || 0) - new Date(a.date || 0);

function clip(text, max) {
  if (!text) return { body: '', truncated: false };
  return text.length > max
    ? { body: text.slice(0, max), truncated: true, body_chars_total: text.length }
    : { body: text, truncated: false };
}

export const PARSER_OPTIONS = {
  maxHtmlLengthToParse: 2 * 1024 * 1024, // html-to-text on hostile HTML is the slow path
  skipImageLinks: true,
  keepCidLinks: false,
};

async function parseOne(client, uid) {
  const id = String(uid);
  // Check size first, so a hostile multi-hundred-MB message is never pulled into memory.
  const head = await client.fetchOne(id, { uid: true, size: true }, { uid: true });
  if (!head) throw new Error(`No message with uid ${uid} in this folder`);
  if (!Number.isSafeInteger(head.size) || head.size < 0) {
    throw new Error('Server did not provide a valid message size');
  }
  if (head.size > MAX_MESSAGE_BYTES) {
    throw new Error(`Message is ${head.size} bytes, over the ${MAX_MESSAGE_BYTES}-byte limit`);
  }
  const msg = await client.fetchOne(
    id,
    { uid: true, source: { start: 0, maxLength: MAX_MESSAGE_BYTES + 1 }, flags: true },
    { uid: true },
  );
  if (!msg?.source) throw new Error(`No message with uid ${uid} in this folder`);
  if (msg.source.length > MAX_MESSAGE_BYTES) {
    throw new Error('Downloaded message exceeds the 40 MB limit');
  }
  return { parsed: await simpleParser(msg.source, PARSER_OPTIONS), flags: msg.flags };
}

export function fullMessage(parsed, folder, uid, maxChars) {
  return {
    folder,
    uid,
    date: parsed.date?.toISOString() || null,
    from: parsed.from?.text || '',
    to: parsed.to?.text || '',
    ...(parsed.cc ? { cc: parsed.cc.text } : {}),
    subject: parsed.subject || '(no subject)',
    message_id: parsed.messageId || null,
    in_reply_to: parsed.inReplyTo || null,
    attachments: (parsed.attachments || []).map((a, i) => ({
      index: i,
      filename: safeName(a.filename, i),
      content_type: a.contentType,
      size: a.size,
    })),
    ...clip(parsed.text || '', maxChars),
  };
}

// --- Operations ---------------------------------------------------------------

export async function listFolders(account) {
  return withClient(account, async (client) => {
    const boxes = await selectableFolders(client);
    return boxes.map((b) => ({
      path: b.path,
      ...(b.specialUse ? { special_use: b.specialUse } : {}),
    }));
  });
}

export async function listMessages(account, { folder = 'INBOX', limit = 20, unreadOnly = false }) {
  return withClient(account, async (client) => {
    const lock = await openRO(client, folder);
    try {
      const uids =
        (await client.search(unreadOnly ? { seen: false } : { all: true }, { uid: true })) || [];
      const recent = uids.slice(-limit);
      const msgs = await fetchSummaries(client, account, recent, folder);
      return { folder, total_matching: uids.length, messages: msgs.sort(byDateDesc) };
    } finally {
      lock.release();
    }
  });
}

/**
 * Search. Gmail searches All Mail once (labels are reported per message). Proton walks
 * every folder and collapses All Mail duplicates, so the result names the folder a
 * message is actually filed in.
 */
export async function search(account, criteria, limit = 40) {
  const { query, text, from, to, subject, body, since, before, unread, folders } = criteria;
  const q = {};
  if (query) {
    if (account.type !== 'gmail')
      throw new Error('"query" (Gmail search syntax) only works on Gmail accounts');
    q.gmraw = query;
  }
  if (text) q.text = text;
  if (from) q.from = from;
  if (to) q.to = to;
  if (subject) q.subject = subject;
  if (body) q.body = body;
  if (since) q.since = new Date(`${since}T00:00:00`);
  if (before) q.before = new Date(`${before}T00:00:00`);
  if (unread) q.seen = false;
  if (!Object.keys(q).length) throw new Error('Give at least one search criterion');

  return withClient(account, async (client) => {
    let targets = folders?.length ? folders : null;
    if (!targets) {
      targets =
        account.type === 'gmail'
          ? [await allMailPath(client)]
          : (await selectableFolders(client)).map((b) => b.path);
    }

    if (targets.length > 100) throw new Error('Over 100 folders; select folders explicitly');

    const hits = [];
    const skipped = [];
    let matched = 0;
    for (const folder of targets) {
      let lock;
      try {
        lock = await openRO(client, folder);
        const uids = (await client.search(q, { uid: true })) || [];
        matched += uids.length;
        hits.push(...(await fetchSummaries(client, account, uids.slice(-limit), folder)));
      } catch (err) {
        skipped.push({ folder, reason: err.responseText || err.message });
      } finally {
        lock?.release();
      }
    }

    // Proton's All Mail mirrors every other folder. Collapse on Message-ID, preferring the
    // real folder, and keep the other locations.
    const byKey = new Map();
    for (const m of hits) {
      const key = m.message_id || `${m.from}|${m.date}|${m.subject}`;
      const prev = byKey.get(key);
      if (!prev) {
        byKey.set(key, { ...m, also_in: [] });
        continue;
      }
      if (/^All Mail$/i.test(prev.folder) && !/^All Mail$/i.test(m.folder)) {
        byKey.set(key, { ...m, also_in: [...prev.also_in, prev.folder] });
      } else if (!prev.also_in.includes(m.folder) && prev.folder !== m.folder) {
        prev.also_in.push(m.folder);
      }
    }
    const unique = [...byKey.values()]
      .map((m) => {
        if (!m.also_in.length) delete m.also_in;
        return m;
      })
      .sort(byDateDesc);

    return {
      searched_folders: targets.length,
      matched_before_limit: matched,
      returned: Math.min(unique.length, limit),
      messages: unique.slice(0, limit),
      ...(skipped.length ? { skipped } : {}),
    };
  });
}

export async function getMessage(account, { folder, uid, maxChars = 20000 }) {
  return withClient(account, async (client) => {
    const lock = await openRO(client, folder);
    try {
      const { parsed } = await parseOne(client, uid);
      return fullMessage(parsed, folder, uid, maxChars);
    } finally {
      lock.release();
    }
  });
}

/**
 * Whole thread. Gmail: X-GM-THRID in All Mail. Proton: Message-ID / References /
 * In-Reply-To chain, searched in All Mail.
 */
export async function getThread(account, { folder, uid, maxChars = 8000 }) {
  return withClient(account, async (client) => {
    let seed;
    let threadId = null;
    {
      const lock = await openRO(client, folder);
      try {
        seed = (await parseOne(client, uid)).parsed;
        if (account.type === 'gmail') {
          const m = await client.fetchOne(
            String(uid),
            { uid: true, threadId: true },
            { uid: true },
          );
          threadId = m?.threadId || null;
        }
      } finally {
        lock.release();
      }
    }

    const allMail = await allMailPath(client);
    const lock = await openRO(client, allMail);
    try {
      const uids = new Set();
      if (threadId) {
        for (const u of (await client.search({ threadId }, { uid: true })) || []) uids.add(u);
      } else {
        const refs = [seed.messageId, seed.inReplyTo, ...[].concat(seed.references || [])].filter(
          // biome-ignore lint/suspicious/noControlCharactersInRegex: Reject control characters in sender-controlled message references.
          (r) => typeof r === 'string' && r.length < 1000 && !/[\x00-\x1f\x7f]/.test(r),
        );
        // References is sender-controlled; cap it so one message cannot trigger thousands of searches.
        for (const id of [...new Set(refs)].slice(-50)) {
          for (const u of (await client.search({ header: { 'message-id': id } }, { uid: true })) ||
            [])
            uids.add(u);
        }
        if (
          typeof seed.messageId === 'string' &&
          seed.messageId.length < 1000 &&
          // biome-ignore lint/suspicious/noControlCharactersInRegex: Reject control characters before an IMAP search.
          !/[\x00-\x1f\x7f]/.test(seed.messageId)
        ) {
          for (const u of (await client.search(
            { header: { references: seed.messageId } },
            { uid: true },
          )) || [])
            uids.add(u);
        }
      }

      const list = [...uids].sort((a, b) => a - b).slice(-MAX_THREAD_MESSAGES);
      const messages = [];
      for (const u of list) {
        const { parsed } = await parseOne(client, u);
        messages.push(fullMessage(parsed, allMail, u, maxChars));
      }
      if (!messages.length) messages.push(fullMessage(seed, folder, uid, maxChars));
      messages.sort((a, b) => new Date(a.date || 0) - new Date(b.date || 0));
      return {
        count: messages.length,
        ...(uids.size > MAX_THREAD_MESSAGES
          ? { note: `Thread has ${uids.size} messages; newest ${MAX_THREAD_MESSAGES} shown` }
          : {}),
        messages,
      };
    } finally {
      lock.release();
    }
  });
}

/** A filename that cannot escape the directory, spoof its extension, or confuse a shell. */
function safeName(name, index) {
  let base = path
    .basename(
      String(name || '')
        .normalize('NFC')
        .replace(/\\/g, '/'),
    )
    .replace(HIDDEN_CHARS, '')
    .replace(/[/:*?"<>|]/g, '_')
    .replace(/^[.\-\s]+/, '')
    .trim();
  if (!base) base = `attachment-${index}`;
  if (base.length <= 150) return base;
  const ext = path.extname(base);
  // An unusually long extension is not a useful file type; do not preserve it.
  if (ext.length > 20) return `attachment-${index}`;
  return base.slice(0, 150 - ext.length) + ext;
}

const extOf = (name) => path.extname(name).slice(1).toLowerCase();

/**
 * Resolve the target directory through symlinks and confirm it is still inside the save root,
 * so a symlink planted in the save folder cannot redirect writes elsewhere.
 */
function resolveSaveDir(root, subdir) {
  if (subdir && (path.isAbsolute(subdir) || /[\0\r\n]/.test(subdir)))
    throw new Error('subdir must be a relative path');
  const dir = subdir ? path.resolve(root, subdir) : root;
  const inside = (p) => p === root || p.startsWith(root + path.sep);
  if (!inside(dir)) throw new Error('subdir must stay inside the save root');
  // Walk one level at a time, resolving each existing component through symlinks before
  // creating anything beneath it, so nothing is ever created outside the root.
  let cur = root;
  for (const seg of path.relative(root, dir).split(path.sep).filter(Boolean)) {
    const next = path.join(cur, seg);
    if (!fs.existsSync(next)) fs.mkdirSync(next, { mode: 0o700 });
    const real = fs.realpathSync(next);
    if (!inside(real)) throw new Error('subdir resolves outside the save root');
    if (!fs.statSync(real).isDirectory()) throw new Error('subdir is not a directory');
    cur = real;
  }
  return cur;
}

/** Write without following or replacing anything that exists (O_CREAT|O_EXCL). */
function writeExclusive(dir, name, content) {
  const ext = path.extname(name);
  const stem = name.slice(0, name.length - ext.length);
  for (let i = 1; i < 1000; i++) {
    const p = path.join(dir, i === 1 ? name : `${stem} (${i})${ext}`);
    try {
      fs.writeFileSync(p, content, { flag: 'wx', mode: 0o600 });
      return p;
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
    }
  }
  throw new Error(`Could not find a free filename for ${name}`);
}

/** Mark a saved file as downloaded from the internet, as browsers do, so Gatekeeper treats it so. */
function quarantine(file) {
  const flags = `0081;${Math.floor(Date.now() / 1000).toString(16)};multi-mail-mcp;`;
  return new Promise((resolve) => {
    execFile(
      '/usr/bin/xattr',
      ['-w', 'com.apple.quarantine', flags, file],
      { timeout: 5000 },
      (err) => resolve(!err),
    );
  });
}

/**
 * Attachments. With save:true, files are written under MAIL_SAVE_ROOT (never overwriting)
 * and only paths come back. Otherwise content returns as base64, capped in size.
 */
export async function getAttachments(account, { folder, uid, indexes, save, subdir }) {
  // Refuse disabled saves before looking up a password or downloading any message.
  if (save && !saveRoot())
    throw new Error('Saving is off for this harness (MAIL_SAVE_ROOT is not set)');
  return withClient(account, async (client) => {
    const lock = await openRO(client, folder);
    let parsed;
    try {
      ({ parsed } = await parseOne(client, uid));
    } finally {
      lock.release();
    }

    return attachmentResult(parsed, { indexes, save, subdir });
  });
}

/** Shared by the IMAP and Gmail API backends; all saving safeguards stay in one place. */
export async function attachmentResult(parsed, { indexes, save, subdir }) {
  let atts = (parsed.attachments || []).map((a, i) => ({ ...a, index: i }));
  if (indexes?.length) atts = atts.filter((a) => indexes.includes(a.index));
  if (!atts.length) return { attachments: [] };

  if (save) {
    const root = saveRoot();
    if (!root) throw new Error('Saving is off for this harness (MAIL_SAVE_ROOT is not set)');
    if (atts.length > MAX_SAVE_COUNT)
      throw new Error(`Over ${MAX_SAVE_COUNT} attachments; pick indexes`);
    const dir = resolveSaveDir(root, subdir);
    const saved = [];
    const refused = [];
    for (const a of atts) {
      const name = safeName(a.filename, a.index);
      const ext = extOf(name);
      if (!SAVE_EXTENSIONS.has(ext)) {
        refused.push({
          index: a.index,
          filename: name,
          reason: `.${ext || '(none)'} is not a saveable type`,
        });
      } else if (a.size > MAX_SAVE_BYTES) {
        refused.push({ index: a.index, filename: name, reason: `over ${MAX_SAVE_BYTES} bytes` });
      } else {
        const p = writeExclusive(dir, name, a.content);
        const quarantined = await quarantine(p);
        saved.push({
          index: a.index,
          filename: name,
          content_type: a.contentType,
          size: a.size,
          path: p,
          quarantined,
          ...(!quarantined
            ? { warning: 'macOS quarantine marking failed; the file was saved without it' }
            : {}),
        });
      }
    }
    return { saved, ...(refused.length ? { refused } : {}) };
  }

  const total = atts.reduce((n, a) => n + a.size, 0);
  if (total > MAX_INLINE_ATTACHMENT_BYTES) {
    throw new Error(
      `Attachments total ${total} bytes; over the inline cap. Pick indexes, or use save:true.`,
    );
  }
  return {
    attachments: atts.map((a) => ({
      index: a.index,
      filename: safeName(a.filename, a.index),
      content_type: a.contentType,
      size: a.size,
      content_base64: a.content.toString('base64'),
    })),
  };
}

/** Exposed for tests only. */
export const _internal = {
  safeName,
  resolveSaveDir,
  writeExclusive,
  extOf,
  SAVE_EXTENSIONS,
  disableWrites,
  openRO,
  quarantine,
  parseOne,
  createReadOnlyClient,
};
