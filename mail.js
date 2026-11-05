/**
 * IMAP operations — READ ONLY — for Proton (via Bridge) and Gmail.
 *
 * Every mailbox is opened with readOnly:true (IMAP EXAMINE), hard-wired in openRO(), and
 * imapflow fetches bodies with BODY.PEEK. Nothing here can flag, move, delete, append,
 * mark read, or send. Messages are addressed as (folder, uid); UIDs are stable per folder.
 */

import fs from 'fs';
import path from 'path';
import { ImapFlow } from 'imapflow';
import { simpleParser } from 'mailparser';
import { getPassword, saveRoot } from './config.js';

const MAX_INLINE_ATTACHMENT_BYTES = 5 * 1024 * 1024;
const MAX_THREAD_MESSAGES = 25;

// --- Connection ---------------------------------------------------------------

async function withClient(account, fn) {
  const client = new ImapFlow({
    host: account.host,
    port: account.port,
    secure: account.secure,
    ...(account.doSTARTTLS === false ? { doSTARTTLS: false } : {}),
    auth: { user: account.user, pass: await getPassword(account) },
    logger: false,
    connectionTimeout: 15000,
  });
  // imapflow emits 'error' for socket faults after connect; without a listener node would crash.
  client.on('error', () => {});

  try {
    await client.connect();
  } catch (err) {
    throw new Error(connectHint(account, err));
  }
  try {
    return await fn(client);
  } finally {
    await client.logout().catch(() => client.close());
  }
}

function connectHint(account, err) {
  const base = `[${account.id}] IMAP login failed: ${err.responseText || err.message}.`;
  if (account.type === 'proton') {
    return `${base} Is Proton Mail Bridge running, and is ${account.user} signed in to it? ` +
      'The password is the Bridge-generated one, not the Proton account password.';
  }
  return `${base} Gmail needs an app password (Google Account > Security > 2-Step Verification > ` +
    'App passwords). Workspace accounts also need IMAP enabled by the admin.';
}

/** The single place a mailbox is opened. readOnly is a literal. */
async function openRO(client, folder) {
  return client.getMailboxLock(folder, { readOnly: true });
}

// --- Helpers -------------------------------------------------------------------

const addr = (list) => (list || [])
  .map((a) => (a.name ? `${a.name} <${a.address}>` : a.address))
  .join(', ');

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
  const all = boxes.find((b) => b.specialUse === '\\All')
    || boxes.find((b) => /^(\[Gmail\]\/)?All Mail$/i.test(b.path));
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

async function parseOne(client, uid) {
  const msg = await client.fetchOne(String(uid), { uid: true, source: true, flags: true }, { uid: true });
  if (!msg || !msg.source) throw new Error(`No message with uid ${uid} in this folder`);
  return { parsed: await simpleParser(msg.source), flags: msg.flags };
}

function fullMessage(parsed, folder, uid, maxChars) {
  return {
    folder,
    uid: Number(uid),
    date: parsed.date?.toISOString() || null,
    from: parsed.from?.text || '',
    to: parsed.to?.text || '',
    ...(parsed.cc ? { cc: parsed.cc.text } : {}),
    subject: parsed.subject || '(no subject)',
    message_id: parsed.messageId || null,
    in_reply_to: parsed.inReplyTo || null,
    attachments: (parsed.attachments || []).map((a, i) => ({
      index: i,
      filename: a.filename || `attachment-${i}`,
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
    return boxes.map((b) => ({ path: b.path, ...(b.specialUse ? { special_use: b.specialUse } : {}) }));
  });
}

export async function listMessages(account, { folder = 'INBOX', limit = 20, unreadOnly = false }) {
  return withClient(account, async (client) => {
    const lock = await openRO(client, folder);
    try {
      const uids = await client.search(unreadOnly ? { seen: false } : { all: true }, { uid: true }) || [];
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
    if (account.type !== 'gmail') throw new Error('"query" (Gmail search syntax) only works on Gmail accounts');
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
      targets = account.type === 'gmail'
        ? [await allMailPath(client)]
        : (await selectableFolders(client)).map((b) => b.path);
    }

    const hits = [];
    const skipped = [];
    let matched = 0;
    for (const folder of targets) {
      let lock;
      try {
        lock = await openRO(client, folder);
        const uids = await client.search(q, { uid: true }) || [];
        matched += uids.length;
        hits.push(...await fetchSummaries(client, account, uids.slice(-limit), folder));
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
      if (!prev) { byKey.set(key, { ...m, also_in: [] }); continue; }
      if (/^All Mail$/i.test(prev.folder) && !/^All Mail$/i.test(m.folder)) {
        byKey.set(key, { ...m, also_in: [...prev.also_in, prev.folder] });
      } else if (!prev.also_in.includes(m.folder) && prev.folder !== m.folder) {
        prev.also_in.push(m.folder);
      }
    }
    const unique = [...byKey.values()]
      .map((m) => { if (!m.also_in.length) delete m.also_in; return m; })
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
          const m = await client.fetchOne(String(uid), { uid: true, threadId: true }, { uid: true });
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
        for (const u of await client.search({ threadId }, { uid: true }) || []) uids.add(u);
      } else {
        const refs = [
          seed.messageId,
          seed.inReplyTo,
          ...[].concat(seed.references || []),
        ].filter(Boolean);
        for (const id of new Set(refs)) {
          for (const u of await client.search({ header: { 'message-id': id } }, { uid: true }) || []) uids.add(u);
        }
        if (seed.messageId) {
          for (const u of await client.search({ header: { references: seed.messageId } }, { uid: true }) || []) uids.add(u);
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
        ...(uids.size > MAX_THREAD_MESSAGES ? { note: `Thread has ${uids.size} messages; newest ${MAX_THREAD_MESSAGES} shown` } : {}),
        messages,
      };
    } finally {
      lock.release();
    }
  });
}

/** Strip anything that could escape the target directory or confuse a shell. */
function safeName(name) {
  const base = path.basename(String(name || 'attachment')).replace(/[\x00-\x1f/\\:*?"<>|]/g, '_').replace(/^\.+/, '_');
  return base.slice(0, 180) || 'attachment';
}

function uniquePath(dir, name) {
  const ext = path.extname(name);
  const stem = name.slice(0, name.length - ext.length);
  let candidate = path.join(dir, name);
  for (let i = 2; fs.existsSync(candidate); i++) candidate = path.join(dir, `${stem} (${i})${ext}`);
  return candidate;
}

/**
 * Attachments. With save:true, files are written under MAIL_SAVE_ROOT (never overwriting)
 * and only paths come back. Otherwise content returns as base64, capped in size.
 */
export async function getAttachments(account, { folder, uid, indexes, save, subdir }) {
  return withClient(account, async (client) => {
    const lock = await openRO(client, folder);
    let parsed;
    try {
      ({ parsed } = await parseOne(client, uid));
    } finally {
      lock.release();
    }

    let atts = (parsed.attachments || []).map((a, i) => ({ ...a, index: i }));
    if (indexes?.length) atts = atts.filter((a) => indexes.includes(a.index));
    if (!atts.length) return { attachments: [] };

    if (save) {
      const root = saveRoot();
      if (!root) throw new Error('Saving is off for this harness (MAIL_SAVE_ROOT is not set)');
      const dir = subdir ? path.resolve(root, subdir) : root;
      if (dir !== root && !dir.startsWith(root + path.sep)) throw new Error('subdir must stay inside the save root');
      if (!fs.existsSync(root)) throw new Error(`Save root does not exist: ${root}`);
      fs.mkdirSync(dir, { recursive: true });
      return {
        saved: atts.map((a) => {
          const p = uniquePath(dir, safeName(a.filename || `attachment-${a.index}`));
          fs.writeFileSync(p, a.content, { flag: 'wx', mode: 0o644 });
          return { index: a.index, filename: a.filename, content_type: a.contentType, size: a.size, path: p };
        }),
      };
    }

    const total = atts.reduce((n, a) => n + a.size, 0);
    if (total > MAX_INLINE_ATTACHMENT_BYTES) {
      throw new Error(`Attachments total ${total} bytes; over the inline cap. Pick indexes, or use save:true.`);
    }
    return {
      attachments: atts.map((a) => ({
        index: a.index,
        filename: a.filename,
        content_type: a.contentType,
        size: a.size,
        content_base64: a.content.toString('base64'),
      })),
    };
  });
}
