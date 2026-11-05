/** Read-only Gmail API backend. IDs are opaque tagged strings, never IMAP UIDs. */
import { simpleParser } from 'mailparser';
import { saveRoot } from './config.js';
import { GMAIL_ROOT, googleJson } from './google-http.js';
import { attachmentResult, fullMessage, PARSER_OPTIONS } from './mail.js';
import { tokenManager } from './oauth.js';
import { withOperationSlot } from './runtime.js';

const MAX_MESSAGE = 40 * 1024 * 1024;
const MAX_RAW_JSON = Math.ceil((MAX_MESSAGE * 4) / 3) + 65536;
const ALL = '[Gmail]/All Mail';
const HEX = /^[a-f0-9]{1,32}$/;
export const taggedId = (id) => {
  if (typeof id !== 'string' || !HEX.test(id)) throw new Error('Invalid Gmail API message id');
  return `gmail:${id}`;
};
export function messageId(uid) {
  if (typeof uid !== 'string' || !/^gmail:[a-f0-9]{1,32}$/.test(uid)) {
    throw new Error(
      'Gmail API requires a gmail: message uid from a new search/list; IMAP numeric UIDs cannot be reused after migration',
    );
  }
  return uid.slice(6);
}

// A second guard against accidental future mutations: only these GET resources are reachable.
const READ_PATH = /^(?:profile|labels|messages|messages\/[a-f0-9]{1,32}|threads\/[a-f0-9]{1,32})$/;
export function createGmailClient(
  account,
  {
    tokens = tokenManager,
    fetchImpl = fetch,
    signal,
    maxOperationBytes = 128 * 1024 * 1024,
    maxRequests = 500,
  } = {},
) {
  let downloaded = 0;
  let requests = 0;
  return {
    async get(resource, params = {}, maxBytes = 1024 * 1024) {
      if (!READ_PATH.test(resource)) throw new Error('Read-only Gmail resource refused');
      const url = new URL(resource, GMAIL_ROOT);
      for (const [key, value] of Object.entries(params)) {
        for (const item of [].concat(value)) url.searchParams.append(key, String(item));
      }
      for (let attempt = 0; attempt < 2; attempt++) {
        if (++requests > maxRequests) {
          throw new Error(
            'Gmail operation request limit reached; narrow folders/search or reduce limit',
          );
        }
        const access = await tokens.get(account, signal);
        try {
          return await googleJson(
            url.toString(),
            { method: 'GET', headers: { Authorization: `Bearer ${access}` }, signal },
            {
              fetchImpl,
              maxBytes,
              onBytes: (bytes) => {
                downloaded += bytes;
                if (downloaded > maxOperationBytes) {
                  throw new Error(
                    'Gmail operation download budget exceeded; narrow search or choose a smaller message/thread',
                  );
                }
              },
            },
          );
        } catch (err) {
          if (err.status === 401 && attempt === 0) {
            tokens.invalidate(account);
            continue;
          }
          if (err.status === 401)
            throw new Error(
              `Gmail login needed; run MAIL_ACCOUNTS=${account.id} node index.js auth ${account.id} --client /path/to/client_secret.json`,
            );
          if (err.status === 403)
            throw new Error(
              'Gmail API access denied; confirm Gmail API is enabled, gmail.readonly was granted, and Workspace policy permits this client',
            );
          if (err.status === 404)
            throw new Error('Gmail message, thread or label no longer exists in this account');
          if (err.status === 429) throw new Error('Gmail API rate limit reached; retry later');
          throw err;
        }
      }
    },
  };
}

export async function withGmail(account, fn) {
  return withOperationSlot(async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 120000);
    try {
      return await fn(createGmailClient(account, { signal: controller.signal }));
    } finally {
      controller.abort();
      clearTimeout(timer);
    }
  });
}

async function labels(api) {
  const data = await api.get('labels');
  if (!Array.isArray(data.labels) || data.labels.length > 10000)
    throw new Error('Invalid or oversized Gmail labels response');
  return data.labels;
}

async function folderLabel(api, folder) {
  if (folder === ALL) return null;
  const list = await labels(api);
  // Exact names from list_folders, including custom labels containing slashes.
  const found = list.find((l) => l.name === folder);
  if (!found) throw new Error('Unknown Gmail label; use a folder path from mail__list_folders');
  return found.id;
}

export async function listFolders(api) {
  return [
    { path: ALL, special_use: '\\All' },
    ...(await labels(api)).map((l) => ({
      path: l.name,
      label_id: l.id,
      ...({
        INBOX: { special_use: '\\Inbox' },
        SENT: { special_use: '\\Sent' },
        TRASH: { special_use: '\\Trash' },
        SPAM: { special_use: '\\Junk' },
        DRAFT: { special_use: '\\Drafts' },
        STARRED: { special_use: '\\Flagged' },
      }[l.id] || {}),
    })),
  ];
}

const dateDesc = (a, b) => new Date(b.date || 0) - new Date(a.date || 0);
function checkSize(message) {
  if (
    !Number.isSafeInteger(message.sizeEstimate) ||
    message.sizeEstimate < 0 ||
    message.sizeEstimate > MAX_MESSAGE
  ) {
    throw new Error('Message size is missing, invalid or over the 40 MB limit');
  }
}

export async function metadata(api, id, folder) {
  taggedId(id);
  const m = await api.get(`messages/${id}`, {
    format: 'metadata',
    metadataHeaders: ['Date', 'From', 'To', 'Cc', 'Subject', 'Message-ID'],
  });
  const headers = m.payload?.headers || [];
  // Decode RFC 2047 headers with the same parser used by IMAP. Prevent injected new headers.
  const source = `${headers
    .filter((h) => /^[a-z-]+$/i.test(h.name))
    .map((h) => `${h.name}: ${String(h.value).replace(/[\r\n]/g, ' ')}`)
    .join('\r\n')}\r\n\r\n`;
  const parsed = await simpleParser(source, PARSER_OPTIONS);
  return {
    folder,
    uid: taggedId(id),
    date:
      parsed.date?.toISOString() ||
      (Number.isFinite(Number(m.internalDate))
        ? new Date(Number(m.internalDate)).toISOString()
        : null),
    from: parsed.from?.text || '',
    to: parsed.to?.text || '',
    ...(parsed.cc ? { cc: parsed.cc.text } : {}),
    subject: parsed.subject || '(no subject)',
    unread: m.labelIds?.includes('UNREAD') || false,
    labels: m.labelIds || [],
    thread_id: m.threadId,
    message_id: parsed.messageId || null,
  };
}

export async function parseMessage(api, id, folder, { checkFolder = true } = {}) {
  taggedId(id);
  const head = await api.get(`messages/${id}`, { format: 'minimal' });
  checkSize(head);
  if (checkFolder) {
    const label = await folderLabel(api, folder);
    if (
      label
        ? !head.labelIds?.includes(label)
        : head.labelIds?.some((l) => ['TRASH', 'SPAM'].includes(l))
    ) {
      throw new Error('Message is not in the supplied Gmail folder; search/list again');
    }
  }
  const raw = await api.get(`messages/${id}`, { format: 'raw' }, MAX_RAW_JSON);
  if (
    typeof raw.raw !== 'string' ||
    !/^[A-Za-z0-9_-]*={0,2}$/.test(raw.raw) ||
    raw.raw.length > Math.ceil((MAX_MESSAGE * 4) / 3) + 4
  )
    throw new Error('Invalid or oversized raw Gmail message');
  const source = Buffer.from(raw.raw, 'base64url');
  if (source.length > MAX_MESSAGE) throw new Error('Downloaded message exceeds the 40 MB limit');
  return { parsed: await simpleParser(source, PARSER_OPTIONS), head };
}

export async function listMessages(api, { folder = 'INBOX', limit = 20, unreadOnly = false }) {
  const label = await folderLabel(api, folder);
  const result = await api.get('messages', {
    maxResults: limit,
    includeSpamTrash: true,
    ...(label ? { labelIds: label } : {}),
    q: [!label ? '-in:spam -in:trash' : '', unreadOnly ? 'is:unread' : '']
      .filter(Boolean)
      .join(' '),
  });
  const messages = [];
  for (const m of (result.messages || []).slice(0, limit))
    messages.push(await metadata(api, m.id, folder));
  return {
    folder,
    total_matching: result.resultSizeEstimate || 0,
    total_matching_is_estimate: true,
    ...(result.nextPageToken ? { more_available: true } : {}),
    messages: messages.sort(dateDesc),
  };
}

const quote = (value) => `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
export function searchQuery(criteria) {
  const parts = [];
  if (criteria.query) parts.push(`(${criteria.query})`);
  if (criteria.text) parts.push(quote(criteria.text));
  for (const field of ['from', 'to', 'subject'])
    if (criteria[field]) parts.push(`${field}:${quote(criteria[field])}`);
  // Epoch timestamps preserve the IMAP backend's machine-local midnight date boundaries.
  if (criteria.since)
    parts.push(`after:${Math.floor(new Date(`${criteria.since}T00:00:00`).getTime() / 1000)}`);
  if (criteria.before)
    parts.push(`before:${Math.floor(new Date(`${criteria.before}T00:00:00`).getTime() / 1000)}`);
  if (criteria.unread) parts.push('is:unread');
  if (!parts.length && !criteria.body) throw new Error('Give at least one search criterion');
  return parts.join(' ');
}

export async function search(api, criteria, limit = 40) {
  const query = searchQuery(criteria);
  const targets = criteria.folders?.length ? criteria.folders : [ALL];
  const hits = new Map();
  const skipped = [];
  let matched = 0;
  let scanned = 0;
  let incomplete = false;
  for (const folder of targets) {
    let label;
    try {
      label = await folderLabel(api, folder);
    } catch (err) {
      if (err.message.startsWith('Unknown Gmail label')) {
        skipped.push({ folder, reason: err.message });
        continue;
      }
      throw err; // Never disguise an expired login or a network failure as an empty search.
    }
    let pageToken;
    do {
      if (criteria.body && scanned >= 200) {
        incomplete = true;
        break;
      }
      const pageLimit = criteria.body ? Math.min(100, 200 - scanned) : limit;
      const result = await api.get('messages', {
        maxResults: pageLimit,
        includeSpamTrash: true,
        ...(label ? { labelIds: label } : {}),
        ...(pageToken ? { pageToken } : {}),
        q: !label
          ? [query ? `(${query})` : '', '-in:spam -in:trash'].filter(Boolean).join(' ')
          : query,
      });
      if (!pageToken) matched += result.resultSizeEstimate || 0;
      for (const m of (result.messages || []).slice(0, pageLimit)) {
        const prior = hits.get(m.id);
        if (prior) {
          if (prior.folder !== folder && !prior.also_in?.includes(folder)) {
            prior.also_in ||= [];
            prior.also_in.push(folder);
          }
          continue;
        }
        if (criteria.body) {
          scanned++;
          const { parsed } = await parseMessage(api, m.id, folder);
          if (!(parsed.text || '').toLowerCase().includes(criteria.body.toLowerCase())) continue;
        }
        hits.set(m.id, await metadata(api, m.id, folder));
      }
      pageToken = result.nextPageToken;
      if (!criteria.body) break;
      if (hits.size >= limit) {
        incomplete ||= !!pageToken;
        break;
      }
    } while (pageToken);
  }
  const messages = [...hits.values()].sort(dateDesc).slice(0, limit);
  return {
    searched_folders: targets.length,
    matched_before_limit: matched,
    matched_before_limit_is_estimate: true,
    returned: messages.length,
    messages,
    ...(criteria.body
      ? {
          body_candidates_scanned: scanned,
          search_incomplete: incomplete,
          note: 'Body-only matching uses decoded plain text; candidate estimates precede body filtering. At most 200 candidates are downloaded.',
        }
      : {}),
    ...(skipped.length ? { skipped } : {}),
  };
}

export async function getMessage(api, { folder, uid, maxChars = 20000 }) {
  const { parsed, head } = await parseMessage(api, messageId(uid), folder);
  return { ...fullMessage(parsed, folder, uid, maxChars), thread_id: head.threadId };
}

export async function getThread(api, { folder, uid, maxChars = 8000 }) {
  const id = messageId(uid);
  const { parsed, head } = await parseMessage(api, id, folder);
  if (!HEX.test(head.threadId)) throw new Error('Missing Gmail thread id');
  // Metadata retains internalDate for selecting the newest siblings without downloading bodies.
  const thread = await api.get(
    `threads/${head.threadId}`,
    { format: 'metadata', metadataHeaders: 'Date' },
    4 * 1024 * 1024,
  );
  const items = thread.messages || [];
  const recent = [...items]
    .sort((a, b) => Number(a.internalDate || 0) - Number(b.internalDate || 0))
    .slice(-25);
  const messages = [];
  for (const m of recent) {
    const content =
      m.id === id ? parsed : (await parseMessage(api, m.id, ALL, { checkFolder: false })).parsed;
    // Thread siblings may live in spam/trash. Return a real label path usable for subsequent reads.
    const location = m.labelIds?.includes('TRASH')
      ? 'TRASH'
      : m.labelIds?.includes('SPAM')
        ? 'SPAM'
        : ALL;
    messages.push(fullMessage(content, location, taggedId(m.id), maxChars));
  }
  if (!messages.length) messages.push(fullMessage(parsed, folder, uid, maxChars));
  messages.sort((a, b) => new Date(a.date || 0) - new Date(b.date || 0));
  return {
    count: messages.length,
    ...(items.length > 25 ? { note: `Thread has ${items.length} messages; newest 25 shown` } : {}),
    messages,
  };
}

export async function getAttachments(api, { folder, uid, indexes, save, subdir }) {
  if (save && !saveRoot())
    throw new Error('Saving is off for this harness (MAIL_SAVE_ROOT is not set)');
  const { parsed } = await parseMessage(api, messageId(uid), folder);
  // Raw MIME via Gmail API preserves exactly the same attachment indexes and safeguards as IMAP.
  return attachmentResult(parsed, { indexes, save, subdir });
}
