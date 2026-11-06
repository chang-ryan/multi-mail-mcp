import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import * as backend from '../backend.js';
import * as gmail from '../gmail.js';
import { GMAIL_ROOT } from '../google-http.js';
import { serializeResult } from '../security.js';

const repo = fileURLToPath(new URL('../', import.meta.url));
const source = Buffer.from(
  'From: Sender <sender@example.test>\r\nTo: Recipient <to@example.test>\r\nSubject: =?UTF-8?B?VGVzdCDwn5iA?=\r\nDate: Wed, 4 Nov 2026 12:00:00 +0000\r\nMessage-ID: <test@example.test>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello body\r\n--x\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename="invoice.pdf"\r\nContent-Transfer-Encoding: base64\r\n\r\naW52b2ljZQ==\r\n--x--\r\n',
);
const head = {
  id: 'abc123',
  threadId: 'def456',
  labelIds: ['INBOX', 'UNREAD'],
  sizeEstimate: source.length,
  internalDate: '1793793600000',
};
const labelList = [
  { id: 'INBOX', name: 'INBOX' },
  { id: 'UNREAD', name: 'UNREAD' },
  { id: 'Label_1', name: 'Projects/Work' },
];
function fakeApi({ messages = [head], raw = source } = {}) {
  const calls = [];
  return {
    calls,
    async get(resource, params = {}) {
      calls.push({ resource, params });
      if (resource === 'labels') return { labels: labelList };
      if (resource === 'messages')
        return {
          messages: messages.map((m) => ({ id: m.id })),
          resultSizeEstimate: messages.length,
        };
      if (resource.startsWith('threads/')) return { messages };
      const id = resource.split('/')[1];
      const m = messages.find((item) => item.id === id);
      assert.ok(m, resource);
      if (params.format === 'minimal') return m;
      if (params.format === 'raw') return { ...m, raw: raw.toString('base64url') };
      return {
        ...m,
        payload: {
          headers: [
            { name: 'From', value: 'Sender <sender@example.test>' },
            { name: 'Subject', value: '=?UTF-8?B?VGVzdCDwn5iA?=' },
            { name: 'Message-ID', value: '<test@example.test>' },
          ],
        },
      };
    },
  };
}

test('opaque Gmail IDs never collide with numeric IMAP UIDs and reject malformed paths', async () => {
  assert.equal(gmail.messageId('gmail:abc123'), 'abc123');
  for (const id of [123, '123', 'gmail:../profile', 'gmail:ABC', 'gmail:', 'gmail:abc?x=y'])
    assert.throws(() => gmail.messageId(id));
  await assert.rejects(
    async () => backend.getMessage({ backend: 'gmail-api' }, { uid: 123 }),
    /numeric UIDs/,
  );
  await assert.rejects(
    async () => backend.getMessage({ backend: 'imap' }, { uid: 'gmail:abc123' }),
    /numeric uid/,
  );
});

test('API client permits only fixed GET resources, retries expired access once, and rejects mutations', async () => {
  let gets = 0,
    invalidated = 0,
    calls = 0;
  const api = gmail.createGmailClient(
    { id: 'personal' },
    {
      tokens: {
        get: async () => {
          gets++;
          return 'test-token';
        },
        invalidate: () => {
          invalidated++;
        },
      },
      fetchImpl: async (url, options) => {
        calls++;
        assert.ok(url.startsWith(GMAIL_ROOT));
        assert.equal(options.method, 'GET');
        assert.equal(options.headers.Authorization, 'Bearer test-token');
        return new Response(JSON.stringify(calls === 1 ? { error: 'expired' } : { labels: [] }), {
          status: calls === 1 ? 401 : 200,
        });
      },
    },
  );
  await assert.rejects(api.get('messages/abc123/trash'), /Read-only/);
  await assert.rejects(api.get('https://attacker.example'), /Read-only/);
  await assert.rejects(api.get('../messages'), /Read-only/);
  assert.deepEqual(await api.get('labels'), { labels: [] });
  assert.equal(calls, 2);
  assert.equal(gets, 2);
  assert.equal(invalidated, 1);
});

test('list/search returns headers, exact label paths and tagged IDs without fetching bodies', async () => {
  const api = fakeApi();
  assert.ok(
    (await gmail.listFolders(api)).some(
      (l) => l.path === 'Projects/Work' && l.label_id === 'Label_1',
    ),
  );
  const list = await gmail.listMessages(api, { folder: 'INBOX', unreadOnly: true });
  assert.equal(list.messages[0].uid, 'gmail:abc123');
  assert.equal(list.messages[0].subject, 'Test 😀');
  assert.equal(list.messages[0].unread, true);
  assert.equal(list.total_matching_is_estimate, true);
  const result = await gmail.search(api, {
    query: 'has:attachment',
    from: 'sender@example.test',
    unread: true,
  });
  assert.equal(result.messages[0].folder, '[Gmail]/All Mail');
  assert.equal(result.messages[0].thread_id, 'def456');
  assert.equal(
    api.calls.some((c) => c.params.format === 'raw'),
    false,
  );
  const request = api.calls.filter((c) => c.resource === 'messages').at(-1);
  assert.match(request.params.q, /-in:spam -in:trash/);
  assert.match(request.params.q, /from:"sender@example.test"/);
  assert.match(request.params.q, /is:unread/);
});

test('Gmail API folders and labels use the IMAP backend names; pseudo-labels are hidden', async () => {
  const system = [
    'INBOX',
    'SENT',
    'DRAFT',
    'SPAM',
    'TRASH',
    'STARRED',
    'IMPORTANT',
    'UNREAD',
    'CHAT',
    'YELLOW_STAR',
    'CATEGORY_PROMOTIONS',
  ].map((id) => ({ id, name: id, type: 'system' }));
  const labels = [...system, { id: 'Label_7', name: '2024 Taxes', type: 'user' }];
  const m = { ...head, labelIds: ['INBOX', 'UNREAD', 'CATEGORY_PROMOTIONS', 'Label_7', 'SENT'] };
  const base = fakeApi({ messages: [m] });
  const api = {
    calls: base.calls,
    async get(resource, params) {
      if (resource !== 'labels') return base.get(resource, params);
      base.calls.push({ resource });
      return { labels };
    },
  };

  assert.deepEqual(
    (await gmail.listFolders(api)).map((f) => f.path),
    [
      'INBOX',
      '[Gmail]/Sent Mail',
      '[Gmail]/Drafts',
      '[Gmail]/Starred',
      '[Gmail]/Important',
      '[Gmail]/Spam',
      '[Gmail]/Trash',
      '[Gmail]/All Mail',
      '2024 Taxes',
    ],
  );

  // IMAP-style paths and raw system IDs both select the same label.
  const lastList = () => api.calls.filter((c) => c.resource === 'messages').at(-1).params;
  for (const folder of ['[Gmail]/Sent Mail', 'SENT']) {
    await gmail.listMessages(api, { folder });
    assert.equal(lastList().labelIds, 'SENT');
  }
  await gmail.listMessages(api, { folder: '2024 Taxes' });
  assert.equal(lastList().labelIds, 'Label_7');
  for (const hidden of ['UNREAD', 'CATEGORY_PROMOTIONS', 'CHAT'])
    await assert.rejects(gmail.listMessages(api, { folder: hidden }), /Unknown Gmail label/);

  const listed = await gmail.listMessages(api, { folder: 'INBOX' });
  assert.deepEqual(listed.messages[0].labels, ['\\Inbox', '2024 Taxes', '\\Sent']);
  assert.equal(listed.messages[0].unread, true);
  // One labels request per client (operation), not one per message.
  assert.equal(api.calls.filter((c) => c.resource === 'labels').length, 1);

  const trashed = { ...head, id: 'b', labelIds: ['TRASH'], internalDate: '2' };
  const thread = await gmail.getThread(fakeApi({ messages: [head, trashed] }), {
    folder: 'INBOX',
    uid: 'gmail:abc123',
  });
  assert.equal(thread.messages.find((x) => x.uid === 'gmail:b').folder, '[Gmail]/Trash');
});

test('full message and attachment indexes share the IMAP MIME parser and attachment policy', async () => {
  const api = fakeApi();
  const result = await gmail.getMessage(api, { folder: 'INBOX', uid: 'gmail:abc123', maxChars: 5 });
  assert.equal(result.uid, 'gmail:abc123');
  assert.equal(result.body, 'Hello');
  assert.equal(result.truncated, true);
  assert.equal(result.attachments[0].filename, 'invoice.pdf');
  const attachments = await gmail.getAttachments(api, {
    folder: 'INBOX',
    uid: result.uid,
    indexes: [0],
  });
  assert.equal(
    Buffer.from(attachments.attachments[0].content_base64, 'base64').toString(),
    'invoice',
  );
  assert.deepEqual(
    (await gmail.getAttachments(api, { folder: 'INBOX', uid: result.uid, indexes: [42] }))
      .attachments,
    [],
  );
});

test('wrong folder and oversized or malformed messages fail before parsing/downloading raw data', async () => {
  const api = fakeApi();
  await assert.rejects(
    gmail.getMessage(api, { folder: 'Projects/Work', uid: 'gmail:abc123' }),
    /not in the supplied/,
  );
  assert.equal(
    api.calls.some((c) => c.params.format === 'raw'),
    false,
  );
  for (const sizeEstimate of [undefined, -1, '100', 40 * 1024 * 1024 + 1]) {
    const oversized = fakeApi({ messages: [{ ...head, sizeEstimate }] });
    await assert.rejects(gmail.parseMessage(oversized, 'abc123', 'INBOX'), /size/);
    assert.equal(
      oversized.calls.some((c) => c.params.format === 'raw'),
      false,
    );
  }
  await assert.rejects(
    gmail.parseMessage(
      {
        get: async (resource, params = {}) =>
          params.format === 'minimal'
            ? head
            : resource === 'labels'
              ? { labels: labelList }
              : { raw: '%not-base64%' },
      },
      'abc123',
      'INBOX',
    ),
    /Invalid or oversized/,
  );
});

test('Gmail native thread reads newest 25 siblings and emits usable message references', async () => {
  const messages = Array.from({ length: 30 }, (_, i) => ({
    ...head,
    id: (i + 1).toString(16),
    internalDate: String(i + 1),
  }));
  const api = fakeApi({ messages });
  const thread = await gmail.getThread(api, { folder: 'INBOX', uid: 'gmail:1' });
  assert.equal(thread.count, 25);
  assert.match(thread.note, /30 messages/);
  assert.ok(thread.messages.every((m) => typeof m.uid === 'string'));
  assert.ok(api.calls.some((c) => c.resource === 'threads/def456'));
  assert.equal(api.calls.find((c) => c.resource === 'threads/def456').params.format, 'metadata');
  assert.equal(thread.messages[0].uid, 'gmail:6');
});

test('body-only search excludes header matches, follows pages, and reports its bounded scan', async () => {
  const api = fakeApi();
  const found = await gmail.search(api, { body: 'HELLO body' });
  assert.equal(found.returned, 1);
  assert.equal(found.body_candidates_scanned, 1);
  assert.equal(found.search_incomplete, false);
  assert.equal((await gmail.search(api, { body: 'Sender' })).returned, 0);
  let pages = 0;
  const paged = {
    async get(resource, params) {
      if (resource === 'messages') {
        pages++;
        return {
          messages: Array.from({ length: 100 }, () => ({ id: 'abc123' })),
          resultSizeEstimate: 1000,
          nextPageToken: 'next',
        };
      }
      return api.get(resource, params);
    },
  };
  const bounded = await gmail.search(paged, { body: 'not present' });
  assert.equal(pages, 2);
  assert.equal(bounded.body_candidates_scanned, 200);
  assert.equal(bounded.search_incomplete, true);
});

test('search deduplicates label matches without suppressing API/login failures', async () => {
  const m = { ...head, labelIds: ['INBOX', 'Label_1'] };
  const api = fakeApi({ messages: [m] });
  const result = await gmail.search(api, {
    text: 'invoice',
    folders: ['INBOX', 'Projects/Work', 'missing'],
  });
  assert.equal(result.returned, 1);
  assert.deepEqual(result.messages[0].also_in, ['Projects/Work']);
  assert.equal(result.skipped[0].folder, 'missing');
  await assert.rejects(
    gmail.search(
      {
        get: async () => {
          throw new Error('Gmail login needed');
        },
      },
      { text: 'invoice' },
    ),
    /login needed/,
  );
});

test('MCP advertises both UID representations and enforces account/backend isolation before credentials', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mail-api-mcp-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const config = path.join(dir, 'accounts.json');
  fs.writeFileSync(
    config,
    JSON.stringify({
      accounts: {
        personal: { type: 'gmail', user: 'first@example.test' },
        widgets: { type: 'gmail', user: 'second@example.test' },
        proton: { type: 'proton', user: 'third@example.test' },
      },
    }),
    { mode: 0o600 },
  );
  const env = {
    PATH: process.env.PATH,
    MAIL_MCP_CONFIG: config,
    MAIL_ACCOUNTS: 'personal',
    MAIL_GMAIL_API_ACCOUNTS: 'personal',
  };
  const client = new Client({ name: 'gmail-api-test', version: '1' });
  t.after(() => client.close());
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [path.join(repo, 'index.js')],
      env,
      stderr: 'pipe',
    }),
  );
  const tools = (await client.listTools()).tools;
  assert.equal(tools.length, 7);
  const read = tools.find((tool) => tool.name === 'mail__get_message');
  assert.ok(read.inputSchema.properties.uid.anyOf.some((s) => s.type === 'string'));
  const accounts = JSON.parse(
    (await client.callTool({ name: 'mail__list_accounts', arguments: {} })).content[0].text,
  ).accounts;
  assert.deepEqual(
    accounts.map((a) => [a.id, a.backend]),
    [['personal', 'gmail-api']],
  );
  for (const [name, args, error] of [
    ['mail__get_message', { folder: 'INBOX', uid: 123 }, /IMAP numeric UIDs/],
    [
      'mail__get_message',
      { account: 'widgets', folder: 'INBOX', uid: 'gmail:abc123' },
      /not available here/,
    ],
    [
      'mail__get_attachments',
      { folder: 'INBOX', uid: 'gmail:abc123', save: true },
      /Saving is off/,
    ],
  ]) {
    const result = await client.callTool({ name, arguments: args });
    assert.equal(result.isError, true);
    const payload = JSON.parse(result.content[0].text);
    assert.match(payload.error, error);
    assert.ok(payload._untrusted);
  }
  const denied = spawnSync(process.execPath, [path.join(repo, 'index.js'), 'auth', 'widgets'], {
    env,
    encoding: 'utf8',
  });
  assert.equal(denied.status, 1);
  assert.match(denied.stderr, /not available here/);
  for (const override of ['widgets', 'proton', '*']) {
    const invalid = spawnSync(process.execPath, [path.join(repo, 'index.js')], {
      env: { ...env, MAIL_GMAIL_API_ACCOUNTS: override },
      encoding: 'utf8',
    });
    assert.equal(invalid.status, 1);
    assert.match(invalid.stderr, /allowed Gmail accounts/);
  }
});

test('both backends retain a bound on serialized MCP payload size', () => {
  assert.throws(() => serializeResult({ body: 'x'.repeat(3 * 1024 * 1024) }), /Result exceeds/);
  assert.ok(serializeResult({ content_base64: Buffer.alloc(2 * 1024 * 1024).toString('base64') }));
});

test('Gmail reads share a cumulative download budget and stop/cancel before parsing excess data', async () => {
  let requests = 0,
    cancelled = false;
  const api = gmail.createGmailClient(
    { id: 'personal' },
    {
      tokens: { get: async () => 'test-token' },
      maxOperationBytes: 10,
      fetchImpl: async () => {
        requests++;
        // Two individually small responses exceed the shared operation budget.
        return new Response(
          new ReadableStream({
            start(controller) {
              controller.enqueue(Buffer.from('{"ok":true}'));
            },
            cancel() {
              cancelled = true;
            },
          }),
        );
      },
    },
  );
  // The first response must end; the second deliberately stalls after the budget breach.
  const first = gmail.createGmailClient(
    { id: 'personal' },
    {
      tokens: { get: async () => 'test-token' },
      maxOperationBytes: 15,
      fetchImpl: async () => {
        requests++;
        return new Response('{"ok":true}');
      },
    },
  );
  assert.deepEqual(await first.get('labels'), { ok: true });
  await assert.rejects(first.get('labels'), /download budget/);
  // A single streamed chunk over the operation budget cancels an otherwise unending body.
  await assert.rejects(api.get('labels', {}, 1024), /download budget/);
  assert.equal(cancelled, true);
  assert.equal(requests, 3);
});

test('Gmail request budgets count retries and reject more requests before credential access', async () => {
  let credentials = 0,
    requests = 0;
  const api = gmail.createGmailClient(
    { id: 'personal' },
    {
      maxRequests: 1,
      tokens: {
        get: async () => {
          credentials++;
          return 'test-token';
        },
        invalidate() {},
      },
      fetchImpl: async () => {
        requests++;
        return new Response('{}', { status: 401 });
      },
    },
  );
  await assert.rejects(api.get('labels'), /request limit/);
  assert.equal(credentials, 1);
  assert.equal(requests, 1);
});

test('repeated address header lines are joined, not reported as empty', async () => {
  const { simpleParser } = await import('mailparser');
  const { fullMessage } = await import('../mail.js');
  const parsed = await simpleParser(
    'From: a@example.test\r\nTo: b@example.test\r\nTo: c@example.test\r\nCc: d@example.test\r\nCc: e@example.test\r\nSubject: s\r\n\r\nhi',
  );
  const message = fullMessage(parsed, 'INBOX', 1, 100);
  assert.equal(message.to, 'b@example.test, c@example.test');
  assert.equal(message.cc, 'd@example.test, e@example.test');
  assert.equal(message.from, 'a@example.test');
});
