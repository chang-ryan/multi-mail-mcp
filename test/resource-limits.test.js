import assert from 'node:assert/strict';
import { once } from 'node:events';
import test from 'node:test';
import { _internal } from '../mail.js';
import { logoutBounded, withOperationSlot } from '../runtime.js';
import { serializeResult } from '../security.js';

const MAX_MESSAGE_BYTES = 40 * 1024 * 1024;

test('the real IMAP wire parser rejects an oversized literal before receiving its body', {
  timeout: 1000,
}, async (t) => {
  const client = _internal.createReadOnlyClient(
    { host: '127.0.0.1', port: 1143, secure: false, user: 'nobody@example.test' },
    'not-a-real-password',
  );
  t.after(() => client.close());
  const failed = once(client.streamer, 'error');
  // Only a size announcement is sent. No large allocation or real server is needed.
  client.streamer.write(Buffer.from(`* 1 FETCH (BODY[] {${MAX_MESSAGE_BYTES + 2}}\r\n`));
  const [error] = await failed;
  assert.equal(error.code, 'LiteralTooLarge');
});

test('an IMAP server cannot bypass the message cap by understating its reported size', async () => {
  let calls = 0;
  const client = {
    async fetchOne(_uid, query) {
      if (++calls === 1) return { size: 20 };
      assert.deepEqual(query.source, { start: 0, maxLength: MAX_MESSAGE_BYTES + 1 });
      return { source: { length: MAX_MESSAGE_BYTES + 1 } };
    },
  };
  await assert.rejects(_internal.parseOne(client, 1), /exceeds the 40 MB limit/);
  assert.equal(calls, 2);
});

test('missing, invalid, and oversized size metadata is refused before fetching source', async () => {
  for (const size of [undefined, NaN, -1, '20', MAX_MESSAGE_BYTES + 1]) {
    let calls = 0;
    const client = {
      async fetchOne() {
        calls++;
        return { size };
      },
    };
    await assert.rejects(_internal.parseOne(client, 1));
    assert.equal(calls, 1);
  }
});

test('bounded source fetching still parses a normal MIME message', async () => {
  const source = Buffer.from(
    'From: sender@example.test\r\nTo: recipient@example.test\r\nSubject: sample\r\n\r\nHello\r\n',
  );
  let calls = 0;
  const client = {
    async fetchOne(_uid, query) {
      if (++calls === 1) return { size: source.length };
      assert.equal(query.source.maxLength, MAX_MESSAGE_BYTES + 1);
      return { source, flags: new Set() };
    },
  };
  const { parsed } = await _internal.parseOne(client, 1);
  assert.equal(parsed.subject, 'sample');
  assert.match(parsed.text, /Hello/);
});

test('concurrent operations reject excess work and release slots after completion or failure', async () => {
  let finishFirst, finishSecond;
  const first = withOperationSlot(
    () =>
      new Promise((resolve) => {
        finishFirst = resolve;
      }),
  );
  const second = withOperationSlot(
    () =>
      new Promise((resolve) => {
        finishSecond = resolve;
      }),
  );
  let ran = false;
  try {
    await assert.rejects(
      withOperationSlot(() => {
        ran = true;
      }),
      /busy/,
    );
    assert.equal(ran, false);
  } finally {
    finishFirst();
    finishSecond();
    await Promise.all([first, second]);
  }
  await assert.rejects(
    withOperationSlot(() => {
      throw new Error('failed');
    }),
    /failed/,
  );
  assert.equal(await withOperationSlot(() => 42), 42);
});

test('a server that never acknowledges logout is forcibly closed', { timeout: 1000 }, async () => {
  let closed = false;
  await logoutBounded(
    {
      logout: () => new Promise(() => {}),
      close() {
        closed = true;
      },
    },
    10,
  );
  assert.equal(closed, true);
});

test('logout rejection and success both close the socket', async () => {
  for (const logout of [
    async () => {},
    async () => {
      throw new Error('socket gone');
    },
  ]) {
    let closed = false;
    await logoutBounded(
      {
        logout,
        close() {
          closed = true;
        },
      },
      100,
    );
    assert.equal(closed, true);
  }
});

test('large or highly escaped result payloads are bounded by serialized UTF-8 bytes', () => {
  assert.throws(() => serializeResult({ body: 'x'.repeat(3 * 1024 * 1024) }), /Result exceeds/);
  assert.throws(() => serializeResult({ body: '\0'.repeat(600000) }), /Result exceeds/);
  const payload = {
    attachments: [{ content_base64: Buffer.alloc(2 * 1024 * 1024).toString('base64') }],
  };
  assert.ok(serializeResult(payload).length < 3 * 1024 * 1024);
  assert.equal(JSON.parse(serializeResult({ body: 'normal' })).body, 'normal');
});

test('the connection guard blocks writable mailbox opens and CLOSE expunges', async () => {
  let opened = false;
  const client = {
    async mailboxOpen(folder, options) {
      opened = true;
      return { path: folder, readOnly: options.readOnly };
    },
  };
  _internal.disableWrites(client);
  for (const options of [undefined, {}, { readOnly: false }]) {
    assert.throws(() => client.mailboxOpen('INBOX', options), /read-only server/);
  }
  assert.equal(opened, false);
  assert.throws(() => client.mailboxClose(), /read-only server/);
  const box = await client.mailboxOpen('INBOX', { readOnly: true });
  assert.equal(box.readOnly, true);
  assert.equal(opened, true);
});
