import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { _internal } from '../mail.js';
import { isCalendarDate, stripHidden, publicError } from '../security.js';

const repo = fileURLToPath(new URL('../', import.meta.url));
const registry = { accounts: {
  first: { type: 'gmail', user: 'first@example.test' },
  second: { type: 'proton', user: 'second@example.test' },
} };
function fixture(t) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'multi-mail-test-')));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const config = path.join(dir, 'accounts.json');
  fs.writeFileSync(config, JSON.stringify(registry), { mode: 0o600 });
  return { dir, config, env: { PATH: process.env.PATH, MAIL_MCP_CONFIG: config, MAIL_ACCOUNTS: 'first' } };
}
function startup(env) {
  return spawnSync(process.execPath, [path.join(repo, 'index.js')], {
    env, encoding: 'utf8', timeout: 10000,
  });
}

test('filenames retain allowed extensions at and beyond the length boundary', () => {
  for (const length of [145, 146, 147, 148, 149, 150, 151, 250]) {
    const name = 'a'.repeat(length - 4) + '.pdf';
    const safe = _internal.safeName(name, 0);
    assert.equal(path.extname(safe), '.pdf');
    assert.ok(safe.length <= 150);
    if (length <= 150) assert.equal(safe, name);
  }
  assert.equal(_internal.safeName('../../invoice.pdf', 0), 'invoice.pdf');
  assert.equal(_internal.safeName('..\\invoice.pdf', 0), 'invoice.pdf');
  assert.equal(_internal.safeName('\u202einvoice.pdf', 0), 'invoice.pdf');
});

test('legacy Office and executable formats are refused', () => {
  for (const ext of ['doc', 'xls', 'ppt', 'docm', 'xlsm', 'pptm', 'exe', 'html', 'zip']) {
    assert.equal(_internal.SAVE_EXTENSIONS.has(ext), false, ext);
  }
  for (const ext of ['pdf', 'png', 'docx', 'xlsx', 'pptx']) {
    assert.equal(_internal.SAVE_EXTENSIONS.has(ext), true, ext);
  }
});

test('directory checks reject symlink escapes before creating outside folders', (t) => {
  const { dir } = fixture(t);
  const root = path.join(dir, 'root');
  const outside = path.join(dir, 'outside');
  fs.mkdirSync(root); fs.mkdirSync(outside);
  fs.symlinkSync(outside, path.join(root, 'escape'));
  fs.symlinkSync(path.join(outside, 'missing'), path.join(root, 'dangling'));
  for (const subdir of ['escape', 'escape/deeper', 'escape/a/b', '../outside/deeper', outside, 'dangling/deeper']) {
    assert.throws(() => _internal.resolveSaveDir(root, subdir));
  }
  assert.deepEqual(fs.readdirSync(outside), []);
  assert.equal(_internal.resolveSaveDir(root, 'a/b'), path.join(root, 'a/b'));
});

test('exclusive saving preserves existing files and refuses to follow file symlinks', (t) => {
  const { dir } = fixture(t);
  const original = path.join(dir, 'original');
  fs.writeFileSync(original, 'keep');
  fs.symlinkSync(original, path.join(dir, 'invoice.pdf'));
  const saved = _internal.writeExclusive(dir, 'invoice.pdf', Buffer.from('new'));
  assert.equal(path.basename(saved), 'invoice (2).pdf');
  assert.equal(fs.readFileSync(original, 'utf8'), 'keep');
  assert.equal(fs.statSync(saved).mode & 0o777, 0o600);
});

test('read-only operations fail closed when the server omits confirmation', async () => {
  for (const mode of [false, undefined, true]) {
    let released = false;
    const client = {
      mailbox: { readOnly: mode },
      async getMailboxLock(folder, options) {
        assert.deepEqual(options, { readOnly: true });
        return { release() { released = true; } };
      },
    };
    if (mode === true) {
      const lock = await _internal.openRO(client, 'INBOX');
      assert.equal(released, false); lock.release();
    } else {
      await assert.rejects(_internal.openRO(client, 'INBOX'), /refusing/);
    }
    assert.equal(released, true);
  }
  const client = {};
  _internal.disableWrites(client);
  for (const name of Object.getOwnPropertyNames(client)) {
    assert.throws(() => client[name](), /read-only server/);
    assert.throws(() => { client[name] = () => {}; }, TypeError);
  }
});

test('calendar dates reject normalization and validate leap years', () => {
  for (const value of ['2026-02-29', '2026-02-30', '2026-04-31', '2026-13-01', '2026-00-01', 'no']) {
    assert.equal(isCalendarDate(value), false, value);
  }
  for (const value of ['2024-02-29', '2026-02-28', '2026-12-31']) {
    assert.equal(isCalendarDate(value), true, value);
  }
});

test('errors remove hidden characters and never stringify arbitrary rejected objects', () => {
  assert.deepEqual(stripHidden('a\u202eb\u{e0061}\0\nc'), { text: 'ab\nc', removed: 3 });
  assert.equal(publicError(new Error('a\u202eb\0')), 'ab');
  assert.equal(publicError({ password: 'do not print' }), 'Operation failed');
  assert.equal(publicError(new Error('x'.repeat(600))).length, 500);
});

test('quarantine reports a failure instead of silently reporting success', async (t) => {
  const { dir } = fixture(t);
  assert.equal(await _internal.quarantine(path.join(dir, 'missing.pdf')), false);
});

test('startup rejects writable, malformed and empty registries with a nonzero status', (t) => {
  const { config, env } = fixture(t);
  fs.chmodSync(config, 0o666);
  let result = startup(env);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /writable by group or others/);
  fs.chmodSync(config, 0o600);
  for (const invalid of [{}, { accounts: {} }, { accounts: [] }, { ...registry, password: 'test-secret' },
    { accounts: { first: { ...registry.accounts.first, app_password: 'test-secret' } } }]) {
    fs.writeFileSync(config, JSON.stringify(invalid));
    result = startup(env);
    assert.equal(result.status, 1);
    assert.ok(!result.stderr.includes('test-secret'));
  }
  fs.writeFileSync(config, '{"accounts": "test-secret" invalid');
  result = startup(env);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /not valid JSON/);
  assert.ok(!result.stderr.includes('test-secret'));
});

test('MCP validates inputs and enforces account scoping without contacting mailboxes', async (t) => {
  const { env } = fixture(t);
  const transport = new StdioClientTransport({ command: process.execPath,
    args: [path.join(repo, 'index.js')], env, stderr: 'pipe' });
  const client = new Client({ name: 'offline-security-test', version: '1.0.0' });
  t.after(() => client.close());
  await client.connect(transport);
  const result = await client.callTool({ name: 'mail__list_accounts', arguments: {} });
  const accounts = JSON.parse(result.content[0].text).accounts;
  assert.deepEqual(accounts.map((a) => a.id), ['first']);
  for (const args of [{ since: '2026-02-30' }, { from: 'x\r\ny' }, { limit: 201 }]) {
    const response = await client.callTool({ name: 'mail__search', arguments: args });
    assert.equal(response.isError, true);
    assert.ok(!JSON.stringify(response).includes('Keychain'));
  }
  const disabledSave = await client.callTool({ name: 'mail__get_attachments',
    arguments: { account: 'first', folder: 'INBOX', uid: 1, save: true } });
  assert.equal(disabledSave.isError, true);
  assert.match(JSON.parse(disabledSave.content[0].text).error, /Saving is off/);
  const denied = await client.callTool({ name: 'mail__list_folders', arguments: { account: 'second' } });
  assert.equal(denied.isError, true);
  const payload = JSON.parse(denied.content[0].text);
  assert.ok(payload._untrusted);
  assert.match(payload.error, /not available here/);
});
