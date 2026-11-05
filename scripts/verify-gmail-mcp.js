#!/usr/bin/env node
// Opt-in live integration check. Uses the actual stdio MCP tools; prints no email content.
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { publicError } from '../security.js';

const client = new Client({ name: 'multi-mail-live-verification', version: '1.0.0' });
async function call(name, args) {
  const result = await client.callTool({ name, arguments: args }, undefined, { timeout: 150000 });
  const data = JSON.parse(result.content[0].text);
  if (result.isError) throw new Error(`${name}: ${data.error}`);
  return data;
}

try {
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [fileURLToPath(new URL('../index.js', import.meta.url))],
      env: Object.fromEntries(
        Object.entries(process.env).filter(([, value]) => value !== undefined),
      ),
      stderr: 'inherit',
    }),
  );
  const { accounts } = await call('mail__list_accounts', {});
  assert.ok(accounts.length > 0);
  for (const account of accounts) {
    assert.equal(account.backend, 'gmail-api', 'Scope this check to Gmail API accounts only');
    const args = { account: account.id };
    const { folders } = await call('mail__list_folders', args);
    assert.ok(folders.some((f) => f.path === 'INBOX'));
    await call('mail__list_messages', { ...args, folder: 'INBOX', limit: 1 });
    const { messages } = await call('mail__search', { ...args, query: 'smaller:1M', limit: 1 });
    if (messages.length) {
      const { folder, uid } = messages[0];
      const message = await call('mail__get_message', { ...args, folder, uid, max_chars: 100 });
      assert.equal(message.uid, uid);
      assert.ok(message._untrusted);
      await call('mail__get_thread', { ...args, folder, uid, max_chars: 100 });
    }
    const found = await call('mail__search', {
      ...args,
      query: 'has:attachment smaller:1M',
      limit: 1,
    });
    let attachmentChecked = false;
    if (found.messages.length) {
      const { folder, uid } = found.messages[0];
      const message = await call('mail__get_message', { ...args, folder, uid, max_chars: 1 });
      if (message.attachments.length) {
        const result = await call('mail__get_attachments', {
          ...args,
          folder,
          uid,
          indexes: [message.attachments[0].index],
          save: false,
        });
        assert.equal(result.attachments.length, 1);
        assert.equal(typeof result.attachments[0].content_base64, 'string');
        attachmentChecked = true;
      }
    }
    console.log(
      `ok ${account.id}: folders, list, search${messages.length ? ', message, thread' : ' (mailbox has no small messages; reads skipped)'}; attachment ${attachmentChecked ? 'checked' : 'skipped (no suitable attachment)'}`,
    );
  }
  const denied = await client.callTool({
    name: 'mail__list_folders',
    arguments: { account: '_scope_probe' },
  });
  assert.equal(denied.isError, true);
  assert.match(JSON.parse(denied.content[0].text).error, /not available here/);
  console.log('ok account isolation');
} catch (error) {
  console.error(publicError(error));
  process.exitCode = 1;
} finally {
  await client.close();
}
