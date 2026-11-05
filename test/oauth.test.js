import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { GMAIL_ROOT, googleJson, SCOPE, TOKEN_URL } from '../google-http.js';
import {
  authorize,
  createTokenManager,
  loopbackAuthorization,
  readDesktopClient,
  validateScope,
} from '../oauth.js';

const account = { id: 'personal', type: 'gmail', user: 'first@example.test' };
const credential = {
  address: account.user,
  client_id: 'example.apps.googleusercontent.com',
  client_secret: 'test-client-value',
  refresh_token: 'test-refresh-value',
  scope: SCOPE,
};
const token = {
  access_token: 'test-access-value',
  token_type: 'Bearer',
  expires_in: 3600,
  scope: SCOPE,
};
const json = (value, status = 200) => new Response(JSON.stringify(value), { status });

test('desktop credentials ignore supplied destinations and reject web clients without exposing their content', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mail-oauth-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'client.json');
  fs.writeFileSync(
    file,
    JSON.stringify({
      installed: {
        ...credential,
        redirect_uris: ['http://localhost'],
        token_uri: 'https://attacker.example/token',
      },
    }),
    { mode: 0o600 },
  );
  assert.deepEqual(readDesktopClient(file), {
    client_id: credential.client_id,
    client_secret: credential.client_secret,
  });
  fs.chmodSync(file, 0o666);
  assert.throws(() => readDesktopClient(file), /non-writable-by-others/);
  fs.chmodSync(file, 0o600);
  fs.writeFileSync(file, JSON.stringify({ web: credential }));
  assert.throws(() => readDesktopClient(file), /desktop/);
  fs.writeFileSync(file, 'secret-content invalid json');
  assert.throws(
    () => readDesktopClient(file),
    (e) => !e.message.includes('secret-content'),
  );
});

test('only the exact read-only Gmail scope is accepted', () => {
  validateScope(SCOPE);
  for (const scope of [
    undefined,
    '',
    'https://mail.google.com/',
    `${SCOPE} openid`,
    `${SCOPE} ${SCOPE}`,
  ]) {
    assert.throws(() => validateScope(scope), /only gmail.readonly/);
  }
});

test('PKCE loopback flow rejects invalid state and host, then accepts the original callback and closes', async () => {
  let authUrl;
  const result = await loopbackAuthorization(account, credential, {
    timeoutMs: 3000,
    openBrowser: async (url) => {
      authUrl = new URL(url);
      assert.equal(authUrl.origin, 'https://accounts.google.com');
      assert.equal(authUrl.searchParams.get('scope'), SCOPE);
      assert.equal(authUrl.searchParams.get('access_type'), 'offline');
      assert.equal(authUrl.searchParams.get('include_granted_scopes'), 'false');
      assert.equal(authUrl.searchParams.get('code_challenge_method'), 'S256');
      const callback = new URL(authUrl.searchParams.get('redirect_uri'));
      assert.equal(callback.hostname, '127.0.0.1');
      callback.search = new URLSearchParams({ state: 'wrong', code: 'wrong-code' });
      assert.equal((await fetch(callback)).status, 400);
      callback.search = new URLSearchParams({
        state: authUrl.searchParams.get('state'),
        code: 'test-code',
      });
      const wrongHostStatus = await new Promise((resolve, reject) => {
        const request = http.get(
          callback,
          { headers: { Host: 'attacker.example' } },
          (response) => {
            response.resume();
            resolve(response.statusCode);
          },
        );
        request.on('error', reject);
      });
      assert.equal(wrongHostStatus, 400);
      const response = await fetch(callback);
      assert.equal(response.status, 200);
      assert.equal(response.headers.get('cache-control'), 'no-store');
    },
  });
  assert.equal(result.code, 'test-code');
  assert.equal(
    createHash('sha256').update(result.code_verifier).digest('base64url'),
    authUrl.searchParams.get('code_challenge'),
  );
  await assert.rejects(fetch(result.redirect_uri));
});

test('denied consent, timeout and browser failure clean up the callback listener', async () => {
  await assert.rejects(loopbackAuthorization(account, credential, { timeoutMs: 10 }), /timed out/);
  await assert.rejects(
    loopbackAuthorization(account, credential, {
      openBrowser: async (url) => {
        const auth = new URL(url);
        const callback = new URL(auth.searchParams.get('redirect_uri'));
        callback.search = new URLSearchParams({
          state: auth.searchParams.get('state'),
          error: 'access_denied',
        });
        await fetch(callback);
      },
    }),
    /Test users/,
  );
  let callback;
  await assert.rejects(
    loopbackAuthorization(account, credential, {
      openBrowser: async (url) => {
        callback = new URL(url).searchParams.get('redirect_uri');
        throw new Error('test browser failure');
      },
    }),
    /browser failure/,
  );
  await assert.rejects(fetch(callback));
});

test('refresh is automatic, single-flight, cached, identity-checked and isolated by account', async () => {
  let reads = 0,
    refreshes = 0,
    profiles = 0;
  const manager = createTokenManager({
    read: async (id) => {
      reads++;
      return { ...credential, address: id === 'personal' ? account.user : 'second@example.test' };
    },
    fetchImpl: async (url, options) => {
      if (url === TOKEN_URL) {
        refreshes++;
        assert.equal(options.body.get('grant_type'), 'refresh_token');
        return json({ ...token, access_token: `access-${refreshes}` });
      }
      assert.equal(url, `${GMAIL_ROOT}profile`);
      profiles++;
      return json({
        emailAddress:
          options.headers.Authorization === 'Bearer access-1'
            ? account.user
            : 'second@example.test',
      });
    },
  });
  const values = await Promise.all([manager.get(account), manager.get(account)]);
  assert.deepEqual(values, ['access-1', 'access-1']);
  assert.equal(await manager.get(account), 'access-1');
  const second = { ...account, id: 'jaw', user: 'second@example.test' };
  assert.equal(await manager.get(second), 'access-2');
  assert.equal(reads, 2);
  assert.equal(refreshes, 2);
  assert.equal(profiles, 2);
  manager.invalidate(account);
  assert.equal(await manager.get(second), 'access-2');
});

test('expired and missing credentials have actionable errors and never echo OAuth response bodies', async () => {
  const missing = createTokenManager({
    read: async () => {
      throw new Error('sensitive-keychain-output');
    },
  });
  await assert.rejects(
    missing.get(account),
    (e) => /auth personal/.test(e.message) && !/sensitive/.test(e.message),
  );
  const expired = createTokenManager({
    read: async () => credential,
    fetchImpl: async () =>
      json({ error: 'invalid_grant', error_description: 'sensitive-server-output' }, 400),
  });
  await assert.rejects(
    expired.get(account),
    (e) => /seven days/.test(e.message) && !/sensitive-server/.test(e.message),
  );
  const mismatch = createTokenManager({
    read: async () => ({ ...credential, address: 'wrong@example.test' }),
    fetchImpl: async () => {
      assert.fail('must reject before sending a token');
    },
  });
  await assert.rejects(mismatch.get(account), /login needed/);
});

test('authorization saves only after identity, offline refresh and label checks pass', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mail-auth-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'client.json');
  fs.writeFileSync(
    file,
    JSON.stringify({ installed: { ...credential, redirect_uris: ['http://localhost'] } }),
    { mode: 0o600 },
  );
  for (const failure of ['identity', 'refresh', 'labels', 'scope', 'missing-refresh', null]) {
    const calls = [];
    let saved;
    const work = authorize(account, file, {
      flow: async () => ({
        code: 'test-code',
        code_verifier: 'test-verifier',
        redirect_uri: 'http://127.0.0.1/callback',
      }),
      fetchImpl: async (url, options) => {
        calls.push(url);
        if (url === TOKEN_URL) {
          if (options.body.get('grant_type') === 'authorization_code') {
            assert.equal(options.body.get('code_verifier'), 'test-verifier');
            return json({
              ...token,
              scope: failure === 'scope' ? `${SCOPE} openid` : SCOPE,
              ...(failure === 'missing-refresh' ? {} : { refresh_token: credential.refresh_token }),
            });
          }
          if (failure === 'refresh') return json({ error: 'invalid_grant' }, 400);
          return json(token);
        }
        if (url.endsWith('profile'))
          return json({
            emailAddress: failure === 'identity' ? 'wrong@example.test' : account.user,
          });
        if (failure === 'labels') return json({}, 403);
        return json({ labels: [] });
      },
      write: async (id, value) => {
        assert.equal(id, account.id);
        saved = value;
      },
    });
    if (failure) {
      await assert.rejects(work);
      assert.equal(saved, undefined, failure);
    } else {
      await work;
      assert.equal(saved.address, account.user);
      assert.equal(saved.refresh_token, credential.refresh_token);
      assert.equal(saved.access_token, undefined);
      assert.deepEqual(calls, [
        TOKEN_URL,
        `${GMAIL_ROOT}profile`,
        TOKEN_URL,
        `${GMAIL_ROOT}profile`,
        `${GMAIL_ROOT}labels`,
      ]);
    }
  }
});

test('HTTP rejects redirects, limits streaming bytes and sanitizes failures', async () => {
  await assert.rejects(
    googleJson(
      TOKEN_URL,
      {},
      {
        maxBytes: 3,
        fetchImpl: async (_url, options) => {
          assert.equal(options.redirect, 'error');
          return json({ large: 'data' });
        },
      },
    ),
    /download limit/,
  );
  await assert.rejects(
    googleJson(
      TOKEN_URL,
      {},
      { fetchImpl: async () => json({ error: { message: 'do-not-echo' } }, 403) },
    ),
    (e) => e.status === 403 && !e.message.includes('do-not-echo'),
  );
});
