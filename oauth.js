import { execFile, spawn } from 'node:child_process';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import { GMAIL_ROOT, googleJson, REVOKE_URL, SCOPE, TOKEN_URL } from './google-http.js';

export const OAUTH_SERVICE = 'multi-mail-mcp.gmail-oauth';
const ID = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const loginHint = (a) =>
  `Gmail login needed for "${a.id}". Run MAIL_ACCOUNTS=${a.id} node index.js auth ${a.id} --client /absolute/path/to/client_secret.json. If consent is blocked, register ${a.user} under Google Auth Platform > Audience > Test users.`;

function keychainRead(id) {
  return new Promise((resolve, reject) => {
    execFile(
      '/usr/bin/security',
      ['find-generic-password', '-s', OAUTH_SERVICE, '-a', id, '-w'],
      { timeout: 10000, maxBuffer: 16384, env: { PATH: '/usr/bin:/bin' } },
      (err, out) => {
        if (err) return reject(new Error('OAuth Keychain item missing or inaccessible'));
        try {
          resolve(JSON.parse(Buffer.from(out.trim(), 'base64url').toString('utf8')));
        } catch {
          reject(new Error('Invalid OAuth Keychain item'));
        }
      },
    );
  });
}

// The credential travels over stdin to security's command interpreter, never argv or a file.
// Base64url and a validated account id avoid interpreter quoting/injection entirely.
export function keychainWrite(id, credential) {
  if (!ID.test(id)) throw new Error('Invalid Keychain account id');
  const encoded = Buffer.from(JSON.stringify(credential)).toString('base64url');
  return new Promise((resolve, reject) => {
    const child = spawn('/usr/bin/security', ['-i'], {
      stdio: ['pipe', 'ignore', 'pipe'],
      env: { PATH: '/usr/bin:/bin' },
    });
    let failed = false;
    // security -i can exit zero even if a subcommand failed. Any diagnostics fail closed.
    child.stderr.on('data', (data) => {
      if (
        data
          .toString()
          .replace(/security>\s*/g, '')
          .trim()
      )
        failed = true;
    });
    const timer = setTimeout(() => {
      failed = true;
      child.kill();
    }, 15000);
    child.on('error', () => {
      failed = true;
    });
    child.stdin.on('error', () => {
      failed = true;
    });
    child.on('close', async (code) => {
      clearTimeout(timer);
      if (failed || code !== 0) {
        reject(new Error('Could not store OAuth credential in macOS Keychain'));
        return;
      }
      try {
        const stored = await keychainRead(id);
        if (JSON.stringify(stored) !== JSON.stringify(credential)) throw new Error();
        resolve();
      } catch {
        reject(new Error('Could not verify OAuth credential stored in macOS Keychain'));
      }
    });
    child.stdin.end(`add-generic-password -U -s ${OAUTH_SERVICE} -a ${id} -w ${encoded}\n`);
  });
}

function keychainDelete(id) {
  return new Promise((resolve, reject) => {
    execFile(
      '/usr/bin/security',
      ['delete-generic-password', '-s', OAUTH_SERVICE, '-a', id],
      { timeout: 10000 },
      (err) => (err ? reject(new Error('Could not delete OAuth Keychain item')) : resolve()),
    );
  });
}

export function readDesktopClient(file) {
  let client;
  try {
    const st = fs.statSync(file);
    if (
      !st.isFile() ||
      st.size > 65536 ||
      st.mode & 0o022 ||
      (process.getuid && st.uid !== process.getuid())
    )
      throw new Error();
    client = JSON.parse(fs.readFileSync(file, 'utf8')).installed;
  } catch {
    throw new Error(
      'Cannot read desktop OAuth client file; use an owned, non-writable-by-others installed credentials JSON',
    );
  }
  if (
    !client ||
    typeof client.client_id !== 'string' ||
    !client.client_id.endsWith('.apps.googleusercontent.com') ||
    typeof client.client_secret !== 'string' ||
    !client.client_secret ||
    !client.redirect_uris?.some((uri) => {
      try {
        const u = new URL(uri);
        return u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
      } catch {
        return false;
      }
    })
  )
    throw new Error('Expected Google desktop (installed) credentials with a localhost redirect');
  // Ignore endpoints from the file: all credential destinations are hard-coded.
  return { client_id: client.client_id, client_secret: client.client_secret };
}

export function validateScope(scope) {
  const scopes = typeof scope === 'string' ? scope.trim().split(/\s+/) : [];
  if (scopes.length !== 1 || scopes[0] !== SCOPE)
    throw new Error(
      'OAuth grant must contain only gmail.readonly; revoke the old grant and authorize again',
    );
}

export async function tokenRequest(params, fetchImpl = fetch, signal) {
  const token = await googleJson(
    TOKEN_URL,
    { method: 'POST', body: new URLSearchParams(params), signal },
    { fetchImpl, maxBytes: 65536 },
  );
  if (
    typeof token.access_token !== 'string' ||
    !token.access_token ||
    token.token_type?.toLowerCase() !== 'bearer' ||
    !Number.isFinite(token.expires_in) ||
    token.expires_in <= 0
  )
    throw new Error('Google returned an invalid access token response');
  if (token.scope !== undefined) validateScope(token.scope);
  return token;
}

export async function verifyIdentity(account, accessToken, fetchImpl = fetch, signal) {
  const profile = await googleJson(
    `${GMAIL_ROOT}profile`,
    { headers: { Authorization: `Bearer ${accessToken}` }, signal },
    { fetchImpl },
  );
  if (
    typeof profile.emailAddress !== 'string' ||
    profile.emailAddress.toLowerCase() !== account.user.toLowerCase()
  ) {
    throw new Error(
      `Authorized Gmail address does not match configured account "${account.id}"; credentials were not saved`,
    );
  }
  return profile;
}

export function createTokenManager({ read = keychainRead, fetchImpl = fetch } = {}) {
  const cache = new Map();
  const pending = new Map();
  return {
    invalidate(account) {
      cache.delete(`${account.id}:${account.user}`);
    },
    async get(account, signal) {
      const key = `${account.id}:${account.user}`;
      if ((cache.get(key)?.expires || 0) > Date.now() + 60000) return cache.get(key).token;
      if (pending.has(key)) return pending.get(key);
      const work = (async () => {
        let c;
        try {
          c = await read(account.id);
        } catch {
          throw new Error(loginHint(account));
        }
        if (
          c?.address?.toLowerCase() !== account.user.toLowerCase() ||
          !c.refresh_token ||
          !c.client_id ||
          !c.client_secret
        ) {
          throw new Error(loginHint(account));
        }
        validateScope(c.scope);
        let token;
        try {
          token = await tokenRequest(
            {
              client_id: c.client_id,
              client_secret: c.client_secret,
              refresh_token: c.refresh_token,
              grant_type: 'refresh_token',
            },
            fetchImpl,
            signal,
          );
        } catch (err) {
          if (err.oauthCode === 'invalid_grant' || err.status === 401)
            throw new Error(
              `${loginHint(account)} Testing-mode refresh tokens expire after seven days.`,
            );
          if (err.oauthCode === 'invalid_client')
            throw new Error(
              'OAuth client is invalid; download current desktop credentials and run auth again',
            );
          throw err;
        }
        await verifyIdentity(account, token.access_token, fetchImpl, signal);
        cache.set(key, {
          token: token.access_token,
          expires: Date.now() + token.expires_in * 1000,
        });
        return token.access_token;
      })();
      pending.set(key, work);
      try {
        return await work;
      } finally {
        pending.delete(key);
      }
    },
  };
}
export const tokenManager = createTokenManager();

export async function loopbackAuthorization(
  account,
  client,
  { openBrowser, timeoutMs = 300000, onReady = () => {} } = {},
) {
  const verifier = randomBytes(32).toString('base64url');
  const state = randomBytes(32).toString('base64url');
  let finish, fail, timer;
  const result = new Promise((resolve, reject) => {
    finish = resolve;
    fail = reject;
  });
  // Prevent a rejection while awaiting browser launch from becoming unhandled.
  result.catch(() => {});
  let expectedHost;
  const server = http.createServer((req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    if (req.method !== 'GET' || req.headers.host !== expectedHost) {
      res.writeHead(400).end('Invalid callback');
      return;
    }
    let url;
    try {
      url = new URL(req.url, `http://${expectedHost}`);
    } catch {
      res.writeHead(400).end('Invalid callback');
      return;
    }
    if (url.pathname !== '/oauth/callback') {
      res.writeHead(404).end('Not found');
      return;
    }
    const received = url.searchParams.getAll('state');
    if (
      received.length !== 1 ||
      Buffer.byteLength(received[0]) !== Buffer.byteLength(state) ||
      !timingSafeEqual(Buffer.from(received[0]), Buffer.from(state))
    ) {
      res.writeHead(400).end('Invalid OAuth state; return to the original login window');
      return;
    }
    if (url.searchParams.has('error')) {
      res.end('Authorization declined. Return to your terminal.');
      fail(new Error(loginHint(account)));
      return;
    }
    const codes = url.searchParams.getAll('code');
    if (codes.length !== 1 || !codes[0] || codes[0].length > 4096) {
      res.writeHead(400).end('Missing authorization code');
      return;
    }
    res.end(
      'Authorization received. Return to your terminal for address and connection verification.',
    );
    finish(codes[0]);
  });
  server.requestTimeout = 10000;
  server.headersTimeout = 10000;
  server.maxConnections = 8;
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    expectedHost = `127.0.0.1:${server.address().port}`;
    const redirect_uri = `http://${expectedHost}/oauth/callback`;
    const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    url.search = new URLSearchParams({
      client_id: client.client_id,
      redirect_uri,
      response_type: 'code',
      scope: SCOPE,
      access_type: 'offline',
      prompt: 'consent',
      include_granted_scopes: 'false',
      login_hint: account.user,
      state,
      code_challenge_method: 'S256',
      code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    }).toString();
    timer = setTimeout(() => fail(new Error('OAuth login timed out; run auth again')), timeoutMs);
    onReady(url.toString());
    if (openBrowser) await openBrowser(url.toString());
    return { code: await result, code_verifier: verifier, redirect_uri };
  } finally {
    clearTimeout(timer);
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
}

function launchBrowser(url) {
  return new Promise((resolve, reject) => {
    execFile('/usr/bin/open', [url], { timeout: 10000 }, (err) =>
      err
        ? reject(
            new Error(
              'Could not open browser; rerun auth with --no-open and use the printed login URL',
            ),
          )
        : resolve(),
    );
  });
}

export async function authorize(
  account,
  clientFile,
  { noOpen = false, fetchImpl = fetch, write = keychainWrite, flow = loopbackAuthorization } = {},
) {
  if (account.type !== 'gmail') throw new Error('OAuth login is available only for Gmail accounts');
  const client = readDesktopClient(clientFile);
  const grant = await flow(account, client, {
    openBrowser: noOpen ? undefined : launchBrowser,
    onReady: (url) => {
      console.log(`Authorize ${account.user} in your browser:\n${url}`);
    },
  });
  const token = await tokenRequest(
    { ...client, ...grant, grant_type: 'authorization_code' },
    fetchImpl,
  );
  validateScope(token.scope);
  if (typeof token.refresh_token !== 'string' || !token.refresh_token)
    throw new Error(
      'Google did not return a refresh token; revoke this app grant, then run auth again',
    );
  await verifyIdentity(account, token.access_token, fetchImpl);
  // Exercise offline refresh before saving, then verify that refreshed access still belongs here.
  const refreshed = await tokenRequest(
    { ...client, refresh_token: token.refresh_token, grant_type: 'refresh_token' },
    fetchImpl,
  );
  await verifyIdentity(account, refreshed.access_token, fetchImpl);
  await googleJson(
    `${GMAIL_ROOT}labels`,
    { headers: { Authorization: `Bearer ${refreshed.access_token}` } },
    { fetchImpl },
  );
  await write(account.id, {
    ...client,
    refresh_token: token.refresh_token,
    scope: SCOPE,
    address: account.user,
    authorized_at: new Date().toISOString(),
  });
  tokenManager.invalidate(account);
  console.log(
    `Authorized and tested ${account.id} (${account.user}); OAuth credential saved in Keychain. Backend unchanged. Enable gmail-api explicitly after checks.`,
  );
}

export async function revoke(account) {
  if (account.type !== 'gmail') throw new Error('OAuth revocation is available only for Gmail');
  const c = await keychainRead(account.id);
  if (c.address?.toLowerCase() !== account.user.toLowerCase())
    throw new Error('OAuth credential address mismatch');
  await googleJson(REVOKE_URL, {
    method: 'POST',
    body: new URLSearchParams({ token: c.refresh_token }),
  });
  await keychainDelete(account.id);
  tokenManager.invalidate(account);
  console.log(
    `Revoked and removed OAuth credential for ${account.id}. Existing app password was not changed.`,
  );
}
