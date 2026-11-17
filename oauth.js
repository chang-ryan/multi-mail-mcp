import { execFile, spawn } from 'node:child_process';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import { GMAIL_ROOT, googleJson, REVOKE_URL, SCOPE, TOKEN_URL } from './google-http.js';

export const OAUTH_SERVICE = 'multi-mail-mcp.gmail-oauth';
const ID = /^[a-z0-9][a-z0-9_-]{0,31}$/;

/**
 * @typedef {object} OAuthProfile
 * @property {string} name Shown in messages, e.g. "Gmail".
 * @property {string} service Keychain service holding this product's credentials.
 * @property {string[]} scopes The exact granted scope set; anything more or less is refused.
 * @property {string} requestScope The scope parameter sent to Google's consent screen.
 * @property {string} scopeError
 * @property {string} command Login command for hints; every %s becomes the account id.
 * @property {(accessToken: string, fetchImpl: typeof fetch, signal?: AbortSignal) => Promise<string>} identity
 *   Returns the address the token belongs to.
 * @property {(accessToken: string, fetchImpl: typeof fetch, previous: any, account: import('./types.js').Account) => Promise<Record<string, unknown>>} [prepare]
 *   Runs after consent and before saving; returns extra non-secret fields to store.
 * @property {string[]} [metadata] Stored non-secret fields exposed by the token manager.
 */

/** @type {OAuthProfile} */
export const GMAIL = {
  name: 'Gmail',
  service: OAUTH_SERVICE,
  scopes: [SCOPE],
  requestScope: SCOPE,
  scopeError:
    'OAuth grant must contain only gmail.readonly; revoke the old grant and authorize again',
  command: 'MAIL_ACCOUNTS=%s node index.js auth %s',
  async identity(accessToken, fetchImpl, signal) {
    const profile = await googleJson(
      `${GMAIL_ROOT}profile`,
      { headers: { Authorization: `Bearer ${accessToken}` }, signal },
      { fetchImpl },
    );
    return profile.emailAddress;
  },
  async prepare(accessToken, fetchImpl) {
    await googleJson(
      `${GMAIL_ROOT}labels`,
      { headers: { Authorization: `Bearer ${accessToken}` } },
      { fetchImpl },
    );
    return {};
  },
};

const loginHint = (a, profile = GMAIL) =>
  `${profile.name} login needed for "${a.id}". Run ${profile.command.replaceAll('%s', a.id)} --client /absolute/path/to/client_secret.json. If consent is blocked, register ${a.user} under Google Auth Platform > Audience > Test users.`;

function keychainRead(id, service = OAUTH_SERVICE) {
  return new Promise((resolve, reject) => {
    execFile(
      '/usr/bin/security',
      ['find-generic-password', '-s', service, '-a', id, '-w'],
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
export function keychainWrite(id, credential, service = OAUTH_SERVICE) {
  if (!ID.test(id)) throw new Error('Invalid Keychain account id');
  if (!/^[a-z0-9.-]{1,64}$/.test(service)) throw new Error('Invalid Keychain service');
  const encoded = Buffer.from(JSON.stringify(credential)).toString('base64url');
  const command = `add-generic-password -U -s ${service} -a ${id} -w ${encoded}\n`;
  // security's interactive parser has a 4096-byte line buffer. A truncated update could
  // replace a working credential with invalid data before the read-back detects failure.
  if (Buffer.byteLength(command) >= 4096)
    throw new Error(
      'OAuth credential exceeds the Keychain command limit; existing credential was not changed',
    );
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
        const stored = await keychainRead(id, service);
        if (JSON.stringify(stored) !== JSON.stringify(credential)) throw new Error();
        resolve();
      } catch {
        reject(new Error('Could not verify OAuth credential stored in macOS Keychain'));
      }
    });
    child.stdin.end(command);
  });
}

function keychainDelete(id, service = OAUTH_SERVICE) {
  return new Promise((resolve, reject) => {
    execFile(
      '/usr/bin/security',
      ['delete-generic-password', '-s', service, '-a', id],
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

// Google may report the `email` scope by its long name.
const SCOPE_ALIASES = { email: 'https://www.googleapis.com/auth/userinfo.email' };

/** @param {unknown} scope @param {OAuthProfile} [profile] */
export function validateScope(scope, profile = GMAIL) {
  const granted =
    typeof scope === 'string'
      ? scope
          .trim()
          .split(/\s+/)
          .map((s) => SCOPE_ALIASES[s] || s)
      : [];
  const expected = new Set(profile.scopes);
  if (
    new Set(granted).size !== granted.length ||
    granted.length !== expected.size ||
    !granted.every((s) => expected.has(s))
  )
    throw new Error(profile.scopeError);
}

export async function tokenRequest(params, fetchImpl = fetch, signal, profile = GMAIL) {
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
  if (token.scope !== undefined) validateScope(token.scope, profile);
  return token;
}

export async function verifyIdentity(
  account,
  accessToken,
  fetchImpl = fetch,
  signal,
  profile = GMAIL,
) {
  const address = await profile.identity(accessToken, fetchImpl, signal);
  if (typeof address !== 'string' || address.toLowerCase() !== account.user.toLowerCase()) {
    throw new Error(
      `Authorized ${profile.name} address does not match configured account "${account.id}"; credentials were not saved`,
    );
  }
  return address;
}

export function createTokenManager({
  read = keychainRead,
  fetchImpl = fetch,
  profile = GMAIL,
} = {}) {
  const cache = new Map();
  const pending = new Map();
  return {
    invalidate(account) {
      cache.delete(`${account.id}:${account.user}`);
    },
    /** Stored non-secret fields (profile.metadata) from the credential behind the last `get`. */
    metadata(account) {
      return cache.get(`${account.id}:${account.user}`)?.metadata || {};
    },
    async get(account, signal) {
      const key = `${account.id}:${account.user}`;
      if ((cache.get(key)?.expires || 0) > Date.now() + 60000) return cache.get(key).token;
      if (pending.has(key)) return pending.get(key);
      const work = (async () => {
        let c;
        try {
          c = await read(account.id, profile.service);
        } catch {
          throw new Error(loginHint(account, profile));
        }
        if (
          c?.address?.toLowerCase() !== account.user.toLowerCase() ||
          !c.refresh_token ||
          !c.client_id ||
          !c.client_secret
        ) {
          throw new Error(loginHint(account, profile));
        }
        validateScope(c.scope, profile);
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
            profile,
          );
        } catch (err) {
          if (err.oauthCode === 'invalid_grant' || err.status === 401)
            throw new Error(
              `${loginHint(account, profile)} Testing-mode refresh tokens expire after seven days.`,
            );
          if (err.oauthCode === 'invalid_client')
            throw new Error(
              'OAuth client is invalid; download current desktop credentials and run auth again',
            );
          throw err;
        }
        await verifyIdentity(account, token.access_token, fetchImpl, signal, profile);
        cache.set(key, {
          token: token.access_token,
          expires: Date.now() + token.expires_in * 1000,
          metadata: Object.fromEntries((profile.metadata || []).map((k) => [k, c[k]])),
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

/**
 * @param {import('./types.js').Account} account
 * @param {{ client_id: string, client_secret?: string }} client
 * @param {{ openBrowser?: (url: string) => Promise<void>, timeoutMs?: number, onReady?: (url: string) => void, profile?: OAuthProfile }} [options]
 */
export async function loopbackAuthorization(
  account,
  client,
  { openBrowser, timeoutMs = 300000, onReady = () => {}, profile = GMAIL } = {},
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
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Content-Type-Options', 'nosniff');
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
    const issuers = url.searchParams.getAll('iss');
    if (
      issuers.length > 1 ||
      (issuers.length === 1 && issuers[0] !== 'https://accounts.google.com')
    ) {
      res.writeHead(400).end('Invalid OAuth issuer');
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
      fail(new Error(loginHint(account, profile)));
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
      server.listen(0, '127.0.0.1', () => resolve(undefined));
    });
    expectedHost = `127.0.0.1:${/** @type {import('node:net').AddressInfo} */ (server.address()).port}`;
    const redirect_uri = `http://${expectedHost}/oauth/callback`;
    const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    url.search = new URLSearchParams({
      client_id: client.client_id,
      redirect_uri,
      response_type: 'code',
      scope: profile.requestScope,
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
  {
    noOpen = false,
    fetchImpl = fetch,
    write = keychainWrite,
    read = keychainRead,
    flow = loopbackAuthorization,
    profile = GMAIL,
    manager = tokenManager,
  } = {},
) {
  if (account.type !== 'gmail')
    throw new Error(`${profile.name} login is available only for Google accounts`);
  const client = readDesktopClient(clientFile);
  const grant = await flow(account, client, {
    openBrowser: noOpen ? undefined : launchBrowser,
    profile,
    onReady: (url) => {
      console.log(`Authorize ${account.user} in your browser:\n${url}`);
    },
  });
  const token = await tokenRequest(
    { ...client, ...grant, grant_type: 'authorization_code' },
    fetchImpl,
    undefined,
    profile,
  );
  validateScope(token.scope, profile);
  if (typeof token.refresh_token !== 'string' || !token.refresh_token)
    throw new Error(
      'Google did not return a refresh token; revoke this app grant, then run auth again',
    );
  await verifyIdentity(account, token.access_token, fetchImpl, undefined, profile);
  // Exercise offline refresh before saving, then verify that refreshed access still belongs here.
  const refreshed = await tokenRequest(
    { ...client, refresh_token: token.refresh_token, grant_type: 'refresh_token' },
    fetchImpl,
    undefined,
    profile,
  );
  await verifyIdentity(account, refreshed.access_token, fetchImpl, undefined, profile);
  let previous = null;
  try {
    previous = await read(account.id, profile.service);
    if (previous?.address?.toLowerCase() !== account.user.toLowerCase()) previous = null;
  } catch {
    previous = null;
  }
  const extra = profile.prepare
    ? await profile.prepare(refreshed.access_token, fetchImpl, previous, account)
    : {};
  await write(
    account.id,
    {
      ...extra,
      ...client,
      refresh_token: token.refresh_token,
      scope: profile.scopes.join(' '),
      address: account.user,
      authorized_at: new Date().toISOString(),
    },
    profile.service,
  );
  manager.invalidate(account);
  return extra;
}

export async function revoke(account, { profile = GMAIL, manager = tokenManager } = {}) {
  if (account.type !== 'gmail')
    throw new Error(`${profile.name} revocation is available only for Google accounts`);
  const c = await keychainRead(account.id, profile.service);
  if (c.address?.toLowerCase() !== account.user.toLowerCase())
    throw new Error('OAuth credential address mismatch');
  await googleJson(REVOKE_URL, {
    method: 'POST',
    body: new URLSearchParams({ token: c.refresh_token }),
  });
  await keychainDelete(account.id, profile.service);
  manager.invalidate(account);
}
