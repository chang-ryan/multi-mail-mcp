// Fixed Google endpoints only. Never include response bodies or bearer tokens in errors.
export const GMAIL_ROOT = 'https://gmail.googleapis.com/gmail/v1/users/me/';
export const TOKEN_URL = 'https://oauth2.googleapis.com/token';
export const REVOKE_URL = 'https://oauth2.googleapis.com/revoke';
export const SCOPE = 'https://www.googleapis.com/auth/gmail.readonly';

function validateDestination(value, method) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error('Google request destination refused');
  }
  const credentialEndpoint = url.href === TOKEN_URL || url.href === REVOKE_URL;
  const gmailRead =
    url.origin === 'https://gmail.googleapis.com' &&
    /^\/gmail\/v1\/users\/me\/(?:profile|labels|messages|messages\/[a-f0-9]{1,32}|threads\/[a-f0-9]{1,32})$/.test(
      url.pathname,
    );
  if (
    url.username ||
    url.password ||
    url.hash ||
    (credentialEndpoint ? method !== 'POST' : !gmailRead || method !== 'GET')
  ) {
    throw new Error('Google request destination or method refused');
  }
}

/**
 * @param {string} url
 * @param {RequestInit} [options]
 * @param {{ fetchImpl?: typeof fetch, maxBytes?: number, onBytes?: (bytes: number) => void }} [limits]
 */
export async function googleJson(
  url,
  options = {},
  { fetchImpl = fetch, maxBytes = 1024 * 1024, onBytes = () => {} } = {},
) {
  validateDestination(url, options.method || 'GET');
  let response;
  try {
    response = await fetchImpl(url, {
      ...options,
      redirect: 'error',
      signal: options.signal || AbortSignal.timeout(30000),
    });
  } catch {
    throw new Error('Google request failed or timed out; check network access and retry');
  }
  const declared = Number(response.headers.get('content-length'));
  if (declared > maxBytes) {
    await response.body?.cancel();
    throw new Error('Google response exceeds the download limit');
  }
  const chunks = [];
  let total = 0;
  if (response.body) {
    const reader = response.body.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maxBytes) throw new Error('Google response exceeds the download limit');
        onBytes(value.byteLength);
        chunks.push(Buffer.from(value));
      }
    } finally {
      await reader.cancel().catch(() => {});
      reader.releaseLock();
    }
  }
  let data;
  try {
    data = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
  } catch {
    throw new Error(`Google returned an invalid response (HTTP ${response.status})`);
  }
  if (!response.ok) {
    /** @type {Error & { status?: number, oauthCode?: string }} */
    const error = new Error(`Google request failed (HTTP ${response.status})`);
    error.status = response.status;
    // Only fixed, recognized codes cross the error boundary.
    if (['invalid_grant', 'invalid_client', 'access_denied'].includes(data.error))
      error.oauthCode = data.error;
    throw error;
  }
  return data;
}
