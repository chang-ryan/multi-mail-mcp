/**
 * Account registry, allowlist, and credential lookup.
 *
 * accounts.json (no secrets) lists every mailbox this machine knows about.
 * MAIL_ACCOUNTS (env, set per harness) says which of them this process may open.
 * Passwords live in the macOS Keychain, never in a file this code reads.
 */

import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const KEYCHAIN_SERVICE = 'multi-mail-mcp';

const CONFIG_PATH =
  process.env.MAIL_MCP_CONFIG ||
  path.join(os.homedir(), '.config', 'multi-mail-mcp', 'accounts.json');

/**
 * Hosts are fixed per backend type. accounts.json cannot point a password at an arbitrary
 * server: Proton goes to the loopback Bridge, Gmail goes to Google over verified TLS.
 */
const BACKENDS = {
  proton: (a, id) => ({
    host: '127.0.0.1',
    port: parsePort(a.port ?? 1143, id),
    secure: false,
    // Bridge on loopback, cleartext. Bridge offers STARTTLS with a self-signed cert;
    // upgrading would mean disabling verification, which is no safer than loopback.
    doSTARTTLS: false,
  }),
  gmail: () => ({
    host: 'imap.gmail.com',
    port: 993,
    secure: true,
    tls: { rejectUnauthorized: true, minVersion: 'TLSv1.2', servername: 'imap.gmail.com' },
  }),
};

const ID_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/;
// biome-ignore lint/suspicious/noControlCharactersInRegex: Reject control characters in account addresses.
const USER_RE = /^[^\s@\x00-\x1f\x7f]+@[^\s@\x00-\x1f\x7f]+$/;
const ACCOUNT_KEYS = new Set(['type', 'user', 'label', 'port', 'backend']);
// biome-ignore lint/suspicious/noControlCharactersInRegex: Reject control characters in account labels.
const CONTROL_RE = /[\x00-\x1f\x7f]/;

function parsePort(v, id) {
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1 || n > 65535) throw new Error(`Account "${id}": bad port ${v}`);
  return n;
}

/**
 * The registry decides where a password is sent (the Proton port, at least), so refuse one
 * that someone other than this user could have edited.
 */
function checkRegistryFile(file) {
  const st = fs.statSync(file);
  if (!st.isFile()) throw new Error(`${file} is not a regular file`);
  if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
    throw new Error(`Refusing ${file}: not owned by the current user`);
  }
  if (st.mode & 0o022) {
    throw new Error(`Refusing ${file}: writable by group or others (chmod 600 or 644)`);
  }
}

function loadRegistry() {
  if (!fs.existsSync(CONFIG_PATH)) {
    throw new Error(`No account registry at ${CONFIG_PATH}. See README, "Setup".`);
  }
  checkRegistryFile(CONFIG_PATH);
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));
  } catch {
    // Parser errors can quote file contents, including an accidentally pasted password.
    throw new Error(`${CONFIG_PATH} is not valid JSON`);
  }
  if (
    !raw ||
    typeof raw !== 'object' ||
    Array.isArray(raw) ||
    Object.keys(raw).some((k) => k !== 'accounts') ||
    !raw.accounts ||
    typeof raw.accounts !== 'object' ||
    Array.isArray(raw.accounts) ||
    !Object.keys(raw.accounts).length
  ) {
    throw new Error('Registry must contain only a non-empty "accounts" object');
  }
  const accounts = Object.create(null);
  for (const [id, a] of Object.entries(raw?.accounts || {})) {
    if (!ID_RE.test(id)) throw new Error(`Bad account id "${id}" in ${CONFIG_PATH}`);
    if (!a || typeof a !== 'object') throw new Error(`Account "${id}": must be an object`);
    for (const k of Object.keys(a)) {
      if (/^pass(word)?$/i.test(k) || /secret|token/i.test(k)) {
        throw new Error(
          `Account "${id}": secrets do not belong in ${CONFIG_PATH}; use the Keychain`,
        );
      }
      if (!ACCOUNT_KEYS.has(k)) throw new Error(`Account "${id}": unknown key "${k}"`);
    }
    if (!Object.hasOwn(BACKENDS, a.type))
      throw new Error(`Account "${id}": type must be "proton" or "gmail"`);
    if (typeof a.user !== 'string' || !USER_RE.test(a.user))
      throw new Error(`Account "${id}": "user" must be an email address`);
    if (a.label !== undefined && (typeof a.label !== 'string' || CONTROL_RE.test(a.label))) {
      throw new Error(`Account "${id}": bad label`);
    }
    const backend = a.backend ?? 'imap';
    if (!['imap', 'gmail-api'].includes(backend) || (a.type !== 'gmail' && backend !== 'imap')) {
      throw new Error(
        `Account "${id}": backend must be imap (any account) or gmail-api (Gmail only)`,
      );
    }
    accounts[id] = Object.freeze({
      id,
      type: a.type,
      backend,
      user: a.user,
      label: a.label || id,
      ...BACKENDS[a.type](a, id),
    });
  }
  return accounts;
}

/**
 * MAIL_ACCOUNTS is required. "*" opens everything; otherwise a comma list of ids.
 * An unset variable is an error rather than "all", so forgetting it fails closed.
 */
function loadAllowlist(registry) {
  const spec = (process.env.MAIL_ACCOUNTS || '').trim();
  if (!spec) {
    throw new Error(
      'MAIL_ACCOUNTS is not set. Set it to a comma list of account ids, or "*" for all.',
    );
  }
  if (spec === '*') return Object.keys(registry);
  const ids = [
    ...new Set(
      spec
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
    ),
  ];
  const unknown = ids.filter((id) => !Object.hasOwn(registry, id));
  if (unknown.length)
    throw new Error(`MAIL_ACCOUNTS names unknown account(s): ${unknown.join(', ')}`);
  if (!ids.length) throw new Error('MAIL_ACCOUNTS lists no accounts');
  return ids;
}

/**
 * MAIL_SAVE_ROOT unset means saving is off. When set it must be an existing directory;
 * it is resolved through symlinks once, here, so later containment checks compare real paths.
 */
function loadSaveRoot() {
  const root = (process.env.MAIL_SAVE_ROOT || '').trim();
  if (!root) return null;
  if (!path.isAbsolute(root)) throw new Error('MAIL_SAVE_ROOT must be an absolute path');
  let real;
  try {
    real = fs.realpathSync(root);
  } catch {
    throw new Error(`MAIL_SAVE_ROOT does not exist: ${root}`);
  }
  if (!fs.statSync(real).isDirectory())
    throw new Error(`MAIL_SAVE_ROOT is not a directory: ${root}`);
  return real;
}

let _state = null;
function state() {
  if (!_state) {
    const registry = loadRegistry();
    const allowed = loadAllowlist(registry);
    // Explicit per-process trial/migration override; never expands MAIL_ACCOUNTS.
    const trial = (process.env.MAIL_GMAIL_API_ACCOUNTS || '').trim();
    const ids = trial ? [...new Set(trial.split(',').map((s) => s.trim()))] : [];
    for (const id of ids) {
      if (!allowed.includes(id) || registry[id]?.type !== 'gmail') {
        throw new Error('MAIL_GMAIL_API_ACCOUNTS must name allowed Gmail accounts');
      }
      registry[id] = Object.freeze({ ...registry[id], backend: 'gmail-api' });
    }
    _state = Object.freeze({ registry, allowed, saveRoot: loadSaveRoot() });
  }
  return _state;
}

/** Validate everything at startup, so misconfiguration fails before the first tool call. */
export function init() {
  state();
}

/** The accounts this process may open, without credentials. */
export function allowedAccounts() {
  const { registry, allowed } = state();
  return allowed.map((id) => {
    const { label, type, user, backend } = registry[id];
    return { id, label, type, backend, address: user };
  });
}

/**
 * Resolve the account a tool call names. With exactly one account allowed, the argument
 * may be omitted.
 */
export function resolveAccount(id) {
  const { registry, allowed } = state();
  if (!id) {
    if (allowed.length === 1) return registry[allowed[0]];
    throw new Error(`Name an account. Allowed here: ${allowed.join(', ')}`);
  }
  if (!allowed.includes(id)) {
    // Do not reveal whether the id exists elsewhere in the registry.
    throw new Error(
      `Account "${String(id).slice(0, 40)}" is not available here. Allowed: ${allowed.join(', ')}`,
    );
  }
  return registry[id];
}

/** Read the password for an account from the login Keychain. Never logged, never cached. */
export function getPassword(account) {
  return new Promise((resolve, reject) => {
    execFile(
      '/usr/bin/security',
      ['find-generic-password', '-s', KEYCHAIN_SERVICE, '-a', account.id, '-w'],
      { timeout: 10000, maxBuffer: 4096, env: { PATH: '/usr/bin:/bin' } },
      (err, stdout) => {
        const pass = err ? '' : stdout.replace(/\n$/, '');
        if (!pass) {
          reject(
            new Error(
              `No Keychain item for account "${account.id}" (service "${KEYCHAIN_SERVICE}"). ` +
                'See README, "Setup".',
            ),
          );
          return;
        }
        resolve(pass);
      },
    );
  });
}

/** Real path of the save root, or null when saving is off. */
export function saveRoot() {
  return state().saveRoot;
}
