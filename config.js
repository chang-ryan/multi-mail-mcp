/**
 * Account registry, allowlist, and credential lookup.
 *
 * accounts.json (no secrets) lists every mailbox this machine knows about.
 * MAIL_ACCOUNTS (env, set per harness) says which of them this process may open.
 * Passwords live in the macOS Keychain, never in a file this code reads.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import { execFile } from 'child_process';

export const KEYCHAIN_SERVICE = 'multi-mail-mcp';

const CONFIG_PATH = process.env.MAIL_MCP_CONFIG
  || path.join(os.homedir(), '.config', 'multi-mail-mcp', 'accounts.json');

/**
 * Hosts are fixed per backend type. accounts.json cannot point a password at an arbitrary
 * server: Proton goes to the loopback Bridge, Gmail goes to Google over TLS.
 */
const BACKENDS = {
  proton: (a) => ({
    host: '127.0.0.1',
    port: Number(a.port || 1143),
    secure: false,
    // Bridge on loopback, cleartext. Bridge offers
    // STARTTLS with a self-signed cert; upgrading would mean disabling verification, which is
    // no safer than staying on the loopback interface.
    doSTARTTLS: false,
  }),
  gmail: () => ({ host: 'imap.gmail.com', port: 993, secure: true }),
};

const ID_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/;

function loadRegistry() {
  if (!fs.existsSync(CONFIG_PATH)) {
    throw new Error(`No account registry at ${CONFIG_PATH}. See README, "Setup".`);
  }
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));
  } catch (err) {
    throw new Error(`${CONFIG_PATH} is not valid JSON: ${err.message}`);
  }
  const accounts = {};
  for (const [id, a] of Object.entries(raw.accounts || {})) {
    if (!ID_RE.test(id)) throw new Error(`Bad account id "${id}" in ${CONFIG_PATH}`);
    if (!BACKENDS[a.type]) throw new Error(`Account "${id}": type must be "proton" or "gmail"`);
    if (!a.user) throw new Error(`Account "${id}": missing "user"`);
    if ('password' in a || 'pass' in a) {
      throw new Error(`Account "${id}": passwords do not belong in ${CONFIG_PATH}; use the Keychain`);
    }
    accounts[id] = { id, type: a.type, user: a.user, label: a.label || id, ...BACKENDS[a.type](a) };
  }
  return accounts;
}

/**
 * MAIL_ACCOUNTS is required. "*" opens everything; otherwise a comma list of ids.
 * An unset variable is an error rather than "all", so forgetting it in a harness config
 * fails closed.
 */
function loadAllowlist(registry) {
  const spec = (process.env.MAIL_ACCOUNTS || '').trim();
  if (!spec) {
    throw new Error('MAIL_ACCOUNTS is not set. Set it to a comma list of account ids, or "*" for all.');
  }
  if (spec === '*') return Object.keys(registry);
  const ids = spec.split(',').map((s) => s.trim()).filter(Boolean);
  const unknown = ids.filter((id) => !registry[id]);
  if (unknown.length) throw new Error(`MAIL_ACCOUNTS names unknown account(s): ${unknown.join(', ')}`);
  return ids;
}

let _state = null;
function state() {
  if (!_state) {
    const registry = loadRegistry();
    _state = { registry, allowed: loadAllowlist(registry) };
  }
  return _state;
}

/** The accounts this process may open, without credentials. */
export function allowedAccounts() {
  const { registry, allowed } = state();
  return allowed.map((id) => {
    const { label, type, user } = registry[id];
    return { id, label, type, address: user };
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
    throw new Error(`Account "${id}" is not available here. Allowed: ${allowed.join(', ')}`);
  }
  return registry[id];
}

/** Read the password for an account from the login Keychain. Never logged. */
export function getPassword(account) {
  return new Promise((resolve, reject) => {
    execFile(
      '/usr/bin/security',
      ['find-generic-password', '-s', KEYCHAIN_SERVICE, '-a', account.id, '-w'],
      { timeout: 10000 },
      (err, stdout) => {
        if (err) {
          reject(new Error(
            `No Keychain item for account "${account.id}" (service "${KEYCHAIN_SERVICE}"). ` +
            'See README, "Setup".',
          ));
          return;
        }
        resolve(stdout.replace(/\n$/, ''));
      },
    );
  });
}

/**
 * Where saved attachments may go. MAIL_SAVE_ROOT unset means saving is off.
 */
export function saveRoot() {
  const root = (process.env.MAIL_SAVE_ROOT || '').trim();
  return root ? path.resolve(root) : null;
}
