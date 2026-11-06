/** @import { Account, GmailApi, MailOps } from './types.js' */
import { saveRoot } from './config.js';
import * as gmail from './gmail.js';
import * as imap from './mail.js';

// The cross-backend contract: both modules must implement every operation with the shared
// result shapes. If either drifts (a missing field, a renamed one), typecheck fails here.
/** @type {MailOps<Account>} */
const imapOps = imap;
/** @type {MailOps<GmailApi>} */
const gmailOps = gmail;

/**
 * @param {Function} imapOp
 * @param {Function} gmailOp
 * @param {Account} account
 * @param {...any} args
 */
function dispatch(imapOp, gmailOp, account, ...args) {
  if (args[0]?.save && !saveRoot()) {
    throw new Error('Saving is off for this harness (MAIL_SAVE_ROOT is not set)');
  }
  const uid = args[0]?.uid;
  if (account.backend === 'gmail-api') {
    if (uid !== undefined) gmail.messageId(uid); // Validate before accessing any credentials.
    return gmail.withGmail(account, (api) => gmailOp(api, ...args));
  }
  if (uid !== undefined && (!Number.isInteger(uid) || uid < 1 || uid > 2 ** 32 - 1)) {
    throw new Error(
      'IMAP requires a numeric uid from a new search/list; Gmail API IDs cannot be used with IMAP',
    );
  }
  return imapOp(account, ...args);
}

/** @type {MailOps<Account>['listFolders']} */
export const listFolders = (a) => dispatch(imapOps.listFolders, gmailOps.listFolders, a);
/** @type {MailOps<Account>['listMessages']} */
export const listMessages = (a, options) =>
  dispatch(imapOps.listMessages, gmailOps.listMessages, a, options);
/** @type {MailOps<Account>['search']} */
export const search = (a, criteria, limit) =>
  dispatch(imapOps.search, gmailOps.search, a, criteria, limit);
/** @type {MailOps<Account>['getMessage']} */
export const getMessage = (a, options) =>
  dispatch(imapOps.getMessage, gmailOps.getMessage, a, options);
/** @type {MailOps<Account>['getThread']} */
export const getThread = (a, options) =>
  dispatch(imapOps.getThread, gmailOps.getThread, a, options);
/** @type {MailOps<Account>['getAttachments']} */
export const getAttachments = (a, options) =>
  dispatch(imapOps.getAttachments, gmailOps.getAttachments, a, options);
