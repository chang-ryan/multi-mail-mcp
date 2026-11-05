import { saveRoot } from './config.js';
import * as gmail from './gmail.js';
import * as imap from './mail.js';

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

export const listFolders = (a) => dispatch(imap.listFolders, gmail.listFolders, a);
export const listMessages = (a, options) =>
  dispatch(imap.listMessages, gmail.listMessages, a, options);
export const search = (a, criteria, limit) =>
  dispatch(imap.search, gmail.search, a, criteria, limit);
export const getMessage = (a, options) => dispatch(imap.getMessage, gmail.getMessage, a, options);
export const getThread = (a, options) => dispatch(imap.getThread, gmail.getThread, a, options);
export const getAttachments = (a, options) =>
  dispatch(imap.getAttachments, gmail.getAttachments, a, options);
