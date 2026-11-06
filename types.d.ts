/**
 * Shared shapes for the mail backends. Types only: nothing here exists at runtime.
 *
 * The IMAP backend (mail.js) and the Gmail API backend (gmail.js) must accept the same tool
 * inputs and return these shapes, so an account reads the same whichever backend serves it.
 * backend.js checks both modules against `MailOps`; a field one backend drops or renames is a
 * type error there rather than a surprise for the agent reading the result.
 */

export type AccountType = 'proton' | 'gmail';
export type BackendName = 'imap' | 'gmail-api';

/** Numeric IMAP UID, or an opaque `gmail:<hex>` Gmail API message id. Never interchangeable. */
export type Uid = number | `gmail:${string}`;

/** A frozen registry entry (config.js). Connection fields are used by the IMAP backend only. */
export interface Account {
  readonly id: string;
  readonly type: AccountType;
  readonly backend: BackendName;
  readonly user: string;
  readonly label: string;
  readonly host: string;
  readonly port: number;
  readonly secure: boolean;
  readonly doSTARTTLS?: boolean;
  readonly tls?: Readonly<Record<string, unknown>>;
}

export interface Folder {
  path: string;
  special_use?: string;
  /** Gmail API only: the native label id behind `path`. */
  label_id?: string;
}

/** Headers-only message, as returned by list and search. */
export interface MessageSummary {
  folder: string;
  uid: Uid;
  date: string | null;
  from: string;
  to: string;
  cc?: string;
  subject: string;
  unread?: boolean;
  /** Gmail only: `\Inbox`-style system names and user label names. */
  labels?: string[];
  thread_id?: string;
  message_id: string | null;
  /** Search only: other folders holding the same message. */
  also_in?: string[];
}

export interface AttachmentInfo {
  index: number;
  filename: string;
  content_type: string;
  size: number;
}

export interface FullMessage {
  folder: string;
  uid: Uid;
  date: string | null;
  from: string;
  to: string;
  cc?: string;
  subject: string;
  message_id: string | null;
  in_reply_to: string | null;
  attachments: AttachmentInfo[];
  body: string;
  truncated: boolean;
  /** Gmail API only. */
  thread_id?: string;
}

export interface ListResult {
  folder: string;
  total_matching: number;
  /** Gmail API: counts are Google's estimates. */
  total_matching_is_estimate?: boolean;
  more_available?: boolean;
  messages: MessageSummary[];
}

export interface SearchCriteria {
  query?: string;
  text?: string;
  from?: string;
  to?: string;
  subject?: string;
  body?: string;
  since?: string;
  before?: string;
  unread?: boolean;
  folders?: string[];
}

export interface SearchResult {
  searched_folders: number;
  matched_before_limit: number;
  matched_before_limit_is_estimate?: boolean;
  returned: number;
  messages: MessageSummary[];
  skipped?: { folder: string; reason: string }[];
  /** Gmail API body-only search: how much of the candidate set was read. */
  body_candidates_scanned?: number;
  search_incomplete?: boolean;
  note?: string;
}

export interface ThreadResult {
  count: number;
  note?: string;
  messages: FullMessage[];
}

export interface SavedAttachment extends AttachmentInfo {
  path: string;
  quarantined: boolean;
  warning?: string;
}

export type AttachmentResult =
  | { attachments: (AttachmentInfo & { content_base64: string })[] }
  | { saved: SavedAttachment[]; refused?: { index: number; filename: string; reason: string }[] };

export interface ListOptions {
  folder?: string;
  limit?: number;
  unreadOnly?: boolean;
}

export interface MessageRef {
  folder: string;
  uid: Uid;
}

export interface AttachmentOptions extends MessageRef {
  indexes?: number[];
  save?: boolean;
  subdir?: string;
}

/**
 * The operations every backend implements. `C` is what the backend works against:
 * the Account for IMAP, a per-operation Gmail API client for the Gmail API.
 */
export interface MailOps<C> {
  listFolders(c: C): Promise<Folder[]>;
  listMessages(c: C, options: ListOptions): Promise<ListResult>;
  search(c: C, criteria: SearchCriteria, limit?: number): Promise<SearchResult>;
  getMessage(c: C, options: MessageRef & { maxChars?: number }): Promise<FullMessage>;
  getThread(c: C, options: MessageRef & { maxChars?: number }): Promise<ThreadResult>;
  getAttachments(c: C, options: AttachmentOptions): Promise<AttachmentResult>;
}

/** The per-operation Gmail API client from gmail.js `createGmailClient`. */
export interface GmailApi {
  // biome-ignore lint/suspicious/noExplicitAny: Raw Google JSON; each caller validates the fields it reads.
  get(resource: string, params?: Record<string, unknown>, maxBytes?: number): Promise<any>;
}
