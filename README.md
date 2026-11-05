# multi-mail-mcp

Read-only, multi-account MCP server for Proton Mail (via Proton Bridge) and Gmail (Gmail API with OAuth, or IMAP with app passwords).

```
mail__list_accounts    the mailboxes this session may read
mail__search           one account; Gmail takes Gmail search syntax in "query"
mail__list_messages    recent messages in a folder, headers only
mail__get_message      one message: headers, text body, attachment list
mail__get_thread       the whole conversation, oldest first
mail__list_folders     folders (Gmail: labels)
mail__get_attachments  base64, or saved into the session's save folder
```

No send, reply, draft, delete, move, flag, or mark-read. Mailboxes are opened read-only and
bodies fetched with `BODY.PEEK`; the Gmail API backend issues only read requests. Reading does not mark messages read.

## Design

- **Per-process scoping.** `MAIL_ACCOUNTS` (required; `*` for all) lists the account ids a process
  may open. Unset is a startup error.
- **Fixed hosts.** `proton` connects only to the local Bridge on `127.0.0.1`; `gmail` only to
  `imap.gmail.com:993` over TLS. The Gmail API backend uses fixed Google HTTPS endpoints.
- **No secrets in files.** Passwords come from the macOS Keychain (service `multi-mail-mcp`, account =
  account id). Gmail OAuth credentials use a separate service, `multi-mail-mcp.gmail-oauth`,
  with one item per account id. Access tokens are kept only in memory.
- **Opt-in attachment saving.** Only inside `MAIL_SAVE_ROOT` (symlinks resolved per level), documents
  and images only (no executables, archives, HTML or macro formats), 25 MB cap, sanitized names,
  never overwrites, attempts to mark files with the macOS quarantine flag and reports failures.
- **Defense in depth.** Mutating IMAP methods are disabled on every connection; a mailbox the server
  opens read-write is refused; inputs reject control characters; messages over 40 MB are not
  fetched; hidden Unicode (tag characters, bidi overrides, zero-width) is stripped from output and
  every result is labelled untrusted; the registry is refused if group/other-writable or if it
  carries a secret; `.npmrc` sets `ignore-scripts`.

## Setup

### 1. Registry — `~/.config/multi-mail-mcp/accounts.json` (no secrets)

```json
{
  "accounts": {
    "acme": { "type": "proton", "user": "ops@acme-holdings.example", "label": "Acme Holdings LLC" },
    "charity": {
      "type": "proton",
      "user": "admin@example-charity.org",
      "label": "Example Charity (non-profit)"
    },
    "personal": { "type": "gmail", "user": "you@gmail.example", "label": "Personal" },
    "widgets": {
      "type": "gmail",
      "user": "you@widgets-co.example",
      "label": "Widgets Co (Google Workspace)"
    }
  }
}
```

Override the path with `MAIL_MCP_CONFIG`. Proton entries take an optional `"port"` (default 1143).
Gmail entries accept `"backend": "gmail-api"` or `"backend": "imap"` (default). Existing entries
continue using IMAP until you explicitly opt in. Proton supports only the IMAP backend.

### 2. Proton: one Bridge, several accounts

Bridge handles several Proton accounts at once: Bridge > **Add account**. Each signed-in account
gets its **own Bridge-generated password** (Bridge > account > Mailbox details); all share
`127.0.0.1:1143`, and Bridge routes by IMAP username. Bridge requires a paid Proton plan on each
account.

### 3. Gmail: choose OAuth or an app password

For OAuth, follow [Gmail OAuth setup and migration](#gmail-oauth-setup-and-migration) below.
For the existing IMAP backend, create an app password:

Google Account > Security > 2-Step Verification (must be on) > **App passwords**. For a Workspace
account the admin must also allow it: Admin console > Apps > Google Workspace > Gmail > End User
Access > **POP and IMAP access** on, and 2-Step Verification allowed for the user.

### 4. Passwords into the Keychain

Run in your own terminal. `-w` as the last argument prompts, so the password never touches shell
history:

```sh
security add-generic-password -U -s multi-mail-mcp -a acme     -l "multi-mail-mcp acme"     -w
security add-generic-password -U -s multi-mail-mcp -a personal -l "multi-mail-mcp personal" -w
# ...one per account id in accounts.json
```

### 5. Check

```sh
MAIL_ACCOUNTS='*' node /path/to/multi-mail-mcp/index.js --check
```

### 6. Register per harness

Claude Code reads `.mcp.json` from the folder a session starts in. Put one in each folder that
should see mail: `examples/entity.mcp.json` scopes a session to one account and saves attachments
into that folder; `examples/all.mcp.json` opens every account with saving off. Each names the server `mail`, so tools are
`mcp__mail__*` everywhere and only the reachable accounts differ:

```json
{
  "mcpServers": {
    "mail": {
      "command": "/absolute/path/to/node",
      "args": ["/absolute/path/to/multi-mail-mcp/index.js"],
      "env": {
        "MAIL_ACCOUNTS": "acme",
        "MAIL_SAVE_ROOT": "/absolute/path/to/Acme Holdings LLC/00 Inbox"
      }
    }
  }
}
```

Use an absolute `node` path: harnesses do not load nvm.

## Gmail OAuth setup and migration

Use Node 18.17+ and macOS Keychain. No new runtime dependencies are required.
Never put the downloaded OAuth JSON, access tokens or refresh tokens in the registry, MCP config,
source control or a chat. The desktop client file is needed only for an explicit login; its
client credentials and refresh token are then stored together in Keychain. Login prints a Google
consent URL, never the returned code or tokens. Keep that temporary URL private too.

### Google Cloud setup

1. In Google Cloud, select your project and enable **Gmail API**.
2. In **Google Auth Platform**, configure Branding and **Audience: External**. While publishing
   status is **Testing**, add **each exact account address** under **Audience > Test users**.
3. Under Data Access, request only `https://www.googleapis.com/auth/gmail.readonly`.
4. Create a **Desktop app** OAuth client. For an agent retrieving mail context, select
   **Use this client for an AI-powered agent**. Download its `installed` JSON with a localhost
   redirect, and keep it outside the repo with `chmod 600 /absolute/path/to/client_secret.json`.

For the current private setup, the project is **Multi Mail MCP** (`multi-mail-mcp-513801`) and
client name is **Multi Mail MCP Desktop**. The API and desktop client are already configured.
If consent fails, confirm both `ryanhchang@gmail.com` and `ryan@waterandflower.com` are listed as
test users; their registration cannot be confirmed by the local login command. Workspace policy
can also block the client.

### Explicit login, one account at a time

Run from this checkout, substituting the actual client file path:

```sh
MAIL_ACCOUNTS=personal node index.js auth personal --client /absolute/path/to/client_secret.json
MAIL_ACCOUNTS=jaw node index.js auth jaw --client /absolute/path/to/client_secret.json
```

You can set `MAIL_GOOGLE_CLIENT_FILE` instead of `--client`. `--no-open` prints the consent URL
without launching a browser; open it manually on **this machine**, which must receive the loopback
callback within five minutes. Choose the account named in the command and approve read-only mail
access. Login uses authorization code + PKCE (S256), random state validation, a random-port
`127.0.0.1` callback and offline access. It checks the Gmail profile's address before saving
anything, exercises refresh, rechecks the address, and lists labels. A wrong account, declined
consent, broader grant, missing refresh token or failed check does not replace stored credentials.
If an old broader grant causes a scope error, revoke the app's grant and authorize again.

Login **does not switch backends**. It preserves app passwords in service `multi-mail-mcp`.
`MAIL_ACCOUNTS` restrictions apply equally to login, revoke, checks and every MCP tool.

### Trial, actual MCP verification and migration

First exercise the API with a process-local override. This does not edit the registry:

```sh
MAIL_ACCOUNTS=personal MAIL_GMAIL_API_ACCOUNTS=personal node index.js --check
MAIL_ACCOUNTS=jaw MAIL_GMAIL_API_ACCOUNTS=jaw node index.js --check
```

Use [examples/gmail-api.mcp.json](examples/gmail-api.mcp.json) to start an MCP process for both
accounts, or put one id in both variables for a single-account session. The override must be an
explicit comma-separated subset of allowed **Gmail** ids; it cannot widen `MAIL_ACCOUNTS`.
The optional live check calls the actual stdio MCP tools, reports only statuses, and never
prints email content or saves attachments:

```sh
MAIL_ACCOUNTS=personal,jaw MAIL_GMAIL_API_ACCOUNTS=personal,jaw node scripts/verify-gmail-mcp.js
```

It reports any skipped reads or attachment checks if no suitable small message exists.
For manual verification through the actual MCP tools:

1. Call `mail__list_accounts`; confirm the expected address and `backend: "gmail-api"` for each.
2. Call `mail__list_folders`, `mail__list_messages` in INBOX, then `mail__search` (e.g. query
   `newer_than:30d`) separately for each account.
3. Pass a returned **folder and uid unchanged** to `mail__get_message` and `mail__get_thread`.
4. If that message has an attachment, use its index with `mail__get_attachments` and `save: false`.
   Inline content is capped at 2 MB. Only enable saving for a session that needs it.
5. Verify that an account excluded from the process allowlist returns an unavailable-account error.

After both checks and MCP reads succeed, explicitly set `"backend": "gmail-api"` on the desired
Gmail entries in `~/.config/multi-mail-mcp/accounts.json`. See
[examples/accounts.oauth.json](examples/accounts.oauth.json). Restart the MCP processes so their
schemas and registry are reloaded. Neither login nor a successful check edits your registry.
To roll back, set `"backend": "imap"` (or remove the backend key), remove the process override,
and restart. Existing app-password Keychain entries are retained throughout. Proton Bridge
configuration and operation are unchanged.

### IDs, folders and search compatibility

The seven read-only tools and their parameter names remain available. IMAP `uid` values are
positive integers. Gmail API `uid` values are tagged strings such as `"gmail:18abcdef01234567"`;
the MCP schema accepts either. **Do not convert them to numbers, reuse an IMAP UID after switching
backends, or transfer IDs between accounts.** An ID of the wrong backend type is rejected before
credential access. Search/list again after switching. `message_id` remains the RFC Message-ID;
`thread_id` is the native backend thread identifier, not a tool input.

Gmail folders are exact label names from `mail__list_folders` (plus a virtual
`[Gmail]/All Mail` that excludes spam/trash). Labels returned on message summaries are API label
IDs, resolvable via `label_id` on folders. Search defaults to All Mail; explicitly select SPAM or
TRASH to include them. Multiple folders are searched as a union and duplicate messages are
collapsed. Counts are Gmail estimates, identified with `*_is_estimate: true`.

`query` is native Gmail search; structured from/to/subject/text filters use Gmail's search
semantics, which can differ from IMAP substring matching. Gmail has no body-only search operator:
`body` filters the decoded plain-text bodies of at most 200 candidates across paginated results
and reports `body_candidates_scanned` and `search_incomplete`. Narrow other filters when a scan is
incomplete. Date filters use the host's local midnight, sent as epoch timestamps to avoid Gmail's
PST interpretation of bare dates. Lists/search return headers only, except when body filtering
requires reading candidates. Native threads return the newest 25 messages, sorted oldest first.

Bodies and attachments use Gmail's raw MIME read endpoint and the existing MIME parser, preserving
attachment indexes, filename sanitization, save-type restrictions, quarantine reporting,
non-overwrite behavior and save-root containment. Messages over 40 MB are refused, response streams
are capped even if size estimates understate the actual data, and serialized MCP results are
capped at 3 MB. API operations have a two-minute deadline and at most two active API reads per
process. Each API operation also has a cumulative 128 MiB response budget and a 500-request cap
(including retries); exceeding either fails with an instruction to narrow the request. These
limits bound network work, not CPU time in the MIME parser. Gmail requests follow no redirects
and only whitelisted GET resources are available. The shared HTTP layer separately enforces
Google origins, account paths and request methods before sending any credentials.
All mail output retains Unicode scrubbing and the untrusted-content label.

### Expiration, revocation and Google requirements

Normal MCP startup never opens a browser. Access tokens refresh automatically in memory, with
profile identity checks after refresh. A missing/inaccessible Keychain item, expired/revoked
refresh token or account mismatch returns a login instruction. Network/rate errors can be retried;
permission errors require checking API enablement, scope and Workspace policy.

For an External app in **Testing** with Gmail scope, Google refresh tokens expire after **seven
days**; rerun `auth` for each account as needed. Moving publishing status to **In production** is
a separate decision from Google verification, does not itself verify the app, and should be
followed by reauthorization to replace testing-issued tokens. Tokens can still be revoked or
expire for other reasons. See Google's [token expiration rules](https://developers.google.com/identity/protocols/oauth2#expiration).

`gmail.readonly` is a **restricted scope**. Public distribution can require OAuth verification
and a security assessment, depending on how restricted data is used, stored or transmitted.
Running an MCP locally does not automatically exempt it: returned email can flow to a cloud
agent. Consult [Gmail scopes](https://developers.google.com/workspace/gmail/api/auth/scopes) and
[restricted-scope verification](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification)
for your distribution and data flow. The [agentic OAuth designation](https://support.google.com/cloud/answer/15549257)
applies to context-retrieving agents, including custom MCPs, grants no additional scopes, and
does not waive consent, verification or other standard requirements. This project does not
publish the app or submit verification.

To revoke one account's Google grant and remove its OAuth Keychain item:

```sh
MAIL_ACCOUNTS=personal node index.js revoke personal
MAIL_ACCOUNTS=jaw node index.js revoke jaw
```

Revocation is an explicit CLI operation, never an MCP tool. Google may revoke the app's entire
grant for that user, including other tokens for the same project. Stop/restart all MCP processes
after revocation to clear cached access tokens. It does not delete the IMAP app-password item.
If revocation fails (for example because the token has already expired), remove access under
[Google Account connections](https://myaccount.google.com/connections) for each account, then delete
only the corresponding local OAuth item:

```sh
security delete-generic-password -s multi-mail-mcp.gmail-oauth -a personal
security delete-generic-password -s multi-mail-mcp.gmail-oauth -a jaw
```

Deleting a local item alone does not revoke Google's grant. To remove old app passwords after a
completed migration, explicitly revoke them in Google Account > Security > App passwords and
delete service `multi-mail-mcp` items separately; no OAuth command changes those items.

The desktop flow follows Google's [installed-app OAuth guidance](https://developers.google.com/identity/protocols/oauth2/native-app).

## License

MIT. See `LICENSE`.

## Security checks

Run `npm ci` to install dependencies, then `npm run lint` for recommended Biome lint rules,
`npm run format` to apply formatting, and `npm run check` to check lint, formatting, and
import organization. CI runs `npm run check` and `npm test` on pushes to `main` and pull requests.

Run `npm test` for offline regression tests. They use temporary registries and a local MCP
process; no mailbox connections or Keychain password lookups are needed.

Attachment saving filters by filename extension, not file contents. Legacy `.doc`, `.xls`
and `.ppt` files are refused because they can carry macros. An allowed extension does not
prove that a file is safe. Each saved-file result reports `quarantined`; a failed macOS
quarantine marking is returned with a warning.

Save-folder checks reject existing symlink escapes. They do not provide protection against
another local process concurrently replacing directory components during a save.

The server allows at most two concurrent mailbox operations per process. Extra calls return
"busy" instead of queuing. IMAP responses have explicit literal, line, response-byte and token
limits; message source fetches request at most 40 MB plus one byte and reject oversized results.
MCP result payloads are limited to 3 MB. Mailbox reads retain their two-minute operation deadline,
and logout cleanup is limited to five seconds. These are resource bounds, not a sandbox for MIME
parsing or a guarantee against parser bugs.

An account allowlist applies only to this server process. It is not isolation from an assistant
that also has shell access as your macOS user, can modify launch configuration, or can read other
mail connectors. Start separate processes with explicit account ids for narrower access. A `*`
scope includes future accounts added to the registry too. Attachment saving should be enabled
only for sessions that need it. Saves refused by configuration fail before any message download.

The untrusted-content label and Unicode scrubbing reduce ambiguity; they cannot guarantee that
an assistant ignores malicious instructions in readable email. Reading mail through this server
also sends the returned content to the assistant provider. Keep approval controls on any other
tools that can send, publish, upload, or execute actions.

The connection guard also rejects writable `mailboxOpen` calls and disables `mailboxClose`
(IMAP CLOSE can expunge deleted messages). Mailbox access still verifies the server's read-only
confirmation after EXAMINE. These guards protect the supported operations and accidental future
calls to those methods; they do not sandbox arbitrary JavaScript running in the same process.
