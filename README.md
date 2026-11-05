# multi-mail-mcp

Read-only, multi-account MCP server for Proton Mail (via Proton Bridge) and Gmail (IMAP).

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
bodies fetched with `BODY.PEEK`, so reading leaves no trace.

## Design

- **Per-process scoping.** `MAIL_ACCOUNTS` (required; `*` for all) lists the account ids a process
  may open. Unset is a startup error.
- **Fixed hosts.** `proton` connects only to the local Bridge on `127.0.0.1`; `gmail` only to
  `imap.gmail.com:993` over TLS.
- **No secrets in files.** Passwords come from the macOS Keychain (service `multi-mail-mcp`, account =
  account id).
- **Opt-in attachment saving.** Only inside `MAIL_SAVE_ROOT` (symlinks resolved per level), documents
  and images only (no executables, archives, HTML or macro formats), 25 MB cap, sanitized names,
  never overwrites, files marked with the macOS quarantine flag.
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
    "acme":     { "type": "proton", "user": "ops@acme-holdings.example",  "label": "Acme Holdings LLC" },
    "charity":  { "type": "proton", "user": "admin@example-charity.org",  "label": "Example Charity (non-profit)" },
    "personal": { "type": "gmail",  "user": "you@gmail.example",          "label": "Personal" },
    "widgets":  { "type": "gmail",  "user": "you@widgets-co.example",     "label": "Widgets Co (Google Workspace)" }
  }
}
```

Override the path with `MAIL_MCP_CONFIG`. Proton entries take an optional `"port"` (default 1143).

### 2. Proton: one Bridge, several accounts

Bridge handles several Proton accounts at once: Bridge > **Add account**. Each signed-in account
gets its **own Bridge-generated password** (Bridge > account > Mailbox details); all share
`127.0.0.1:1143`, and Bridge routes by IMAP username. Bridge requires a paid Proton plan on each
account.

### 3. Gmail: app password

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

## License

MIT. See `LICENSE`.
