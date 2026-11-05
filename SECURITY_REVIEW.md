# Gmail OAuth/API security review

Reviewed 2026-11-04 on the PR branch, including the OAuth CLI, Keychain subprocesses,
Google HTTP client, backend dispatch, MCP schemas, MIME/attachment handling and account scope.

## Findings and changes

- **Medium: cumulative resource amplification.** Per-response limits permitted a multi-folder
  search, body scan or thread read to download many individually permitted responses. Each
  Gmail tool operation now shares a 128 MiB response budget and a 500-request budget, including
  retries. Exceeding either fails; streamed bodies are cancelled before excess data is parsed.
- **Low: oversized Keychain command could truncate an update.** A credential larger than the
  interactive command buffer could replace a working item with incomplete data. Inputs are
  now bounded before spawning `security`; secrets still travel over stdin rather than argv.
  The bound follows [Apple's interactive command parser](https://github.com/apple-oss-distributions/SecurityTool/blob/main/security.c).
- **Defense in depth: credential destination enforcement.** The shared HTTP layer now validates
  Google HTTPS origins, exact token/revocation endpoints, `users/me` read resources and HTTP
  methods before fetching. This supplements the API client's existing path guard and redirect
  refusal; an unexpected future caller cannot send credentials to an arbitrary endpoint.
- **Defense in depth: callback validation and response headers.** Unexpected or duplicate OAuth
  issuers are rejected when supplied. Callback responses set `Referrer-Policy: no-referrer`
  and `X-Content-Type-Options: nosniff`, alongside existing no-store and CSP headers.

## Verification

- Formatting/lint and all 41 tests passed, including new request/destination limits,
  streaming cancellation, oversized Keychain input and callback issuer regression cases.
- `npm audit --json` reported zero known dependency vulnerabilities, including dev dependencies.
- Tracked-file scanning found no common Google client-secret/access-token/refresh-token patterns.
- Both authorized accounts passed live stdio MCP reads: folders, list, search, message,
  native thread, one small attachment, and the denied-account probe. No registry or app-password
  changes were made, and no new browser consent was required.

## Boundaries retained

`MAIL_ACCOUNTS` is a server-process allowlist, not isolation from other processes running as
the same macOS user. Returned email is untrusted input and can reach a cloud agent; labels
and Unicode scrubbing cannot enforce an agent's behavior. Attachment saving filters extensions,
not file contents, and does not protect against concurrent local directory replacement. MIME
parsing runs in the server process; network and output bounds do not provide a CPU/memory
sandbox for parser defects. These limitations also apply to the existing IMAP backend.
