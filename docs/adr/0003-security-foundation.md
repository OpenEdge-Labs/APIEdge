# ADR 0003: Security foundation: HTTP hardening, secrets encryption, SSRF guard

Date: 2026-11-01 · Status: Accepted · Task: T-002

## Context
T-002 asks for the OWASP baseline every later feature builds on: security headers and CSP, a CORS
allow-list, body-size limits, CSRF protection for cookie auth, a global error handler, structured
JSON logging with secret masking, a secrets-encryption helper and an SSRF guard for upstream URLs.

## Decision
* **Pure ASGI middleware** (`apiedge.security.middleware`), not `BaseHTTPMiddleware`, so streaming
  responses work and the order is explicit. Outermost first: security headers, request context
  (request id, access log, error barrier), CORS, body-size limit, CSRF. The error barrier sits
  inside the header middleware so even 500 responses carry the security headers.
* **CSP** for the console is strict (`script-src 'self'`, no `unsafe-inline`, `frame-ancestors
  'none'`). Only the development-only Swagger page (`/api/docs`) gets a relaxed policy.
* **CSRF** uses the double-submit cookie (`apiedge_csrf`, `SameSite=Strict`) plus an `Origin`
  check, enforced only for unsafe requests that carry an auth cookie (`apiedge_session`,
  `apiedge_refresh`, introduced by T-003). Bearer-token API clients are unaffected.
* **CORS** is closed by default; `APIEDGE_CORS_ALLOW_ORIGINS` lists exact origins (`*` rejected).
* **Validation errors** (422) never echo submitted values, so passwords cannot leak back.
* **Logging**: stdlib `logging` with our JSON formatter (no new dependency). Messages, extras and
  exception text pass through `apiedge.security.masking`, which the packet inspector will reuse.
  Our access log omits query strings; uvicorn's access log is silenced.
* **Secrets at rest**: AES-256-GCM via `pycryptodome` (BSD-2-Clause/Unlicense/MIT), token format
  `v1.<key id>.<b64url(nonce|ct|tag)>`, optional associated data to bind a token to its tenant,
  row and field, and key rotation through `APIEDGE_SECRET_KEY_PREVIOUS`. The master key comes from
  `APIEDGE_SECRET_KEY` or `<data dir>/secret.key`, created by `apiedge init` with mode 0600.
  We chose AES-GCM over Fernet for associated-data support. We chose `pycryptodome` over
  `cryptography`: `cryptography` 49 and later have no macOS x86_64 wheel, and 48.0.1 (the last
  release with one) has three advisories (PYSEC-2026-3552/3553/3554), which the strict runtime
  pip-audit gate rejects. `pycryptodome` 4.1.0 has abi3 wheels for all 15 targets and no
  dependencies. X.509/mTLS work (T-023) will revisit `cryptography`.
* **SSRF guard** (`apiedge.security.ssrf`): scheme, credential and port checks, rejection of
  non-canonical numeric hosts, and checks of *every* resolved address against private, loopback,
  link-local, CGNAT, NAT64/6to4 and cloud-metadata ranges. `allow_private` is the on-prem switch;
  metadata stays blocked unless explicitly allow-listed. Callers receive the vetted addresses and
  must connect to them (DNS-rebinding defence); T-007 wires this into the proxy.
* **CodeQL** runs in CI with `upload: never` (the repository is private without code-scanning
  upload) and a SARIF gate step that fails on any error or warning finding.

## Consequences
* One new runtime dependency (`pycryptodome`); its wheels exist for all 15 install targets.
* Losing the master key makes stored secrets unrecoverable: the key file must be backed up.
* If the console is served from a different origin than the API, that origin must be added to
  `APIEDGE_CORS_ALLOW_ORIGINS` (it is then also trusted by the CSRF origin check).
* Windows ignores POSIX file modes; the key file relies on the per-user data directory ACLs there.
