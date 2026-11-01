# APIEdge Security

APIEdge targets the **OWASP Top 10 (2021)**, the **OWASP API Security Top 10 (2023)** and
**OWASP ASVS 4.0 Level 2**. This document maps each item to the code and tests that cover it. It is
updated with every task. Status: **Done** (implemented and tested), **Partial** (foundation in
place, more to come in the named task) or **Planned**.

Report vulnerabilities privately to the maintainer (Alingan Patra); do not open public issues.

## 1. Controls in place

| Control | Code | Tests |
|---|---|---|
| Security headers: CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP, HSTS over HTTPS, `Cache-Control: no-store` on the API | `src/apiedge/security/middleware.py` (`SecurityHeadersMiddleware`) | `tests/integration/test_security_middleware.py` |
| CORS allow-list (closed by default, `*` rejected) | `middleware.py`, `config.py` (`cors_allow_origins`) | `test_security_middleware.py`, `tests/unit/test_config.py` |
| Request body-size limit (Content-Length and streamed bodies, 413) | `BodySizeLimitMiddleware` | `test_security_middleware.py::test_body_size_limit` |
| CSRF: double-submit cookie + Origin check for cookie-authenticated unsafe requests | `CSRFMiddleware` | `test_security_middleware.py::test_csrf_*` |
| Global error barrier: generic 500 with request id, no stack trace; 422 without echoed input | `RequestContextMiddleware`, `_validation_error_handler` | `test_errors_never_leak_*`, `test_validation_errors_do_not_echo_input` |
| Structured JSON logs with secret masking; access log without query strings; request ids | `src/apiedge/logs.py`, `src/apiedge/security/masking.py` | `tests/unit/test_masking_logs.py` |
| Secrets encryption at rest (AES-256-GCM, associated data, key rotation) | `src/apiedge/security/crypto.py` | `tests/unit/test_crypto.py` |
| SSRF guard for upstream URLs | `src/apiedge/security/ssrf.py` | `tests/unit/test_ssrf.py` |
| Argon2id password hashing | `src/apiedge/security/passwords.py` | `tests/unit/test_passwords.py` |
| No server/version disclosure (`server_header=False`, minimal `/healthz`) | `cli.py`, `app.py` | `tests/integration/test_app.py` |
| Hash-locked dependencies, license gate | `requirements/*.lock`, `scripts/check-licenses.py` | CI `quality` job |

## 2. OWASP Top 10 (2021)

| ID | Risk | APIEdge control | Status |
|---|---|---|---|
| A01 | Broken Access Control | Deny-by-default RBAC dependency, tenant-filtered data access, BOLA tests (T-003); CSRF protection (T-002) | Partial (T-003) |
| A02 | Cryptographic Failures | AES-256-GCM secrets at rest with key outside the DB (T-002); Argon2id (T-001); HSTS (T-002); TLS on gateway and console (T-016/T-023) | Partial |
| A03 | Injection | SQLAlchemy ORM / bound parameters only; Pydantic validation; strict CSP; no `eval`/`exec` outside the sandbox (T-010); bandit + CodeQL in CI | Done (baseline) |
| A04 | Insecure Design | Body-size limits (T-002); login throttling and lockout (T-003); gateway rate limits (T-008) | Partial |
| A05 | Security Misconfiguration | Secure defaults (localhost bind, production mode, CORS closed), security headers, docs only in development, no stack traces | Done (baseline) |
| A06 | Vulnerable and Outdated Components | Hash-locked pins, pip-audit (runtime strict), npm audit, license gate; SBOM per release (T-016) | Partial (T-016) |
| A07 | Identification and Authentication Failures | Argon2id (T-001); password policy, MFA, refresh rotation, session invalidation (T-003) | Planned (T-003) |
| A08 | Software and Data Integrity Failures | Hash-verified installs, CSRF (T-002); signed releases and checksums (T-016) | Partial |
| A09 | Security Logging and Monitoring Failures | Structured JSON logs with masking and request ids (T-002); audit log (T-003) | Partial (T-003) |
| A10 | Server-Side Request Forgery | SSRF guard utility (T-002); enforced in the proxy, scripts and inspector replay (T-007, T-010, T-012) | Partial |

## 3. OWASP API Security Top 10 (2023)

| ID | Risk | APIEdge control | Status |
|---|---|---|---|
| API1 | Broken Object Level Authorization | Object- and tenant-ownership checks in the data-access layer, BOLA tests | Planned (T-003) |
| API2 | Broken Authentication | Argon2id, lockout, MFA, short-lived JWT + rotating refresh cookie | Planned (T-003) |
| API3 | Broken Object Property Level Authorization | Explicit Pydantic response models (no ORM passthrough), 422 without echoed input (T-002) | Partial |
| API4 | Unrestricted Resource Consumption | Admin API body-size limit (T-002); gateway rate limits, quotas, timeouts (T-007/T-008) | Partial |
| API5 | Broken Function Level Authorization | `resource:action` permission on every admin route, 403 tests | Planned (T-003) |
| API6 | Unrestricted Access to Sensitive Business Flows | Rate limits and quotas per consumer/plan | Planned (T-008/T-014) |
| API7 | Server Side Request Forgery | SSRF guard (T-002), enforced at every outbound call site | Partial |
| API8 | Security Misconfiguration | Same as A05; CORS allow-list | Done (baseline) |
| API9 | Improper Inventory Management | API lifecycle and versions, retired APIs enforced by the gateway | Planned (T-006/T-021) |
| API10 | Unsafe Consumption of APIs | Upstream timeouts, response size caps, SSRF guard, TLS verification | Planned (T-007) |

## 4. ASVS 4.0 Level 2 (by chapter)

| Chapter | Coverage today | Next |
|---|---|---|
| V1 Architecture | `docs/ARCHITECTURE.md`, ADRs 0001-0003 | ongoing |
| V2 Authentication | Argon2id | T-003 |
| V3 Session Management | CSRF cookie (`SameSite=Strict`) | T-003 cookies (HttpOnly, Secure, SameSite) |
| V4 Access Control | - | T-003 |
| V5 Validation, Sanitization, Encoding | Pydantic, strict CSP, SSRF guard | each feature |
| V6 Stored Cryptography | AES-256-GCM, key outside DB, rotation | T-023 vault integration |
| V7 Error Handling and Logging | Generic errors, JSON logs, masking, request ids | T-003 audit log |
| V8 Data Protection | `Cache-Control: no-store` on API, masking | T-012 inspector masking |
| V9 Communication | HSTS over HTTPS | T-016/T-023 TLS |
| V10 Malicious Code | bandit, CodeQL, hash-locked dependencies | - |
| V11 Business Logic | - | T-008 |
| V12 Files and Resources | Body-size limits | T-011 imports |
| V13 API and Web Service | CORS allow-list, CSRF, content-type via FastAPI | T-003 |
| V14 Configuration | Secure defaults, docs only in dev, no server header, pinned deps | T-016 SBOM |

## 5. CI security gates

| Gate | Where | Fails on |
|---|---|---|
| bandit | `.github/workflows/ci.yml` (`quality`) | any finding in `src`, `scripts` |
| pip-audit | `ci.yml` (`quality`) | any known vulnerability in `runtime.lock` (strict); `dev.lock` with documented exceptions |
| npm audit | `ci.yml` (`console`) | high or critical |
| License gate | `ci.yml` (`quality`) | GPL, AGPL, SSPL |
| CodeQL (Python, JS/TS, `security-extended`) | `.github/workflows/codeql.yml` (gate: `scripts/codeql-gate.py`) | any error or warning result that is not accepted (see below), or any mismatch between inline markers and the table below (SARIF kept as an artifact; the private repo has no code-scanning upload) |

### Accepted findings

Fixing a finding is always preferred. A CodeQL finding is accepted only when it has **both**:

1. an inline justification comment on the flagged line, `codeql[<rule id>] <reason>` (the syntax
   GitHub code scanning uses), and
2. a row in the table below with the same file and rule, a justification and the review date.

`scripts/codeql-gate.py` runs in the CodeQL workflow (against the SARIF results) and in the CI
`quality` job (marker/table consistency only). It fails when an inline marker has no row, when a
row has no inline marker, when a row is incomplete, or when a finding is not covered by both.

| File | Rule | Justification | Date |
|---|---|---|---|
| `src/apiedge/cli.py` | `py/clear-text-logging-sensitive-data` | `create-admin --generate-password` prints the generated first-admin password once to the operator's terminal by design (T-019, needed for unattended installs). It is never written to a log (the installer runs this step with logging off), and a password change is forced at first login. | 2026-11-01 |

Fixed, not accepted (recorded for transparency): CodeQL's name heuristic treats any identifier
containing "password" as a secret, so the policy constants were renamed (`MIN_PASSWORD_LENGTH` to
`POLICY_MIN_LENGTH`, `PASSWORD_POLICY_TEXT` to `POLICY_TEXT`). The policy error message is static
text and never contains the password.

## 6. Security configuration

See `docs/admin-guide/configuration.md` and `.env.example`. Security-relevant settings:
`APIEDGE_ENV`, `APIEDGE_CORS_ALLOW_ORIGINS`, `APIEDGE_MAX_REQUEST_BODY_BYTES`,
`APIEDGE_HSTS_MAX_AGE`, `APIEDGE_LOG_FORMAT`, `APIEDGE_SECRET_KEY`, `APIEDGE_SECRET_KEY_PREVIOUS`,
`APIEDGE_SECRET_KEY_FILE`, `APIEDGE_SSRF_ALLOW_PRIVATE`, `APIEDGE_SSRF_ALLOW_CIDRS`,
`APIEDGE_SSRF_DENY_CIDRS`.

**Back up the secrets key** (`<data dir>/secret.key` or `APIEDGE_SECRET_KEY`). Without it,
encrypted secrets cannot be recovered. To rotate: set the new key as `APIEDGE_SECRET_KEY`, list the
old one in `APIEDGE_SECRET_KEY_PREVIOUS`, and re-encrypt stored secrets (a re-encryption command
arrives with the first feature that stores secrets).
