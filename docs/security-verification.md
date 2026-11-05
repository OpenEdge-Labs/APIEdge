<!-- Copyright 2026 OpenEdge Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Security verification report (pre-release)

Task T-018, 2026-11-02, against commit `9973147` plus the T-018 changes. This report records how
APIEdge was checked against the **OWASP Top 10 (2021)**, the **OWASP API Security Top 10 (2023)**
and **OWASP ASVS 4.0 Level 2**, what was found and what was done about it. The per-control mapping
to code and tests stays in [Security](SECURITY.md); this report is the release-time snapshot.

Scope: the admin API and console (`apiedge run`, port 8080), the gateway data plane (port 8081),
the container image (both variants), the Python and npm dependency sets and the CI/release
pipeline. Out of scope, because the features do not exist yet: the low-code script sandbox
(T-010), the flow builder (T-009), OIDC SSO, native TLS listeners (T-023) and clustering (T-026).

## 1. Summary

| Severity | Found | Fixed | Open (tracked) |
|---|---|---|---|
| Critical | 0 | - | - |
| High (dependency, base image) | 1 group (18 CVEs) | 0 (no fix exists) | 1 (F-09, accepted with review date) |
| Medium | 1 | 1 (F-02, T-023) | 0 |
| Low | 5 | 2 (F-01, F-10) | 3 (F-03 VP-009; F-04, F-11 accepted design) |
| Informational | 4 | - | 4 (license and process items) |

No critical finding and no high finding in APIEdge's own code or Python and npm dependencies
was found by any method. The image scan reported 18 High CVEs in Debian packages of the base image
for which Debian has no fix (F-09); each was reviewed and accepted with a review date. The code
defects found (F-01, F-10) are fixed with tests. Open items are design gaps that already have a task or a proposal; none of them can be
closed without a customer decision or a later task.

## 2. Methods and results

| Method | Tool / where | Result |
|---|---|---|
| SAST (Python) | bandit (`ci.yml` quality, every push) | 0 findings in `src`, `scripts` (one Low found in the new DAST script during this task, fixed before commit) |
| SAST (Python, JS/TS) | CodeQL `security-extended` (`codeql.yml`, gate `scripts/codeql-gate.py`) | 0 open results; 1 accepted finding (unchanged, see [Security](SECURITY.md#accepted-findings)) |
| SAST (Semgrep) | not added | Semgrep's CLI is LGPL-2.1, which the dependency license policy excludes; CodeQL and bandit cover the same rule families. Not a gap in coverage, recorded for transparency |
| Dependency audit (runtime) | `pip-audit --strict --require-hashes runtime.lock` | no known vulnerabilities |
| Dependency audit (dev, docs) | `pip-audit` on `dev.lock`, `docs.lock` | docs: none. dev: none since T-032 (the 17 filelock advisories were fixed by filelock 4.2.9 once Python 3.10 support ended; F-07 closed) |
| Dependency audit (console) | `npm audit` | 0 vulnerabilities |
| Container image scan | Grype via `anchore/scan-action` pinned by commit, the container image (`ci.yml` `image-scan`; one variant since T-033), gate `scripts/scan-gate.py` | fails on High/Critical unless accepted; results in section 6 |
| DAST smoke pass | `scripts/dast-smoke.py` against a running production-mode instance (`ci.yml` `dast`) | 64 checks, all passing locally; also runs in CI |
| DAST baseline | OWASP ZAP baseline (image pinned by digest) against console and gateway (`ci.yml` `dast`), gate `scripts/scan-gate.py` | fails on Medium/High unless accepted; results in section 6 |
| Access-control review | `tests/integration/test_route_access_matrix.py` over all 75 admin operations | every route classified; 401/403/404 denials verified for each (section 4) |
| Manual review | auth, sessions, CSRF, proxy handling, SSRF, error handling, logging, secrets | F-01 found and fixed; F-02 to F-04 recorded |

### DAST smoke checks

`scripts/dast-smoke.py` (standard library only) checks, against the live server:

* security headers on the console, the API, the health probe and error responses: CSP with
  `default-src` and `frame-ancestors 'none'` and without `unsafe-inline`/`unsafe-eval`,
  `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Cache-Control: no-store` on the
  API, no `Server` / `X-Powered-By` banner (console and gateway);
* `/docs`, `/redoc`, `/openapi.json` not served in production;
* CORS: preflight and simple requests from an unknown origin get no CORS headers;
* errors: unknown paths, malformed JSON and invalid input answer 404/422 without stack traces,
  library names or echoed input (an XSS marker is sent and must not come back); `TRACE` refused;
* cookies: session and refresh cookies `HttpOnly`, `SameSite=Strict`, path-scoped (`/api`,
  `/api/v1/auth`); the CSRF cookie readable by the console and `SameSite=Strict`;
* CSRF: cookie-authenticated writes without the token, with a mismatched token, or from a
  foreign `Origin` answer 403; a cross-site "simple" (`text/plain`) sign-in is refused;
* body limits: 413 on the admin API and on a published gateway route;
* SSRF guard: upstreams pointing at cloud metadata, loopback (IPv4, IPv6, hex-encoded), private
  ranges and `file:` are refused;
* gateway: unknown routes answer a fixed 404, dot-segment paths are refused;
* login throttling: 429 after the per-minute budget, also when every attempt carries a different
  `X-Forwarded-For` (regression check for F-01); unknown users and bad passwords look alike.

## 3. Findings

| ID | Severity | Finding | Resolution |
|---|---|---|---|
| F-01 | Low | **Forwarded headers trusted from 127.0.0.1 by default.** Uvicorn trusts `X-Forwarded-For`/`-Proto` from 127.0.0.1 unless configured otherwise. Any process on the APIEdge host could choose its client address: verified live, 30 failed sign-ins with rotating `X-Forwarded-For` never hit the per-IP throttle (budget 20/min). On the gateway the same bypassed IP-filter and per-address rate-limit policies, contrary to the documented rule that only `APIEDGE_GATEWAY_TRUSTED_PROXIES` may forward. Per-account lockout still applied, and remote clients were not affected. | **Fixed.** The gateway listener trusts forwarded headers only from `APIEDGE_GATEWAY_TRUSTED_PROXIES` (empty by default: never). The console listener uses the new `APIEDGE_TRUSTED_PROXIES` (default `127.0.0.1`, so a reverse proxy on the same host keeps working; set it empty when there is none). Tests: `tests/unit/test_proxy_trust.py`; DAST regression check in CI. |
| F-02 | Medium | **No native TLS listener.** `apiedge run` served HTTP only; TLS depended on a TLS-terminating reverse proxy or ingress. Auth cookies are `Secure` only over HTTPS or with `APIEDGE_COOKIE_SECURE=true`; HSTS is sent only over HTTPS. | **Fixed in T-023.** The console and gateway listeners terminate TLS natively (`APIEDGE_TLS_*`, `APIEDGE_GATEWAY_TLS_*`; TLS 1.2 minimum, AEAD ciphers, no compression or renegotiation), with optional client certificates on the gateway and the tenant-scoped `mtls` policy ([operations](admin-guide/operations.md#exposing-apiedge-on-the-network-tls), ADR 0013). Over HTTPS cookies are `Secure` and HSTS is sent. Verified with real handshakes in `tests/integration/test_tls.py` (TLS 1.1 and plain HTTP refused, mTLS optional and required) and live with `apiedge tls self-signed` + `apiedge run`. |
| F-03 | Low | **MFA is optional for every account**, including SuperAdmins. TOTP is available and enforced once enrolled, but no policy requires it. ASVS 4.0 L2 does not require MFA for every user; it is good practice for platform administrators. | **Open**, proposal **VP-009** (MFA enforcement policy per tenant and for SuperAdmins). Needs a customer decision because it changes the sign-in flow. |
| F-04 | Low | **Account lockout can be triggered by others.** Five wrong passwords lock an account for 15 minutes, so an attacker who knows a username can lock it out. | **Accepted design** (ASVS 2.2.1 allows lockout with throttling). Per-IP throttling limits the rate; administrators can unlock users; thresholds are configurable (`APIEDGE_LOGIN_MAX_FAILURES`, `APIEDGE_LOGIN_LOCKOUT_MINUTES`). |
| F-05 | Info | **LGPL-3.0 component in one image variant.** `psycopg` was installed only in the image built with `APIEDGE_WITH_POSTGRES=1` (the compose build). | **Closed (T-033, 2026-11-05)**: the customer chose pg8000 (BSD-3-Clause, pure Python) in `runtime.lock`; psycopg, the build argument and the second image variant were removed. |
| F-06 | Info | **Secrets re-encryption.** After a secrets-key rotation the old key must stay configured while data encrypted with it exists. | **Closed (T-034, 2026-11-06)**: `apiedge rotate-secrets` re-encrypts every stored secret with the current key (idempotent, compare-and-set writes, undecryptable tokens kept and reported), so the old key can be removed. Tests: `tests/integration/test_rotate_secrets.py`. |
| F-07 | Info | **Dev-only advisories.** 17 filelock advisories in `dev.lock`; the fix needs Python 3.11+. Not in the runtime set. | **Closed (T-032, 2026-11-05)**: Python 3.10 support ended and `dev.lock` now pins filelock 4.2.9; `requirements/audit-ignore-dev.txt` is empty. |
| F-09 | High (third-party) | **Unfixed CVEs in the base image.** Grype reported 18 High CVEs (no Critical) in Debian 13 packages of `python:3.12-slim` (glibc, util-linux, ncurses, libstdc++, SQLite FTS5 and session extension, libacl, Perl, zlib `gz*`), identical in both image variants. Debian has no fixed version for any of them. No Python package was affected. | **Accepted with review** (rows in [Accepted scanner findings](SECURITY.md#accepted-scanner-findings), review by 2027-01-31): none is reachable from network input (APIEdge never runs the affected tools, uses no FTS5 or session extension, opens only its own database) and the container runs as uid 10001, read-only, with capabilities dropped. Re-checked on every CI run; a new High or Critical fails the build. |
| F-10 | Low | **No `Cross-Origin-Embedder-Policy` header** (ZAP 90004 on the console). | **Fixed**: `Cross-Origin-Embedder-Policy: require-corp` on every response (the console loads only same-origin resources, which already carry CORP). Test: `test_security_middleware.py`. |
| F-11 | Low | **CSRF cookie without `HttpOnly`** (ZAP 10010). | **Accepted design**: the double-submit token must be readable by the console to be echoed in `X-CSRF-Token`. It is not a credential, is `SameSite=Strict`, and the session cookies themselves are `HttpOnly`. Below the gate threshold, so no allowlist row is needed. |
| F-08 | Info | **Release signing key and log shipping not yet in place.** SHA256SUMS are produced and verified; the GPG signature waits for the customer's key. Log shipping and alerting are not built. | **Open**, T-031 (signing key) and T-028 (log shipping, alerting). |

## 4. Access control coverage (RBAC and tenant isolation)

`tests/integration/test_route_access_matrix.py` enumerates every operation of the admin API from
the OpenAPI document and compares its declared access (`x-apiedge-access`) with a reviewed table.
A new route that is not classified fails the suite. For the 75 operations:

| Access | Operations | Denials verified |
|---|---|---|
| public | 5 (`login`, `refresh`, `logout`, `/healthz`, `/readyz`) | exactly these five are reachable without a session |
| signed-in | 7 (own profile, password, MFA, tenant list, permission catalog) | 401 without credentials |
| platform (SuperAdmin) | 4 | 401 without credentials; 403 for a tenant administrator |
| tenant permission | 18 | 401; 403 for a tenant member without the permission; 404 for an administrator of another tenant |
| product-scoped permission | 27 | as tenant routes; and each of the 15 routes under `/products/{product_id}` refuses (403/404) a user whose grant is scoped to a different product, using real object ids and valid bodies so a missing check would show as success |

Object-level checks for ids that are not in the path's product (inspector sessions and exchanges,
analytics filters, users, roles, assignments) are covered by the feature tests listed in
[Security](SECURITY.md#1-controls-in-place) (`test_inspector.py`, `test_analytics.py`,
`test_rbac_api.py`, `test_tenancy.py`).

## 5. Standard-by-standard verdict

### OWASP Top 10 (2021)

| ID | Verdict | Evidence / gap |
|---|---|---|
| A01 Broken Access Control | Met | Route matrix (section 4), BOLA and cross-tenant tests, CSRF (DAST and tests), tenant filter in the data layer |
| A02 Cryptographic Failures | Met | AES-256-GCM at rest, Argon2id, hashed API keys and refresh tokens; native TLS 1.2+ listeners and HSTS over HTTPS (F-02 fixed in T-023) |
| A03 Injection | Met | ORM only, strict Pydantic input models, no `eval`/`exec`, strict CSP, header CR/LF refused, CSV formula escaping; bandit and CodeQL clean |
| A04 Insecure Design | Met | Body limits, login throttling and lockout, anti-escalation, fail-closed policies, bounded capture and caches |
| A05 Security Misconfiguration | Met | Secure defaults verified by DAST (headers, CSP, docs hidden, CORS closed, no banners, no stack traces); ZAP baseline in CI |
| A06 Vulnerable Components | Met | Hash-locked pins; pip-audit, npm audit, Grype image scan all gate CI; SBOM per release. Open: none |
| A07 Identification and Authentication | Met (MFA optional, F-03) | Argon2id, policy, lockout, TOTP, rotation with reuse detection, absolute 12 h session lifetime, session invalidation |
| A08 Software and Data Integrity | Partially met | Hash-verified installs, SHA256SUMS verified on each OS, actions and images pinned by digest/commit for the new scanners, CSRF. Gap: signing key (F-08) |
| A09 Logging and Monitoring | Partially met | Structured masked logs, audit log of privileged actions. Gap: log shipping and alerting (T-028) |
| A10 SSRF | Met (for the features that exist) | SSRF guard on save and at connect time (DNS rebinding), JWKS and inspector replay through the guarded client; DAST probes. Scripts (T-010) will need the same when built |

### OWASP API Security Top 10 (2023)

| ID | Verdict | Evidence / gap |
|---|---|---|
| API1 BOLA | Met | Route matrix, product-scope denials with real ids, tenant isolation tests |
| API2 Broken Authentication | Met | As A07; gateway API keys hashed and revocable, JWT algorithm allow-list |
| API3 Broken Object Property Level Authorization | Met | Explicit response models (no ORM passthrough), unknown request fields rejected, secrets write-only, system settings without secrets |
| API4 Unrestricted Resource Consumption | Met | Body limits (DAST verified on both listeners), rate limits and quotas, timeouts, bounded caches and capture |
| API5 Broken Function Level Authorization | Met | Every operation classified; 403 denials for each tenant, product and platform route |
| API6 Sensitive Business Flows | Partially met | Login throttling, per-consumer rate limits and quotas; plan-based limits come with T-014 |
| API7 SSRF | Met | As A10 |
| API8 Security Misconfiguration | Met | As A05 |
| API9 Improper Inventory Management | Partially met | Lifecycle and versions enforced by the gateway (410, `Deprecation`); catalogs and governance with T-021 |
| API10 Unsafe Consumption of APIs | Met | TLS verification always on, redirects not followed, timeouts and bounded retries, streamed (not buffered) upstream responses, hop-by-hop headers stripped, upstream errors replaced by fixed documents |

### ASVS 4.0 Level 2

| Chapter | Verdict | Notes |
|---|---|---|
| V1 Architecture | Met | Architecture, ADRs, threat-relevant decisions recorded; this report |
| V2 Authentication | Met | 2.1 password policy (12-128, deny list, no composition rules); 2.2 throttling and lockout; 2.4 Argon2id; 2.5 forced change of generated/reset passwords; 2.8 TOTP with replay guard. MFA optional (F-03) |
| V3 Session Management | Met | Random opaque refresh tokens, rotation and reuse detection, `HttpOnly`/`SameSite=Strict`/path-scoped cookies (`Secure` over HTTPS, native TLS since T-023), 15 min access tokens, absolute 12 h re-authentication (3.3.2), logout and invalidation on password and role change |
| V4 Access Control | Met | Deny by default, server-side checks on every route, anti-escalation, tenant and object-level checks (section 4) |
| V5 Validation, Sanitization, Encoding | Met | Strict Pydantic models, header value checks, CSP and React encoding, CSV escaping, SSRF guard |
| V6 Stored Cryptography | Met | AES-256-GCM with associated data and key rotation, key outside the database; re-encryption with `apiedge rotate-secrets` (F-06 closed) |
| V7 Error Handling and Logging | Partially met | Generic errors with request ids, masked structured logs, audit trail; central log shipping pending (T-028) |
| V8 Data Protection | Met | `no-store` on API responses, masking, encrypted and retention-limited captures, unmask permission and audit |
| V9 Communication | Met | Inbound native TLS 1.2+ with optional client certificates (T-023, F-02 fixed); outbound TLS 1.2+ with verification. Revocation checking not implemented |
| V10 Malicious Code | Met | bandit, CodeQL, hash-locked dependencies, pinned actions and images for the scanners |
| V11 Business Logic | Met (baseline) | Rate limits, quotas, lifecycle rules (retired read-only), key limits per product |
| V12 Files and Resources | Met | Body limits; no file upload or server-side file access in the current feature set |
| V13 API and Web Service | Met | CORS allow-list, CSRF, content-type enforced (simple-request sign-in refused), unknown fields rejected |
| V14 Configuration | Met | Secure defaults, docs hidden in production, no banners, pinned dependencies and SBOM, DAST and image scan gates. Signing key pending (F-08) |

## 6. CI scanner results

The scanners run on every push in `ci.yml` (`dast`, `image-scan`). Findings at or above the
threshold fail the build unless accepted in the
[Accepted scanner findings](SECURITY.md#accepted-scanner-findings) table, which requires a
justification and a review date at most 180 days out (`scripts/scan-gate.py`).

First run, CI 41479170443 (commit `650565e`):

| Scanner | Target | Result |
|---|---|---|
| DAST smoke pass | running instance | 64 passed, 0 failed |
| ZAP baseline | console | 0 High, 0 Medium; Low: 10010 (F-11), 90004 (F-10, fixed); Informational: 10049, 10109, 10112 |
| ZAP baseline | gateway | 0 High, 0 Medium, 0 Low; Informational: 10049 (non-storable content) |
| Grype | default image | 193 matches; 0 Critical, 60 High package matches = 18 CVEs (F-09), the rest Medium or lower |
| Grype | PostgreSQL image | identical to the default image (`psycopg` itself reported nothing); since T-033 there is only one image, with pg8000 |

ZAP's Informational alerts describe normal behaviour (an API that is not cacheable, a single-page
application, session cookies) and need no action.

## 7. How to repeat the verification

```bash
# against a running instance in production mode (first admin created beforehand)
APIEDGE_TRUSTED_PROXIES= apiedge run &
python scripts/dast-smoke.py --console http://127.0.0.1:8080 \
    --gateway http://127.0.0.1:8081 --password-file admin-password.txt
# access-control matrix and the rest of the suite
pytest tests/integration/test_route_access_matrix.py
```

The smoke pass creates and deletes a scratch tenant, changes a pending first-login password to a
random one, and ends by exhausting the sign-in budget of the calling address for one minute. Use a
disposable instance.
