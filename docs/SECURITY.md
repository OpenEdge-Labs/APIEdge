# APIEdge Security

APIEdge targets the **OWASP Top 10 (2021)**, the **OWASP API Security Top 10 (2023)** and
**OWASP ASVS 4.0 Level 2**. This document maps each item to the code and tests that cover it. It is
updated with every task. Status: **Done** (implemented and tested), **Partial** (foundation in
place, more to come in the named task) or **Planned**.

Report vulnerabilities privately to the OpenEdge Labs maintainers; do not open public issues.

The pre-release verification (T-018), with findings, severities and resolutions, is in the
[security verification report](security-verification.md).

## 1. Controls in place

| Control | Code | Tests |
|---|---|---|
| Security headers: CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP/COEP, HSTS over HTTPS, `Cache-Control: no-store` on the API | `src/apiedge/security/middleware.py` (`SecurityHeadersMiddleware`) | `tests/integration/test_security_middleware.py` |
| CORS allow-list (closed by default, `*` rejected) | `middleware.py`, `config.py` (`cors_allow_origins`) | `test_security_middleware.py`, `tests/unit/test_config.py` |
| Request body-size limit (Content-Length and streamed bodies, 413) | `BodySizeLimitMiddleware` | `test_security_middleware.py::test_body_size_limit` |
| CSRF: double-submit cookie + Origin check for cookie-authenticated unsafe requests | `CSRFMiddleware` | `test_security_middleware.py::test_csrf_*` |
| Global error barrier: generic 500 with request id, no stack trace; 422 without echoed input | `RequestContextMiddleware`, `_validation_error_handler` | `test_errors_never_leak_*`, `test_validation_errors_do_not_echo_input` |
| Structured JSON logs with secret masking; access log without query strings; request ids | `src/apiedge/logs.py`, `src/apiedge/security/masking.py` | `tests/unit/test_masking_logs.py` |
| Secrets encryption at rest (AES-256-GCM, associated data, key rotation) | `src/apiedge/security/crypto.py` | `tests/unit/test_crypto.py` |
| SSRF guard for upstream URLs | `src/apiedge/security/ssrf.py` | `tests/unit/test_ssrf.py` |
| Argon2id password hashing; password policy (12-128 chars, no username, common-password deny list, no composition rules) | `src/apiedge/security/passwords.py` | `tests/unit/test_passwords.py`, `tests/unit/test_auth_core.py` |
| Authentication: pinned-algorithm HS256 access JWTs (15 min, `iss`/`aud`/`typ` checked), opaque rotating refresh tokens stored as SHA-256 with reuse detection (family revocation), HttpOnly `SameSite=Strict` cookies or Bearer header | `src/apiedge/security/auth.py`, `src/apiedge/admin/auth_routes.py` | `tests/unit/test_auth_core.py`, `tests/integration/test_auth_api.py` |
| Login throttling per client IP (429), account lockout, generic errors (unknown user and bad password look the same, timing equalised) | `auth.py` (`LoginThrottle`, `record_failure`), `auth_routes.py` | `test_auth_api.py::test_lockout_*`, `::test_login_throttled_per_ip`, `::test_bad_password_and_unknown_user_look_the_same` |
| TOTP MFA (RFC 6238, +-1 step, replay guard); secret encrypted at rest with AES-256-GCM bound to the user id | `auth.py`, `auth_routes.py` | `test_auth_api.py::test_totp_*` |
| Session invalidation on password change/reset, role grant/revoke, deactivation (`token_version` + refresh revocation); forced password change on first sign-in and after reset | `auth.py` (`invalidate_sessions`), `admin/deps.py` | `test_auth_api.py::test_password_change_required_*`, `test_rbac_api.py::test_role_change_ends_sessions` |
| RBAC: deny-by-default `resource:action` permission dependency on every admin route; platform permissions only for SuperAdmins; anti-escalation (grant only what you hold, manage only less-or-equally privileged users) | `src/apiedge/security/rbac.py`, `src/apiedge/admin/deps.py`, `admin/users.py`, `admin/roles.py` | `tests/unit/test_rbac.py`, `tests/integration/test_rbac_api.py` |
| Multi-tenancy: tenant-bound sessions add `tenant_id` criteria to every ORM query and refuse cross-tenant writes; foreign tenants answer 404 | `src/apiedge/db/tenancy.py`, `admin/deps.py` (`require`) | `tests/integration/test_tenancy.py`, `test_rbac_api.py::test_*cross_tenant*`, `::test_bola_*` |
| Product-level authorization: product routes check the permission for the product (tenant-wide or product-scoped grant); unreadable products answer 404 (T-005) | `src/apiedge/admin/products.py`, `admin/deps.py` (`require_any`) | `tests/integration/test_products_api.py` |
| API-level authorization: API routes check `api:*` for the product (tenant-wide or product-scoped); an API outside the product in the path answers 404 (T-006) | `src/apiedge/admin/apis.py` | `tests/integration/test_apis_api.py` (`test_product_scoped_developer_and_bola`, `test_cross_tenant_access_is_not_found`) |
| Upstream URLs pass the SSRF guard under the configured policy when saved; the response carries a fixed message, not the guard's exception text (T-006) | `src/apiedge/admin/apis.py` (`_upstreams`), `config.py` (`Settings.ssrf_policy`) | `tests/integration/test_apis_api.py::test_upstreams_go_through_the_ssrf_guard`, `::test_ssrf_policy_comes_from_settings` |
| Gateway connect-time SSRF guard: every new upstream connection re-resolves the host, checks all addresses and connects to a checked one while keeping Host/SNI (DNS rebinding); no redirects followed; proxy env vars ignored (T-007) | `src/apiedge/gateway/transport.py`, `src/apiedge/security/ssrf.py` (`resolve_checked_async`) | `tests/integration/test_gateway.py::test_connect_time_ssrf_guard`, `::test_host_name_is_kept_when_connecting_to_the_checked_address`, `::test_redirects_are_passed_through_not_followed`, `tests/unit/test_gateway_units.py::test_connect_time_resolution` |
| Gateway hardening: hop-by-hop headers stripped both ways, `X-Forwarded-*` set by the gateway, request body limit (413), dot-segment paths refused, fixed error documents without upstream or exception details, TLS 1.2+ with certificate verification always on (T-007) | `src/apiedge/gateway/app.py`, `transport.py` | `test_gateway.py::test_header_handling`, `::test_body_size_limit`, `::test_dot_segments_are_refused`, `::test_timeout_answers_504_without_details` |
| Gateway lifecycle and tenant enforcement: drafts and inactive tenants invisible, retired APIs/products 410, deprecated flagged; routing snapshot keyed by each API's own tenant (T-007) | `src/apiedge/gateway/snapshot.py` | `test_gateway.py::test_lifecycle_gating`, `::test_tenant_separation`, `::test_inactive_tenant_is_not_served` |
| Policy chains (T-008): `policy:read` / `policy:update` per product on the chain routes; chains validated by strict Pydantic models on save and again when the gateway loads them; unusable entries (invalid config, undecryptable secret) fail closed with 503; a policy exception answers a generic 500 | `src/apiedge/admin/policies.py`, `src/apiedge/policies/` | `tests/integration/test_policies_api.py::test_policy_chain_rbac_and_tenant_isolation`, `::test_policy_chain_validation`, `tests/unit/test_policies_units.py::test_unusable_stored_policies_fail_closed`, `tests/integration/test_policies_gateway.py::test_secrets_are_encrypted_and_bad_ciphertext_fails_closed` |
| Policy secrets (JWT shared secret) encrypted with AES-256-GCM bound to API, policy and field; write-only in the admin API; never in audit details | `admin/policies.py`, `policies/builtin.py` (`decrypt_secrets`) | `test_policies_api.py::test_policy_chain_crud_and_write_only_secrets` |
| Native TLS (T-023, closes F-02): console and gateway listeners terminate TLS 1.2+ (1.3 optional) with forward secret AEAD ciphers, no compression or renegotiation; plain HTTP is not served on a TLS port; `Secure` cookies and HSTS follow automatically | `src/apiedge/security/tls.py`, `cli.py` (`cmd_run`), `config.py` | `tests/integration/test_tls.py::test_native_tls_gateway_with_client_certificates`, `::test_required_client_certificates_fail_the_handshake`, `tests/unit/test_x509.py::test_tls_settings_validation` |
| Client certificates / mTLS (T-023): the `mtls` policy verifies the chain (signatures, validity, CA flags, client-authentication usage) against a truststore of the API's own tenant, with subject and fingerprint allow-lists; a foreign or missing truststore fails closed (503); forwarded certificates accepted only from trusted proxies and never forwarded upstream; strict bounded DER parsing; SHA-1/MD5 signatures refused | `src/apiedge/security/x509.py`, `policies/builtin.py` (`ClientCertAuth`), `gateway/app.py` (`_client_cert`) | `tests/integration/test_tls.py::test_mtls_policy`, `::test_mtls_allow_lists_and_fail_closed`, `tests/unit/test_x509.py::test_chain_validation`, `::test_tampered_and_malformed_certificates` |
| Keystores and truststores (T-023): `tls:read` / `tls:manage` tenant-wide; private keys must match the certificate, are stored only AES-256-GCM encrypted bound to tenant and keystore and are never returned; truststores in use cannot be deleted; all changes audited | `src/apiedge/admin/tls.py` | `tests/integration/test_tls.py::test_truststore_crud_rbac_and_isolation`, `::test_keystore_crud_encryption_and_validation`, `test_route_access_matrix.py` |
| OAuth 2.0 / OIDC server (T-023): per-tenant issuers, keys, clients and user registry on tenant-bound sessions; client secrets, codes and refresh tokens stored only as SHA-256; signing keys AES-256-GCM encrypted bound to tenant and key id; PKCE S256 mandatory; exact redirect URI matching (https, loopback or app scheme); single-use 60 s codes; refresh rotation with family revocation on reuse (audited); access-token revocation by `jti`; sign-in page with strict CSP, `frame-ancestors 'none'`, SameSite=Strict CSRF cookie, per-address throttling, account lockout and TOTP; admin routes `oauth:read` / `oauth:manage` | `src/apiedge/gateway/oauth_server.py`, `security/oauth.py`, `security/user_registry.py`, `admin/oauth.py` | `tests/integration/test_oauth.py`, `tests/unit/test_oauth.py`, `test_route_access_matrix.py` |
| Upstream TLS profiles (T-023): per-API TLS 1.2/1.3 minimum, tenant truststore for upstream verification and keystore client certificate (upstream mTLS); verification cannot be turned off; profiles, stores and keys only resolve within the API's own tenant, unusable profiles fail closed (503); referenced profiles, truststores and keystores cannot be deleted | `src/apiedge/admin/tls.py`, `gateway/snapshot.py` (`_profiles`), `gateway/transport.py` (`build_profile_context`) | `tests/integration/test_tls_profiles.py` |
| API keys (T-008): 256-bit random, shown once (`Cache-Control: no-store`), stored as SHA-256 with a display prefix, expiry and revocation (reloads the gateway); `apikey:read` / `apikey:manage` per product; keys only valid for their own product and tenant; not forwarded upstream by default | `admin/policies.py`, `policies/builtin.py` (`ApiKeyAuth`), `gateway/snapshot.py` | `test_policies_api.py::test_api_keys_shown_once_stored_hashed_and_revocable`, `::test_api_key_rbac_and_tenant_isolation`, `test_policies_gateway.py::test_api_key_policy`, `::test_key_management_and_revocation_through_admin_api` |
| JWT validation (T-008): algorithm allow-list (no `none`, no HS/asymmetric mix), `crit` refused, RSA >= 2048 bits, curve bound to algorithm, `exp`/`nbf`/`iss`/`aud` with bounded leeway, token size cap; JWKS over https through the SSRF-guarded client (checked on save and at connect time), 64 KiB cap, throttled refresh, symmetric JWKs ignored | `src/apiedge/policies/jwt.py` | `test_policies_units.py::test_invalid_tokens_are_refused`, `::test_algorithm_confusion_hs_signed_with_public_key_is_refused`, `::test_parse_jwks_skips_symmetric_and_bad_keys`, `::test_jwks_failures_and_size_limit`, `test_policies_gateway.py::test_jwt_policy`, `::test_jwks_fetch_goes_through_the_ssrf_guard`, `test_policies_api.py::test_policy_chain_server_side_checks` |
| Rate limits and quotas (T-008): fixed windows per consumer, client address or API; Redis shared or bounded in-process counters (fallback on Redis errors); hashed keys; 429 with `Retry-After` and `RateLimit-*` | `src/apiedge/policies/stores.py`, `builtin.py` (`RateLimit`) | `test_policies_units.py::test_memory_limiter_fixed_windows_and_bounded_keys`, `::test_redis_limiter_uses_redis_and_falls_back`, `test_policies_gateway.py::test_rate_limit_per_consumer_and_ip` |
| Client address: `X-Forwarded-For` only honoured from `APIEDGE_GATEWAY_TRUSTED_PROXIES`, read from the right (spoofed left-hand entries ignored) | `src/apiedge/gateway/app.py` (`client_address`) | `test_policies_units.py::test_client_address_behind_trusted_proxies`, `test_policies_gateway.py::test_ip_filter_policy` |
| Response cache (T-008): GET/HEAD only, respects `no-store`/`no-cache`/`private`/`Set-Cookie`/`Vary`; authenticated requests bypass unless enabled, then keyed per identity or credential hash; byte-capped LRU; exchange headers (request id, CORS, rate limit) not stored | `builtin.py` (`Cache`), `stores.py` (`ResponseCache`) | `test_policies_gateway.py::test_cache_policy`, `::test_cache_of_authenticated_responses_is_per_consumer`, `test_policies_units.py::test_response_cache_lru_by_size_and_expiry` |
| Transforms, CORS, mocks (T-008): gateway-managed headers cannot be set or removed; header values limited to visible Latin-1 (no CR/LF injection); CORS `*` with credentials refused, preflights answered before auth and refused with 403 for unknown origins, methods or headers; mock bodies capped at 64 KiB | `policies/config.py`, `builtin.py` | `test_policies_units.py::test_invalid_policy_configs_are_rejected`, `test_policies_gateway.py::test_transform_policy`, `::test_cors_policy`, `::test_mock_route_scoping_disabled_policies_and_trace` |
| Analytics (T-013): `analytics:view` tenant-wide or per product on every analytics route; tenant-bound queries; product-scoped callers only see their products (a foreign `product_id` yields no data); bounded time ranges (31 days) and export size; CSV formula-injection escaping; exports audit-logged; only identifiers and numbers stored (no content, headers, query strings or client IPs) | `src/apiedge/admin/analytics.py`, `src/apiedge/analytics/` | `tests/integration/test_analytics.py::test_rbac_product_scope_and_tenant_isolation`, `::test_csv_export_and_audit`, `::test_time_range_validation`, `tests/unit/test_analytics_units.py::test_csv_cells_cannot_become_formulas` |
| Packet inspector (T-012): `inspector:view` / `inspector:capture` / `inspector:unmask` tenant-wide or per product on every route; tenant-bound queries plus product scoping (other products and tenants answer 404); capture opt-in per API, time-boxed and limited per tenant; bodies capped, in-memory queue bounded in bytes (drops, never blocks), per-session ring buffer and retention; full exchanges stored only AES-256-GCM encrypted and bound to tenant and session; masked by default on every read path (headers, query/form parameters, JSON keys, embedded credentials, configured fields); unmasked views, HAR exports and replays audit-logged; replay only to the API's configured upstreams through an explicit SSRF check and the guarded client; live view ends after 5 minutes so authorization is re-checked | `src/apiedge/admin/inspector.py`, `src/apiedge/inspector/` | `tests/integration/test_inspector.py::test_rbac_and_tenant_isolation`, `::test_product_scoped_inspector_grant`, `::test_capture_mask_and_unmask`, `::test_replay_goes_to_the_api_upstream_through_the_ssrf_guard`, `::test_ring_buffer_and_body_cap`, `::test_retention_and_delete`, `tests/unit/test_inspector_units.py` |
| Prometheus `/metrics` off by default; enabled only with `APIEDGE_METRICS_TOKEN` (>= 16 chars), bearer token compared in constant time, not in the OpenAPI schema (T-013) | `src/apiedge/app.py`, `config.py` | `test_analytics.py::test_prometheus_metrics_endpoint`, `test_analytics_units.py::test_metrics_token_setting` |
| Audit log of sign-ins (success/failure), lockouts, refresh-token reuse and every privileged change; masked details; tenant-scoped reading | `src/apiedge/security/audit.py`, `admin/tenants.py` | `test_rbac_api.py::test_audit_log_is_tenant_scoped`, `::test_tenant_admin_user_and_role_lifecycle` |
| Console (T-004): strict CSP without `unsafe-inline` (bundle has no inline scripts or styles), double-submit CSRF header on every unsafe request, session only in HttpOnly cookies (no token in JS storage), React output encoding, permission-aware navigation as UX only (the server enforces); system settings view never returns secrets | `console/src/api.ts`, `console/src/access.ts`, `src/apiedge/admin/system.py` | `tests/integration/test_console.py`, `console/test/*.test.ts` |
| No server/version disclosure (`server_header=False`, minimal `/healthz`) | `cli.py`, `app.py` | `tests/integration/test_app.py` |
| Access-control matrix (T-018): every admin operation's declared access is compared with a reviewed table (unclassified routes fail); 401 without credentials, 403 without the permission, 404 across tenants, 403 for tenant admins on platform routes, and product-scoped grants refused on other products (real ids, valid bodies) | `src/apiedge/admin/deps.py` (`annotate_access`) | `tests/integration/test_route_access_matrix.py` |
| Forwarded headers (T-018, F-01): `X-Forwarded-For` / `-Proto` honoured only from configured proxies, per listener (`APIEDGE_TRUSTED_PROXIES` for the console, default `127.0.0.1`; `APIEDGE_GATEWAY_TRUSTED_PROXIES` for the gateway, default none) | `src/apiedge/cli.py` (`proxy_options`), `config.py` | `tests/unit/test_proxy_trust.py`, DAST throttle check |
| DAST (T-018): smoke pass over headers, CSP, CORS, cookie flags, CSRF, body limits, error documents, SSRF guard and login throttling against a running instance; OWASP ZAP baseline on console and gateway; Grype scan of the container image | `scripts/dast-smoke.py`, `scripts/scan-gate.py` | CI `dast` and `image-scan` jobs, `tests/unit/test_scan_gate.py` |
| Hash-locked dependencies, license gate | `requirements/*.lock`, `scripts/check-licenses.py` | CI `quality` job |
| Release integrity (T-016): wheel content check (console and migrations present, no third-party code), installer bundles built only from git-tracked files, CycloneDX SBOM, SHA256SUMS verified on every OS before use, optional GPG signature; publishing is opt-in and draft-only | `scripts/build-release.py`, `.github/workflows/release.yml` | `tests/unit/test_build_release.py`, `release.yml` jobs |
| Container hardening (T-016): base images pinned by digest, dependencies installed with `--require-hashes`, allow-list `.dockerignore`, non-root user 10001, read-only root filesystem and dropped capabilities in compose and Helm, ports published on localhost only, no default passwords (compose refuses to start without `POSTGRES_PASSWORD`), first admin password from a secret file or generated once | `packaging/docker/`, `docker-compose.yml`, `packaging/helm/apiedge/` | `test_build_release.py::test_dockerfile_*`, `::test_compose_*`, `release.yml` (`docker`, `helm`) |

## 2. OWASP Top 10 (2021)

| ID | Risk | APIEdge control | Status |
|---|---|---|---|
| A01 | Broken Access Control | Deny-by-default RBAC dependency, tenant-filtered data access, BOLA and cross-tenant tests (T-003); CSRF protection (T-002) | Done (admin API; each new resource adds its own tests) |
| A02 | Cryptographic Failures | AES-256-GCM secrets at rest with key outside the DB (T-002); Argon2id (T-001); HSTS (T-002); native TLS on gateway and console listeners, mTLS (T-023) | Done |
| A03 | Injection | SQLAlchemy ORM / bound parameters only; Pydantic validation; strict CSP; no `eval`/`exec` outside the sandbox (T-010); bandit + CodeQL in CI | Done (baseline) |
| A04 | Insecure Design | Body-size limits (T-002, gateway T-007); login throttling and lockout, anti-escalation rules (T-003); gateway rate limits and quotas, fail-closed policy pipeline (T-008) | Done (baseline) |
| A05 | Security Misconfiguration | Secure defaults (localhost bind, production mode, CORS closed), security headers, docs only in development, no stack traces | Done (baseline) |
| A06 | Vulnerable and Outdated Components | Hash-locked pins, pip-audit (runtime strict), npm audit, license gate; CycloneDX SBOM of the Python runtime and bundled console packages in every release build; container base images pinned by digest (T-016) | Done (baseline) |
| A07 | Identification and Authentication Failures | Argon2id (T-001); password policy, lockout, TOTP MFA, refresh rotation with reuse detection, session invalidation, forced first password change (T-003); built-in OAuth 2.0 / OIDC server with PKCE, refresh rotation and reuse detection (T-023); console SSO later | Done |
| A08 | Software and Data Integrity Failures | Hash-verified installs (installer, wheel smoke test and container image), CSRF (T-002); SHA256SUMS over every release artifact, verified in CI on each OS before use (T-016); GPG signature of SHA256SUMS when the release key secret is configured (pending the customer's key, T-031) | Partial (signing key) |
| A09 | Security Logging and Monitoring Failures | Structured JSON logs with masking and request ids (T-002); audit log with tenant-scoped viewer API (T-003); log shipping and alerting (T-028) | Partial (T-028) |
| A10 | Server-Side Request Forgery | SSRF guard utility (T-002); enforced when upstream URLs are saved (T-006); enforced at connect time in the gateway proxy against DNS rebinding (T-007); inspector replay limited to the API's upstreams and SSRF-checked (T-012); scripts (T-010) | Partial |

## 3. OWASP API Security Top 10 (2023)

| ID | Risk | APIEdge control | Status |
|---|---|---|---|
| API1 | Broken Object Level Authorization | Tenant filter in the data-access layer plus explicit ownership checks; BOLA tests (T-003); product-level checks and product BOLA tests (T-005); API BOLA tests (T-006); analytics product scoping and tenant isolation tests (T-013); inspector session/exchange BOLA and tenant tests (T-012) | Done (admin API) |
| API2 | Broken Authentication | Argon2id, throttling, lockout, MFA, short-lived JWT + rotating refresh cookie (T-003); gateway API keys (hashed, revocable) and JWT validation with algorithm allow-list (T-008); OAuth 2.0 tokens from the tenant's own authorization server (T-023) | Done |
| API3 | Broken Object Property Level Authorization | Explicit Pydantic response models (no ORM passthrough), unknown request fields rejected, 422 without echoed input (T-002); secrets write-only (T-008); verified in T-018 | Done |
| API4 | Unrestricted Resource Consumption | Admin API body-size limit (T-002); gateway body limit, upstream timeouts and bounded retries (T-007); rate limits and quotas, bounded counters, caches and JWKS documents (T-008); bounded packet capture (T-012) | Done (baseline) |
| API5 | Broken Function Level Authorization | `resource:action` permission on every admin route, 403 tests (T-003) | Done |
| API6 | Unrestricted Access to Sensitive Business Flows | Rate limits and quotas per consumer, address or API (T-008); per plan (T-014) | Partial (T-014) |
| API7 | Server Side Request Forgery | SSRF guard (T-002), enforced at every outbound call site; upstream URLs checked on save (T-006) and at every gateway connect (T-007); JWKS URLs checked on save and fetched through the guarded client (T-008); inspector replay (T-012) | Partial |
| API8 | Security Misconfiguration | Same as A05; CORS allow-list | Done (baseline) |
| API9 | Improper Inventory Management | API lifecycle and versions (T-006); deprecated and retired APIs enforced by the gateway (T-007, 410 / `Deprecation`); catalogs and governance (T-021) | Partial |
| API10 | Unsafe Consumption of APIs | Upstream timeouts and bounded retries, streamed responses, no redirects followed, SSRF guard, TLS verification always on, fixed error documents (T-007) | Done (baseline) |

## 4. ASVS 4.0 Level 2 (by chapter)

| Chapter | Coverage today | Next |
|---|---|---|
| V1 Architecture | `docs/ARCHITECTURE.md`, ADRs 0001-0004 | ongoing |
| V2 Authentication | Argon2id, password policy, lockout, throttling, TOTP | OIDC SSO |
| V3 Session Management | HttpOnly/SameSite=Strict/Secure cookies, 15-min tokens, rotation, absolute 12 h refresh-family lifetime (3.3.2), revocation on logout/password/role change | - |
| V4 Access Control | RBAC dependency, tenant filter, anti-escalation | per feature |
| V5 Validation, Sanitization, Encoding | Pydantic, strict CSP, SSRF guard | each feature |
| V6 Stored Cryptography | AES-256-GCM, key outside DB, rotation | T-023 vault integration |
| V7 Error Handling and Logging | Generic errors, JSON logs, masking, request ids, audit log | T-028 |
| V8 Data Protection | `Cache-Control: no-store` on API, masking; captured traffic encrypted, masked by default, retention-limited (T-012) | - |
| V9 Communication | Native TLS 1.2+ listeners, client certificates (mTLS), HSTS over HTTPS; outbound TLS 1.2+ with verification (T-023) | Revocation checks (CRL/OCSP) |
| V10 Malicious Code | bandit, CodeQL, hash-locked dependencies | - |
| V11 Business Logic | Rate limits and quotas (T-008), lifecycle rules, per-product key limits | T-014 plans |
| V12 Files and Resources | Body-size limits | T-011 imports |
| V13 API and Web Service | CORS allow-list, CSRF, strict input models (unknown fields rejected) | each feature |
| V14 Configuration | Secure defaults, docs only in dev, no server header, pinned deps, CycloneDX SBOM, checksummed release artifacts (T-016) | Release signing key (T-031) |

## 5. CI security gates

| Gate | Where | Fails on |
|---|---|---|
| bandit | `.github/workflows/ci.yml` (`quality`) | any finding in `src`, `scripts` |
| pip-audit | `ci.yml` (`quality`) | any known vulnerability in `runtime.lock` (strict); `dev.lock` with documented exceptions |
| npm audit | `ci.yml` (`console`) | high or critical |
| License gate | `ci.yml` (`quality`) | GPL, AGPL, SSPL |
| Scanner acceptances | `ci.yml` (`quality`, `scripts/scan-gate.py check`) | an incomplete or expired row in the Accepted scanner findings table |
| DAST smoke pass | `ci.yml` (`dast`, `scripts/dast-smoke.py`) | any failed check against the running instance |
| OWASP ZAP baseline (console, gateway; image pinned by digest) | `ci.yml` (`dast`, gate `scripts/scan-gate.py zap`) | a Medium or High alert that is not accepted (reports kept as an artifact) |
| Grype container scan (default and PostgreSQL image; action pinned by commit) | `ci.yml` (`image-scan`, gate `scripts/scan-gate.py grype`) | a High or Critical vulnerability that is not accepted (JSON kept as an artifact) |
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

### Accepted scanner findings

Fixing is always preferred. A ZAP alert (Medium or High) or a Grype vulnerability (High or
Critical) is accepted only by a row below. `scripts/scan-gate.py` fails the build on an unaccepted
finding, on an incomplete row, on a row past its review date, and on a review date more than 180
days after acceptance, so every acceptance is reviewed again. Target is `console` or `gateway`
for ZAP and the package name for Grype.

All rows below come from the first Grype run (CI 41479170443): High findings in Debian 13 packages of
the pinned `python:3.12-slim` base image (one image variant since T-033), for which Debian has no
fixed version (status `wont-fix` or `not-fixed`). No Python package and no Critical finding was
reported. None is reachable from network input to APIEdge; the image runs as uid 10001 with a
read-only root filesystem and dropped capabilities (compose, Helm). Each row is reviewed again by
its date, and earlier whenever the base image digest is bumped.

| Scanner | ID | Target | Justification | Accepted | Review by |
|---|---|---|---|---|---|
| grype | CVE-2025-69720 | libncursesw6, libtinfo6, ncurses-base, ncurses-bin | Debian 13 base-image package, no fixed version in Debian; overflow in the `infocmp` CLI, which APIEdge never runs. Revisit when Debian ships a fix or the base image is bumped | 2026-11-02 | 2027-01-31 |
| grype | CVE-2026-102010 | gcc-14-base, libgcc-s1, libstdc++6 | Debian 13 base-image package, no fixed version in Debian; libstdc++ priority-queue `erase_if`; no APIEdge or dependency code path passes untrusted input to it. Revisit when Debian ships a fix or the base image is bumped | 2026-11-02 | 2027-01-31 |
| grype | CVE-2026-95619 | gcc-14-base, libgcc-s1, libstdc++6 | Debian 13 base-image package, no fixed version in Debian; libstdc++ aligned `operator new` with huge sizes; request bodies are size-capped before any native code sees them. Revisit when Debian ships a fix or the base image is bumped | 2026-11-02 | 2027-01-31 |
| grype | CVE-2026-119373 | libsqlite3-0 | Debian 13 base-image package, no fixed version in Debian; FTS5 bug; APIEdge creates no FTS5 tables and only opens its own database with ORM-generated SQL. Revisit when Debian ships a fix or the base image is bumped | 2026-11-02 | 2027-01-31 |
| grype | CVE-2026-119374 | libsqlite3-0 | Debian 13 base-image package, no fixed version in Debian; FTS5 secure-delete with a crafted database file; APIEdge never opens database files from users. Revisit when Debian ships a fix or the base image is bumped | 2026-11-02 | 2027-01-31 |
| grype | CVE-2026-119379 | libsqlite3-0 | Debian 13 base-image package, no fixed version in Debian; SQLite session extension `sqlite3changeset_apply`, not used by Python's sqlite3 module or APIEdge. Revisit when Debian ships a fix or the base image is bumped | 2026-11-02 | 2027-01-31 |
| grype | CVE-2026-19499 | libc-bin, libc6 | Debian 13 base-image package, no fixed version in Debian; glibc `strfmon`, not called by Python or APIEdge. Revisit when Debian ships a fix or the base image is bumped | 2026-11-02 | 2027-01-31 |
| grype | CVE-2026-5435 | libc-bin, libc6 | Debian 13 base-image package, no fixed version in Debian; deprecated glibc `ns_printrr` / `fp_nquery` TSIG printing, not called. Revisit when Debian ships a fix or the base image is bumped | 2026-11-02 | 2027-01-31 |
| grype | CVE-2026-84243 | libc-bin, libc6 | Debian 13 base-image package, no fixed version in Debian; gettext `LANGUAGE` path handling; needs control of the process environment, which is set by the operator only. Revisit when Debian ships a fix or the base image is bumped | 2026-11-02 | 2027-01-31 |
| grype | CVE-2026-54369 | libacl1 | Debian 13 base-image package, no fixed version in Debian; local privilege escalation via ACL path functions; container runs as uid 10001 with a read-only root filesystem and no SUID use. Revisit when Debian ships a fix or the base image is bumped | 2026-11-02 | 2027-01-31 |
| grype | CVE-2026-54370 | libacl1 | Debian 13 base-image package, no fixed version in Debian; local TOCTOU in ACL path functions; same container restrictions, not called by APIEdge. Revisit when Debian ships a fix or the base image is bumped | 2026-11-02 | 2027-01-31 |
| grype | CVE-2026-76642 | bsdutils, libblkid1, liblastlog2-2, libmount1, libsmartcols1, libuuid1, login, mount, util-linux | Debian 13 base-image package, no fixed version in Debian; local mount-helper issue; container runs non-root with capabilities dropped and never mounts. Revisit when Debian ships a fix or the base image is bumped | 2026-11-02 | 2027-01-31 |
| grype | CVE-2026-78408 | bsdutils, libblkid1, liblastlog2-2, libmount1, libsmartcols1, libuuid1, login, mount, util-linux | Debian 13 base-image package, no fixed version in Debian; `nsenter --join-cgroup`, never run in the container. Revisit when Debian ships a fix or the base image is bumped | 2026-11-02 | 2027-01-31 |
| grype | CVE-2026-78409 | bsdutils, libblkid1, liblastlog2-2, libmount1, libsmartcols1, libuuid1, login, mount, util-linux | Debian 13 base-image package, no fixed version in Debian; `X-mount.subdir` symlink traversal by local users; no mounts in the container. Revisit when Debian ships a fix or the base image is bumped | 2026-11-02 | 2027-01-31 |
| grype | CVE-2026-78410 | bsdutils, libblkid1, liblastlog2-2, libmount1, libsmartcols1, libuuid1, login, mount, util-linux | Debian 13 base-image package, no fixed version in Debian; SUID `mount` with fstab bind mounts; no fstab mounts, non-root, capabilities dropped. Revisit when Debian ships a fix or the base image is bumped | 2026-11-02 | 2027-01-31 |
| grype | CVE-2026-82560 | perl-base | Debian 13 base-image package, no fixed version in Debian; Perl `Pod::Text`; Perl is never run by APIEdge. Revisit when Debian ships a fix or the base image is bumped | 2026-11-02 | 2027-01-31 |
| grype | CVE-2026-9538 | perl-base | Debian 13 base-image package, no fixed version in Debian; Perl `Archive::Tar`; Perl is never run by APIEdge. Revisit when Debian ships a fix or the base image is bumped | 2026-11-02 | 2027-01-31 |
| grype | CVE-2026-85091 | zlib1g | Debian 13 base-image package, no fixed version in Debian; zlib `gzwrite`/`gzprintf` non-blocking path; Python's gzip and httpx use only the deflate/inflate stream API. Revisit when Debian ships a fix or the base image is bumped | 2026-11-02 | 2027-01-31 |

### Fixed defects

| Date | Found by | Defect | Fix |
|---|---|---|---|
| 2026-11-02 | Manual review and live probe, T-018 (F-01) | Forwarded headers were trusted from 127.0.0.1 (the ASGI server's default). A process on the APIEdge host could set its client address with `X-Forwarded-For`: 30 failed sign-ins with rotating addresses never reached the per-IP throttle, and the gateway's IP-filter and per-address rate-limit policies could be bypassed, contrary to the rule that only `APIEDGE_GATEWAY_TRUSTED_PROXIES` may forward. Remote clients and per-account lockout were unaffected. | Each listener now trusts forwarded headers only from its configured proxies: the gateway from `APIEDGE_GATEWAY_TRUSTED_PROXIES` (none by default), the console from the new `APIEDGE_TRUSTED_PROXIES` (default `127.0.0.1` for a same-host reverse proxy; empty disables). Tests: `tests/unit/test_proxy_trust.py`; the CI DAST pass checks the throttle with spoofed headers. |
| 2026-11-01 | CI (Windows, Python 3.12), during T-005 | Tenant filter could be silently missing. `install_tenant_filter` skipped installation when `event.contains(...)` said the listener was present, but SQLAlchemy's event registry is keyed by `id(target)`: a session factory allocated at the address of a garbage-collected factory was reported as filtered, so its sessions ran unfiltered and a tenant's audit log (and other list queries that rely only on the data-layer filter) could include other tenants' rows. Route-level tenant checks (`require`, 404 for foreign tenants, explicit `tenant_id` comparisons on object lookups) were unaffected. The server creates one factory per process, so a long-running `apiedge run` was exposed only if a factory had been created and collected earlier in the same process (tests, embedding `create_app` more than once). | The guard is now a marker attribute on the factory itself (`src/apiedge/db/tenancy.py`). Regression test `tests/integration/test_tenancy.py::test_filter_installed_on_every_new_factory` creates factories at recycled addresses and fails on the old code. |

## 6. Security configuration

See the [configuration guide](admin-guide/configuration.md) and `.env.example`. Security-relevant settings:
`APIEDGE_ENV`, `APIEDGE_CORS_ALLOW_ORIGINS`, `APIEDGE_MAX_REQUEST_BODY_BYTES`,
`APIEDGE_HSTS_MAX_AGE`, `APIEDGE_LOG_FORMAT`, `APIEDGE_SECRET_KEY`, `APIEDGE_SECRET_KEY_PREVIOUS`,
`APIEDGE_SECRET_KEY_FILE`, `APIEDGE_SSRF_ALLOW_PRIVATE`, `APIEDGE_SSRF_ALLOW_CIDRS`,
`APIEDGE_SSRF_DENY_CIDRS`, `APIEDGE_ACCESS_TOKEN_TTL_SECONDS`,
`APIEDGE_REFRESH_TOKEN_TTL_HOURS`, `APIEDGE_LOGIN_MAX_FAILURES`, `APIEDGE_LOGIN_LOCKOUT_MINUTES`,
`APIEDGE_LOGIN_RATE_LIMIT_PER_MINUTE`, `APIEDGE_JWT_SECRET`, `APIEDGE_COOKIE_SECURE`,
`APIEDGE_TRUSTED_PROXIES`, `APIEDGE_GATEWAY_TRUSTED_PROXIES`.

**Back up the secrets key** (`<data dir>/secret.key` or `APIEDGE_SECRET_KEY`). Without it,
encrypted secrets cannot be recovered. To rotate: set the new key as `APIEDGE_SECRET_KEY`, list the
old one in `APIEDGE_SECRET_KEY_PREVIOUS`. New data is encrypted with the new key and old data stays
readable. Then run `apiedge rotate-secrets` (T-034): it re-encrypts every
stored secret (MFA secrets, policy secrets, keystore and OAuth signing keys, captured traffic)
with the new key, keeping each token's associated data, so the old key can be removed. It is
idempotent, writes each row with a compare-and-set update (a row changed meanwhile is skipped,
never overwritten), never deletes undecryptable tokens and never prints values. Tests:
`tests/integration/test_rotate_secrets.py`. See [operations](admin-guide/operations.md#the-secrets-key).
