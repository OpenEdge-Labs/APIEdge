# APIEdge — Customer Task List

Tasks for the APIEdge development team (APVendor). Add new tasks at the bottom of the relevant section. The development team updates only the status markers and the `>` notes under each task.

**Status:** `[ ]` open · `[~]` in progress · `[x]` done · `[!]` blocked · `[?]` needs your input
**Priority:** P1 (highest) to P3

**Execution order:** highest priority first, once all dependencies are done.

## Global requirements (apply to every task)

- **G-1 Stack:** Python + FastAPI, as specified in `docs/PROJECT_GUIDE.md`.
- **G-2 Security:** OWASP Top 10, OWASP API Security Top 10 and ASVS L2, as mapped in `docs/SECURITY.md`.
- **G-3 Cross-platform:** everything must work on Windows, Linux and macOS.
- **G-4 Documentation:** every feature ships with its user, admin and API documentation.
- **G-5 RBAC and multi-tenancy:** every feature is permission-checked and tenant-isolated.
- **G-6 Git:** after each completed task, commit and push to `origin main` (GitHub: APIEdge).
- **G-7 One-click installer:** third-party dependencies are **not** committed to git. A one-click installer for each OS (`install.bat` for Windows, `install.command` for macOS, `install.sh` for Linux) downloads them from the internet and installs and starts APIEdge. Details are in `docs/PROJECT_GUIDE.md`.
- **G-8 Enterprise feature parity:** APIEdge must provide the capabilities of IBM API Connect / DataPower and the other leading gateways (Kong, Apigee, Azure APIM, AWS API Gateway, MuleSoft, WSO2, Tyk, Gravitee), tracked in `docs/FEATURE_MATRIX.md`. All of it is our own original implementation.
- **G-9 Single task list:** `APIProjectTask.md` is the only place where tasks, their status, delivery notes, blockers, questions and proposals are tracked. Do not create other task lists, TODO files or issue trackers. `docs/PROGRESS.md` is a delivery log only.

## Task format

```
- [ ] **T-XXX** (P1) Short title
  - Details / acceptance criteria
  - Depends on: T-YYY
```

---

## Phase 1: Foundation

- [x] **T-001** (P1) Project scaffolding (Python/FastAPI)
  - Set up `pyproject.toml` with the `src/apiedge` package, the `apiedge` CLI (`init`, `migrate`, `run`, `create-admin`), pydantic-settings config and `platformdirs` data dirs.
  - Add SQLAlchemy and Alembic, with SQLite as the default and PostgreSQL optional.
  - Create `console/` as a React + Vite + TS skeleton, built into `src/apiedge/static`.
  - Configure ruff, mypy, bandit, pytest and pre-commit, plus `.env.example`.
  - Add a GitHub Actions CI matrix (Windows, Linux, macOS × Python 3.10–3.12).
  - Write `docs/ARCHITECTURE.md`, a README quick start, LICENSE and NOTICE.
  - Set up hash-locked dependency files in `requirements/` (see T-019).
  > Delivered: `src/apiedge` package with the `apiedge` CLI (`init`, `migrate`, `run [--open]`, `create-admin`, `version`), pydantic-settings (`APIEDGE_*`, `.env.example`), platformdirs data dir, SQLAlchemy 2 + Alembic (SQLite default, PostgreSQL via `APIEDGE_DATABASE_URL` and the `apiedge[postgres]` extra), `/healthz` and `/readyz`, a React + Vite + TS console shell prebuilt into `src/apiedge/static`, ruff, mypy --strict, bandit, pytest and pre-commit, CI on 3 OS x Python 3.10-3.12, `docs/ARCHITECTURE.md`, ADR 0001 and 0002, and a README quick start. Local results: 36 tests pass, all linters clean. Try it: `python scripts/install.py --local --dev --no-start`, then `.venv/Scripts/apiedge run --open` (Windows) or `.venv/bin/apiedge run --open`.
  > Vendor decision: a minimal `users` table (Argon2id hash, `must_change_password`) ships now so `create-admin` and the installer work end to end. T-003 extends it through migrations.

- [x] **T-019** (P1) One-click installer for all OSs
  - Add `install.bat` (Windows, double-click), `install.command` (macOS, double-click) and `install.sh` (Linux), all calling the shared `scripts/install.py`.
  - The installer checks for Python 3.10+ and gives guided installation if it is missing. It creates an isolated venv, downloads and installs dependencies from PyPI using the hash-locked `requirements/runtime.lock`, then installs APIEdge, runs migrations, creates the first admin, optionally registers a service and shortcut, starts the gateway and opens the console.
  - Re-running it repairs or upgrades. It supports `--uninstall`, `--unattended`, `--proxy` and `--index-url`, and writes an install log.
  - Do not commit dependencies (no `vendor/`, wheels or node_modules). The prebuilt console in `src/apiedge/static/` is committed.
  - Add `THIRD_PARTY_LICENSES.md` and a CI license check that fails on GPL, AGPL or SSPL.
  - Add a CI job that runs the installer unattended on Windows, Linux and macOS and smoke-tests the health endpoint.
  - Document installation in the README and the Installation Guide.
  - Depends on: T-001 (do it together with T-001, before any feature work)
  > Delivered: `install.bat` (to `scripts/install.ps1`), `install.command` and `install.sh` (to `scripts/install.sh`), all calling `scripts/install.py`. The installer checks for Python 3.10-3.12 (with OS-specific guidance if missing), creates a venv in the data dir, installs `requirements/build.lock`, `runtime.lock` and APIEdge itself with `--require-hashes` (every download is hash-verified), runs migrations, creates the first admin (prompted, or generated and shown once, never logged), and optionally adds shortcuts and start-at-logon (systemd user unit / launchd agent / Windows Startup folder) before starting APIEdge and opening the console. Re-running it repairs or upgrades. Options: `--uninstall [--purge-data]`, `--unattended`, `--proxy`, `--index-url`. The log is `<data dir>/install.log`. Locks are regenerated with `scripts/update-locks.py`. `scripts/check-licenses.py` maintains `THIRD_PARTY_LICENSES.md` and fails on GPL, AGPL or SSPL. CI runs each OS's installer unattended (install, re-install, uninstall) with a `/healthz` smoke test. Verified locally on Windows: `install.bat --unattended --smoke-test` passes on a fresh venv and on a re-run; the macOS and Linux installers and CI are verified only by the first CI run. No dependencies were ever committed: no `vendor/` directory, wheels or `node_modules`.
  > Fixed 2026-10-31: the first CI run (41226967643) failed on Python 3.11 and 3.12 because the lock files had no environment markers. The locks now carry per-target PEP 508 markers and every target is verified (commit da08eff). CI run 41228102117 passed all 14 jobs: tests on 3 OS x 3 Python versions, the installer smoke test on 3 OSs, quality and console.
  > Vendor decision: Windows "service" means a per-user Startup-folder entry, because a real Windows service needs admin rights or extra tooling. Shortcut and service creation were not run on this machine; the generated files are unit-tested.
  > Vendor decision: `filelock` 4.1.0 is a dev-only dependency (through pip-audit and pre-commit) with 17 CVEs, and the fix needs Python 3.11 or newer. CI audits `runtime.lock` strictly and `dev.lock` with these IDs listed in `requirements/audit-ignore-dev.txt`. `argon2-cffi-bindings` is held at 25.1.0, because 26.1.0 has no macOS x86_64 wheel.

- [x] **T-002** (P1) Security foundation (OWASP baseline)
  - Add security headers and CSP middleware, a CORS allow-list, request body-size limits, CSRF protection for cookie auth, a global error handler with no stack traces in production, and structured JSON logging with secret masking.
  - Add the secrets-encryption helper and an SSRF guard utility for upstream URLs.
  - Create `docs/SECURITY.md` with an OWASP mapping table.
  - Add pip-audit, bandit and CodeQL to CI.
  - Depends on: T-001
  > Delivered: hardening middleware on every console/admin API response (CSP and security headers, HSTS over HTTPS, CORS allow-list closed by default, 2 MiB body limit with 413, CSRF double-submit cookie plus Origin check for cookie-authenticated requests, global error handler returning a generic 500 with a request id, 422 without echoed input), structured JSON logs with secret masking (`APIEDGE_LOG_FORMAT`), AES-256-GCM secrets helper with key rotation (`apiedge.security.crypto`; `apiedge init` creates `<data dir>/secret.key`), SSRF guard for upstream URLs (`apiedge.security.ssrf`), `docs/SECURITY.md` with the OWASP mapping, CodeQL workflow (pip-audit and bandit were already in CI), ADR 0003, and a CodeQL acceptance gate (`scripts/codeql-gate.py`: a finding is accepted only with both an inline `codeql[<rule id>]` justification and a row in the "Accepted findings" table of `docs/SECURITY.md`; currently one accepted finding, the one-time display of a generated first-admin password in `src/apiedge/cli.py`). Try it: `apiedge run`, then `curl -i http://localhost:8080/healthz` to see the headers and CSRF cookie. Settings: `.env.example`, `docs/admin-guide/configuration.md`. Verified: 129 tests pass, ruff, mypy --strict and bandit clean; CI run 41268477655 and CodeQL run 41268477597 green.
  > Vendor decision: `pycryptodome` 4.1.0 rather than `cryptography`, because `cryptography` 49+ has no macOS x86_64 wheel and 48.0.1 has three open advisories that the strict runtime pip-audit gate rejects. T-023 (mTLS/X.509) will revisit this.
  > Vendor decision: the repository is private with no code-scanning upload, so CodeQL runs with `upload: never`, keeps the SARIF as an artifact, and fails the build on any error- or warning-level result.

- [x] **T-003** (P1) Authentication, multi-tenancy and RBAC core
  - Add tenants, users, roles, permissions and role assignments (scoped to a tenant or a product), with built-in roles seeded.
  - Use Argon2id hashing, a password policy, login throttling and lockout, JWT access tokens plus rotating refresh cookies, and TOTP MFA.
  - Add tenant-filtered data access and an RBAC FastAPI dependency.
  - Add an audit log.
  - Write tests for RBAC denial, BOLA (accessing another object by ID) and cross-tenant denial.
  - Depends on: T-002
  > Delivered: admin API under `/api/v1`. Sign-in (`/auth/login`) uses Argon2id and a password policy (12-128 characters, must not contain the username, common passwords rejected), per-IP throttling (429), account lockout, and TOTP MFA (`/auth/mfa/setup`, `enable`, `disable`) with a replay guard and the secret encrypted at rest. Sessions use 15-minute HS256 access JWTs (Bearer header or HttpOnly `apiedge_session` cookie) and rotating refresh cookies (`/auth/refresh`) with reuse detection that revokes the whole session family. Also: `/auth/logout`, `/auth/me`, `/auth/change-password`, a forced password change at first sign-in and after a reset, and all of a user's sessions end on a password change, password reset, role grant or revoke, or deactivation. Tenants (`/tenants`), tenant users (`/tenants/{id}/users`, including unlock, MFA reset and password reset), the `resource:action` permission catalog (`/permissions`), built-in and custom roles (`/tenants/{id}/roles`), and role grants scoped to a tenant or to one product (`/tenants/{id}/users/{uid}/roles`). Anti-escalation rules: you can only grant what you hold and only manage users with no more permissions than you. Tenant-bound sessions filter every ORM query by `tenant_id` and refuse cross-tenant writes (`apiedge.db.tenancy`). Other tenants answer 404. Audit log: `/tenants/{id}/audit`, and `/audit` for SuperAdmins. Migration 0002, ADR 0004, guide `docs/admin-guide/access-control.md`. To try it: `apiedge create-admin`, `apiedge run`, then `POST /api/v1/auth/login`. Verified: 209 tests pass (80 new, covering RBAC denial, BOLA, cross-tenant, escalation, lockout, refresh reuse and MFA); ruff, mypy --strict and bandit are clean; a live sign-in was checked. CI run 41271605207 and CodeQL run 41271605218 are green. No new accepted CodeQL findings: a py/log-injection finding was fixed by keeping user-influenced fields out of application logs.
  > Vendor decision: each user belongs to one tenant, and usernames are unique across the installation. SuperAdmin is a platform flag (`apiedge create-admin`), and the SuperAdmin role cannot be granted through the API. Only SuperAdmins can suspend a tenant. The refresh token is sent only as a cookie. The login throttle is per process until T-026 (Redis). New MIT dependencies: `pyjwt` 2.15.1 and `pyotp` 2.10.0.

- [x] **T-004** (P1) Admin panel UI
  - Add the console login (including MFA) and app shell.
  - Add screens for tenants, users, roles and permissions, the audit log viewer and system settings.
  - Show navigation and actions according to the user's permissions.
  - First run forces a change of the admin password.
  - Depends on: T-003
  > Vendor decision: System settings is a read-only view of the effective configuration (settings are set through `APIEDGE_*` environment variables), served by a new SuperAdmin-only `GET /api/v1/system/settings` that never returns secrets. MFA enrolment shows the secret and `otpauth://` URI as text (no QR code dependency). Console tests use Node's built-in test runner instead of vitest/Playwright to keep the npm dependency set unchanged.
  > Delivered: console admin panel at http://localhost:8080/ - sign-in with MFA step, forced first password change, permission-aware navigation, tenants, users (role grants, reset password, unlock, reset MFA), roles and permissions, audit log, system settings and My account (password, MFA). Try: `apiedge create-admin`, `apiedge run --open`, sign in and change the password. Guide: docs/admin-guide/access-control.md ("Using the console"). CI run 41272785586 and CodeQL run 41272785579 green.

## Phase 2: Products and APIs

- [x] **T-005** (P1) Product management
  - Add CRUD for Products (name, description, owners, lifecycle) through the admin API and console.
  - Depends on: T-004
  > Delivered: products per tenant with name, description, owners (users of the tenant) and a lifecycle (draft, published, deprecated, retired). Admin API `/api/v1/tenants/{id}/products`: list (with a lifecycle filter), create, get, update, `POST .../{pid}/lifecycle` and delete. Each route needs the matching `product:*` permission, held tenant-wide or through a role grant scoped to that product. A product you cannot read answers 404, and one you can read but not change answers 403. Retired products are final and read-only, and only draft or retired products can be deleted. Role grants with `product_id` must name a product of the same tenant, and deleting a product revokes the grants scoped to it. Audit events: `product.create`, `product.update`, `product.lifecycle`, `product.delete`. Console: a Products screen (filter, create, edit, lifecycle buttons, delete), plus a product scope on role grants in the Users screen. Migration 0003 (the products and product_owners tables, and the foreign key on `role_assignments.product_id`), ADR 0005, and the guide `docs/user-guide/products.md`. To try it: `apiedge run`, sign in, then open Products. Verified: 228 pytest pass (14 new, covering RBAC denial, product scope, BOLA, cross-tenant, lifecycle and audit), 18 console tests, and ruff, mypy --strict, bandit, tsc and npm audit are clean. CI run 41311185458 and CodeQL run 41311185568 are green. No CodeQL findings were accepted. Also fixed a tenant-isolation defect found by CI: the tenant filter could be skipped for a session factory created at a recycled memory address (see `docs/SECURITY.md`, Fixed defects).
  > Vendor decision: owners are contacts and do not give access; access comes only from role grants. Product names are unique per tenant, and products have no slug. Lifecycle changes have their own route and permission (`product:publish`). Product-scoped grants created before migration 0003 could not refer to a real product, so the migration removes them.

- [x] **T-006** (P1) API management inside Products
  - Add CRUD for APIs in a Product: base path, version, upstreams (validated by the SSRF guard), routes, lifecycle.
  - Add a no-code form editor.
  - Depends on: T-005
  > Delivered: APIs inside products, each with a name, version, base path (unique in the tenant), description, upstream timeout, weighted upstreams and routes (methods plus a path with `{name}` parameters and an optional final `/*`; overlapping routes are refused), and a lifecycle (draft, published, deprecated, retired). Every upstream URL is checked by the SSRF guard (T-002) under the configured `APIEDGE_SSRF_*` policy when it is saved. Admin API `/api/v1/tenants/{id}/products/{pid}/apis`: list, create, get, update (the upstream and route lists are replaced), `POST .../{aid}/lifecycle` and delete. Each route needs the matching `api:*` permission, held tenant-wide or through a role grant scoped to the product. A product whose APIs you cannot read answers 404, and so does an API that is not in the product named in the path. Publishing needs at least one upstream and one route. Retired APIs are read-only, and only draft or retired APIs can be deleted. A product that still contains APIs can no longer be deleted (the T-005 carry-over). Audit events: `api.create`, `api.update`, `api.lifecycle`, `api.delete`. Console: an **APIs** button on each product opens a panel with the no-code form editor (upstream and route rows, method checkboxes, checks before saving), plus lifecycle and delete buttons. Migration 0004, ADR 0006, and the guide `docs/user-guide/apis.md`. To try it: `apiedge run`, sign in, open Products and click APIs. Verified: 267 pytest pass (39 new or changed, covering RBAC denial, product scope, BOLA, cross-tenant, the SSRF guard, lifecycle, audit and model/migration drift), 23 console tests, and ruff, ruff format, mypy --strict, bandit, the CodeQL gate, tsc and npm audit are clean. CI run 41313351468 and CodeQL run 41313351463 are green. No CodeQL findings were accepted. Also made a flaky T-005 tenancy regression test deterministic (it failed on CI run 41312919574 because of an allocator-dependent precondition).
  > Vendor decision: an API is edited as one document (its upstream and route lists are replaced on save). Base paths are unique within the tenant and may not use the server's own paths (`/api/v1`, `/healthz`, `/readyz`, `/docs`, `/redoc`, `/openapi.json`, `/assets`). Publishing needs at least one upstream and one route, and a published API keeps its base path. The APIs of a retired product are read-only but can still be deprecated and retired, so the product can be emptied and deleted.

- [x] **T-007** (P1) Gateway runtime
  - Use FastAPI/ASGI with httpx to proxy published APIs, with timeouts, retries, load balancing and TLS.
  - Config hot-reloads through Redis pub/sub, or in-process when Redis is absent.
  - The gateway enforces deprecated and retired APIs.
  - Depends on: T-006
  > Delivered: `apiedge run` now also serves the gateway on port 8081 (`APIEDGE_GATEWAY_PORT`): published APIs at `http://127.0.0.1:8081/<tenant slug><base path>/...` with route matching (404/405), weighted round-robin, per-API timeouts (504), safe retries, verified TLS (optional CA bundle), hop-by-hop stripping, `X-Forwarded-*`, body limit (413) and detail-free errors. Deprecated APIs/products carry `Deprecation: true`; retired ones answer 410; drafts 404. Changes hot-reload without restart (in-process events, optional Redis via `APIEDGE_REDIS_URL`, 30 s periodic reload). The SSRF guard is re-applied on every upstream connect (DNS rebinding). Console API list shows the gateway path. Try: publish an API in the console, then `curl http://127.0.0.1:8081/<tenant>/<base path>/...`. Guide: `docs/user-guide/gateway.md`, ADR 0007. CI 41315999469 and CodeQL 41315999489 green.

## Phase 3: No-code / Low-code

- [x] **T-008** (P2) Built-in policies
  - Add API key auth (keys stored hashed), JWT validation, rate limit/quota, header/body transform, CORS, IP allow/deny, cache and mock response policies, each configurable in the console.
  - Depends on: T-007
  > Vendor decision: taken before T-016 (P1) because the P1 tasks T-012, T-023 and T-025 depend on it and the gateway had no authentication or rate limiting yet.
  > Vendor decision: policy chains are stored per API as validated JSON (ordered, optionally per route, stable policy ids); API keys belong to a product until consumers arrive in T-014 (new permissions `apikey:read` / `apikey:manage`); JWT verification uses pycryptodome (no new dependency); rate limits use fixed windows (Redis when configured, per-process fallback); trusted proxies for `X-Forwarded-For` are a gateway setting (`APIEDGE_GATEWAY_TRUSTED_PROXIES`); the response cache is per gateway process; CORS preflights are answered before the rest of the chain (ADR 0009).
  > Delivered: eight built-in policies (API key, JWT, rate limit / quota, header/body transform, CORS, IP allow/deny, cache, mock) run by the gateway as an ordered pipeline that fails closed and records a per-policy decision trace for the packet inspector; analytics shows `key:<name>` / `jwt:<subject>` consumers. Console: **Products > APIs > Policies** (form-based editor: add, reorder, enable, limit to routes) and **API keys** (create, shown once, revoke). Admin API `GET/PUT .../apis/{id}/policies` (`policy:read` / `policy:update`) and `.../products/{id}/api-keys` (`apikey:read` / `apikey:manage`), audited. Try: add an API key policy to a published API, create a key, then `curl -H "x-api-key: <key>" http://127.0.0.1:8081/<tenant>/<base path>/...`. Guide: `docs/user-guide/policies.md`, ADR 0009. CI 41362042193 and CodeQL 41362042239 green.

- [ ] **T-009** (P2) Visual policy flow builder
  - Add a drag-and-drop editor (React Flow) for composing a route's policy chain.
  - Depends on: T-008

- [ ] **T-010** (P2) Low-code script policy
  - Run Restricted Python in an isolated worker with CPU, time and memory limits and no network or filesystem access.
  - Add a Monaco editor and a test runner in the console.
  - Write security tests that try to escape the sandbox.
  - Depends on: T-009

- [ ] **T-011** (P2) OpenAPI import/export
  - Import an OpenAPI 3 spec to create an API and its routes, and export an API as OpenAPI.
  - Depends on: T-006

## Phase 4: Debugging and Analytics

- [x] **T-012** (P1) Packet inspector
  - Capture traffic per API, route or consumer, opt-in and time-boxed, with ring-buffer and retention limits.
  - Record full exchanges with timings and a policy-by-policy trace.
  - Add a live view (WebSocket/SSE), filters, a detail pane, HAR export and replay (replay goes through the SSRF guard).
  - Mask sensitive data by default; unmasked viewing needs a separate permission and is audit-logged.
  - Write the Inspector Guide.
  - Depends on: T-008
  > Vendor decision: captures are stored in the database (encrypted with the secrets key, so capture needs the master key) so they work with separate gateway and console processes; masking happens when data is read, so the unmasked view is possible with `inspector:unmask`; the live view uses Server-Sent Events; replay goes to the API's current upstream (not through the gateway again) through the SSRF guard and needs `inspector:capture`; requests that match no route of the API are not captured (ADR 0010).
  > Done: CI run 41366973745 and CodeQL run 41366973700 green on 24e9ab6 (438 pytest, 37 console tests).

- [x] **T-013** (P1) Analytics interface for admins
  - Collect per-request metrics and aggregate them into time buckets.
  - Add dashboards for traffic, p50/p95/p99 latency, error rate and status codes, with top APIs and consumers and time-range and API/consumer filters.
  - Add CSV export and a Prometheus `/metrics` endpoint.
  - Write the Analytics Guide.
  - Depends on: T-007
  > Vendor decision: the error rate counts 4xx and 5xx responses (both are also shown separately). Until consumers exist (T-014) all traffic is attributed to the anonymous consumer. `/metrics` is served on the console port and is off unless `APIEDGE_METRICS_TOKEN` is set (bearer token), because the metrics cover every tenant.
  > Delivered: the gateway measures every API request (status, latency, bytes, route, method, consumer) into per-minute aggregates with latency histograms, flushed every 10 s to the analytics tables (30-day retention). Console **Analytics** page: time range (15 min to 30 days), requests, error rate, 4xx/5xx, p50/p95/p99, data in/out, traffic chart with errors and p95, top APIs, status codes and top consumers with click-to-filter, CSV export (audited). Admin API `GET /api/v1/tenants/{id}/analytics/summary` and `.../export.csv` (`analytics:view`, tenant-wide or per product). Prometheus `GET /metrics` with `APIEDGE_METRICS_TOKEN`. Try: send traffic through the gateway, then open Analytics in the console. Guide: `docs/user-guide/analytics.md`, ADR 0008. CI 41318323346 and CodeQL 41318323315 green.

## Phase 5: Consumers

- [ ] **T-014** (P2) Plans, consumers and subscriptions
  - Depends on: T-008

- [ ] **T-015** (P3) Developer portal
  - Depends on: T-014

## Phase 6: Shipping

- [x] **T-016** (P1) Cross-platform packaging and release
  - Build the wheel with the console bundled inside.
  - Package the one-click installer as a downloadable zip per OS on GitHub Releases.
  - Build a multi-arch Docker image with docker-compose, and a Kubernetes Helm chart.
  - Generate the SBOM (CycloneDX), checksums and signatures.
  - Add a GitHub Actions release workflow that publishes to GitHub Releases on a version tag.
  - Smoke-test the install on all three OSs in CI.
  - Depends on: T-007
  > Vendor decision: publishing stays off until T-031: the release workflow builds and tests every artifact on each `v*` tag and keeps them as a workflow artifact; a draft GitHub release is created only when the repository variable `APIEDGE_PUBLISH_RELEASE` is `true`. Nothing is pushed to PyPI or a container registry. Signing is a GPG signature of `SHA256SUMS`, done only when the `APIEDGE_RELEASE_GPG_KEY` / `APIEDGE_RELEASE_GPG_PASSPHRASE` secrets exist (ADR 0011).
  > Vendor decision: the CycloneDX SBOM is generated by `scripts/build-release.py` from `runtime.lock` and the console's production npm packages, instead of adding a CycloneDX tool to the dev lock. Compose uses Valkey (BSD) rather than Redis 8 for licensing reasons. The PostgreSQL driver is installed only in the compose-built image from a hash-pinned list (`packaging/docker/postgres-driver.txt`, build arg `APIEDGE_WITH_POSTGRES=1`); it is not in `runtime.lock` (VP-002 still open). The Helm chart runs one replica (SQLite on a ReadWriteOnce volume); HA is T-026.
  > Delivered: `scripts/build-release.py` builds the wheel (console included), installer zips for Windows, macOS and Linux, a CycloneDX SBOM, the Helm chart and `SHA256SUMS`; `.github/workflows/release.yml` runs on `v*` tags and packaging changes and tests the artifacts on all three OSs (bundle unzipped and installed unattended with a `/healthz` check, re-run and uninstall; wheel in a clean venv on Python 3.10 and 3.12), builds the linux/amd64 + linux/arm64 image and smoke-tests `docker compose` (APIEdge, PostgreSQL, Valkey) including a sign-in; `helm lint`/`template`. Publishing to GitHub Releases is wired but opt-in (draft only, variable `APIEDGE_PUBLISH_RELEASE`); signing waits for the customer's key (T-031). Try: `docker compose up -d --build` with `POSTGRES_PASSWORD` set, or download the `apiedge-release` artifact of a Release run. Guides: `docs/installation.md` sections 1 and 8 to 11, `docs/releasing.md`, ADR 0011. Release run 41370507762, CI 41370507822 and CodeQL 41370507748 green on 81499e7.

- [x] **T-017** (P1) Complete documentation set
  - Write the Installation Guide (per OS, one-click installer, Docker, pip), Administrator Guide, User Guide (no-code and low-code), Inspector Guide, Analytics Guide, the API reference (OpenAPI plus rendered HTML), Security and OWASP mapping, Upgrade notes, and a Troubleshooting guide.
  - Publish the docs site with MkDocs, built in CI and shipped in the release bundle.
  - Depends on: T-016
  > Vendor decision: MkDocs 1.6.1 with its built-in theme only, pinned in a separate `requirements/docs.lock` used by CI and release builds (never by the installer); the site is built with `--strict` and works offline (ADR 0012). The rendered HTML API reference is a page of that site, generated from the application's OpenAPI document by `scripts/export-openapi.py`; each operation's required permission is now part of the OpenAPI document (`x-apiedge-access`).
  > Vendor decision: low-code is documented as available only as far as it exists (transform and mock policies, the admin API); the script policy, flow builder and OpenAPI import are marked upcoming. The missing secrets re-encryption command is documented honestly and proposed as VP-008.
  > Delivered: an offline MkDocs documentation site (`mkdocs build --strict`; shipped in release builds as `apiedge-<version>-docs.zip`). It includes Installation Guide, Upgrade notes, Administrator Guide (configuration, access control, operations), User Guide (first-API tutorial, low-code status), Packet Inspector and Analytics Guides, Admin API guide and a reference generated from the app (`scripts/export-openapi.py`, `docs/api/`), Troubleshooting, Security, Architecture and ADRs. The CI `docs` job and the tests catch drift in settings, links, navigation and the API reference. Try it: build with `requirements/docs.lock` (see docs/releasing.md) and open `build/site/index.html`. Green: CI run 41472434372, CodeQL run 41472434325, Release run 41472434391.

- [x] **T-018** (P1) Security verification before release
  - Run an OWASP ZAP baseline scan against the console and the gateway in CI.
  - Review the ASVS L2 checklist.
  - Fix every high and critical finding, and record the results in `docs/SECURITY.md`.
  - Depends on: T-012, T-013, T-016
  > Delivered: `docs/security-verification.md` (findings F-01 to F-11 with severities and resolutions; verdicts for every OWASP Top 10, API Top 10 and ASVS L2 chapter). CI now runs a DAST smoke pass (`scripts/dast-smoke.py`, 64 checks) and an OWASP ZAP baseline against the running console and gateway, and a Grype scan of both container images; `scripts/scan-gate.py` fails on ZAP Medium/High and Grype High/Critical unless accepted in `docs/SECURITY.md` with a justification and a review date (at most 180 days). `tests/integration/test_route_access_matrix.py` checks 401/403/404 denials on all 61 admin operations. Fixed: forwarded headers trusted from 127.0.0.1 (F-01, new `APIEDGE_TRUSTED_PROXIES`), missing COEP header (F-10). No critical finding; no high finding in APIEdge code or Python/npm dependencies. Try: `pytest tests/integration/test_route_access_matrix.py`, or `python scripts/dast-smoke.py --password-file <file>` against a disposable instance.
  > Vendor decision: 18 High CVEs in Debian base-image packages have no fixed version upstream; each was reviewed as unreachable and accepted with review date 2027-01-31 rather than failing every build. Semgrep was not added because its CLI is LGPL-2.1 (CodeQL and bandit cover SAST). The console keeps trusting 127.0.0.1 as a proxy by default for compatibility; the gateway no longer does (see upgrade notes). Open items: native TLS (T-023), MFA enforcement (VP-009), psycopg LGPL-3.0 in the PostgreSQL image (VP-002), re-encryption (VP-008).
  > Done: CI 41480270095 and CodeQL 41480270195 green on 9413970; Release 41479170250 green on 650565e.
  > Customer decision (2026-11-05): the 18 accepted base-image CVE rows stay accepted until their review date 2027-01-31.

- [x] **T-032** (P1) Supported Python range 3.11-3.13 (from VP-001)
  - Move the supported Python range from 3.10-3.12 to 3.11-3.13: `pyproject.toml`, hash locks for every OS x Python 3.11-3.13, the CI test matrix, the installer checks and the documentation.
  - Depends on: T-019
  > Customer decision (2026-11-05): VP-001 accepted; Python 3.10 is end of life since October 2026.
  > Delivered: supported interpreters are CPython 3.11, 3.12 and 3.13 (`requires-python >=3.11,<3.14`); hash locks regenerated for 15 targets (Windows, Linux x86_64/aarch64, macOS x86_64/arm64 x 3.11-3.13); CI tests 3 OSs x 3 Pythons, the release wheel smoke test runs on 3.11 and 3.13; the installers accept only 3.11-3.13; filelock 4.2.9 closes the dev-only advisories (F-07). ADR 0014; upgrade note for hosts with only Python 3.10. Done: CI 42083896291 (macOS installer job re-run after a runner-acquisition failure), CodeQL 42083896247 and Release 42083895797 green on abdca7f.

- [x] **T-033** (P2) Permissively licensed PostgreSQL driver (from VP-002)
  - Use pg8000 (BSD-3-Clause, pure Python) as the PostgreSQL driver in `runtime.lock` (`postgresql+pg8000://` URLs) and remove psycopg (LGPL-3.0) from the Docker image and `packaging/docker/postgres-driver.txt`; update compose, the documentation, `docs/SECURITY.md` (close the F-05 license finding) and `THIRD_PARTY_LICENSES.md`.
  - Verify PostgreSQL through the compose smoke job of the Release workflow.
  - Depends on: T-016
  > Customer decision (2026-11-05): VP-002 resolved in favour of pg8000.
  > Delivered: pg8000 1.31.6 (with scramp, asn1crypto, python-dateutil, tzdata; all permissive) in `runtime.lock` and `pyproject.toml`; psycopg, `packaging/docker/postgres-driver.txt`, the `APIEDGE_WITH_POSTGRES` build argument and the `postgres` extra removed, so there is one image and the CI image scan has one variant. `postgresql://`, `postgres://` and `postgresql+psycopg://` URLs select pg8000, so existing configurations keep working. F-05 closed. Try: `docker compose up -d --build` with `POSTGRES_PASSWORD` set.
  > Done: Release 42089494361 (docker compose smoke test with PostgreSQL 17 through pg8000, sign-in included), CI 42089494293 and CodeQL 42089494178 green on 9cac60a.

- [ ] **T-034** (P1) Secrets re-encryption command (from VP-008)
  - Add `apiedge rotate-secrets`: re-encrypt every value encrypted at rest (MFA secrets, policy secrets, keystore keys, stored captures and other encrypted columns) with the current master key, so an old key can be removed from `APIEDGE_SECRET_KEY_PREVIOUS` after a rotation. Report what was re-encrypted, be safe to re-run, and document the rotation procedure.
  - Depends on: T-002
  > Customer decision (2026-11-05): VP-008 accepted as P1.

## Phase 7: Enterprise feature parity (IBM API Connect / DataPower and leading gateways)

- [x] **T-020** (P1) Feature parity matrix
  - Research the capabilities of IBM API Connect / DataPower, Kong, Apigee, Azure APIM, AWS API Gateway, MuleSoft, WSO2, Tyk and Gravitee.
  - Write `docs/FEATURE_MATRIX.md` (feature → which gateways have it → APIEdge task and status).
  - Propose tasks for any gaps not covered below in Vendor Proposals.
  - Depends on: T-001
  > Delivered: `docs/FEATURE_MATRIX.md` lists 103 capabilities in 11 areas (lifecycle, console and access control, policies, security, protocols, traffic, consumers, operations, observability, testing, AI gateway). Each row shows which of the nine reference gateway families offer it (offered, partial, not offered) and the APIEdge status with its task: 29 done, 11 partial, 58 planned, 5 proposed. Statuses were checked against the code, not task titles. Gaps no task covers are proposed as VP-003 to VP-007. Linked from the README.
  > Vendor decision: reference marks are a coarse summary of public product documentation as of late 2026 and are meant for prioritization, not procurement. Capabilities are described in our own words only. APIEdge-specific hardening (SSRF guard, encrypted captures, hash-locked dependencies) is listed in its own section without reference columns.
  > Done: CI run 41368222524 and CodeQL run 41368222507 green on 543bcd7.

- [ ] **T-021** (P1) Catalogs, environments and API lifecycle governance
  - Add catalogs/environments (dev, test, prod) with promotion, versions and revisions, approval workflows, API linting rules, change history and diff.
  - Depends on: T-006

- [ ] **T-022** (P1) Assembly policies
  - Add invoke, proxy, switch, operation-switch, if, throw, catch/error flows, set-variable, visual data map, parse, validate (JSON Schema, XML Schema, OpenAPI), redact, log, XSLT, and JSON↔XML conversion, all usable in the flow builder.
  - Depends on: T-009

- [~] **T-023** (P1) Advanced security
  - Add a built-in OAuth 2.0 authorization server (client credentials, authorization code with PKCE, refresh, introspection, revocation), OIDC, and JWT generation.
  - Add basic auth with LDAP/AD, mTLS, and HMAC signatures.
  - Add JSON and XML threat protection, WAF rules, bot and IP reputation.
  - Add management of TLS profiles, keystores and truststores, and secrets-vault integration (HashiCorp Vault).
  - Add console SSO (OIDC, SAML, LDAP).
  - Depends on: T-008
  > Verified: slices 1 and 1b (with the follow-up fixes for linear PEM matching and the runtime image's Debian security updates) are green on GitHub: CI 42071664370 and CodeQL 42071664315 on 4a17892. Slice 2 (OAuth 2.0 / OIDC / JWT generation): CI 42089494293, CodeQL 42089494178 and Release 42089494361 green on 9cac60a.
  > Vendor decision (slice 2): end users sign in at the authorize step with the tenant's console users (customer decision) through a pluggable `UserRegistry`; there is no consent screen (clients are registered by tenant administrators, so they are first-party); PKCE S256 is required for every authorization code request; the token endpoint has no CORS yet (browser apps need a backend-for-frontend); the JWT policy's built-in issuer validates signatures locally and does not consult access-token revocation, so access tokens default to 10 minutes. New setting `APIEDGE_GATEWAY_PUBLIC_URL` defines the issuer; API base paths may no longer start with `/oauth2`. LDAP waits for VP-010 (the only maintained pure-Python client, ldap3, is LGPL-3.0).
  > Vendor decision: delivered in slices, each committed separately. Listener certificates are operator files set in `APIEDGE_TLS_*` / `APIEDGE_GATEWAY_TLS_*` (platform configuration); keystores and truststores are tenant data. X.509 handling is our own bounded DER reader on the already-locked pycryptodome, because `cryptography` cannot be locked for every supported platform (ADR 0013). An `mtls` policy always checks the client certificate against a truststore of the API's own tenant, on top of the listener's platform CA bundle, so one tenant's client certificates cannot open another tenant's APIs. Revocation (CRL/OCSP) is not checked.
  > In progress - slice 1 delivered: native TLS on the console and gateway listeners (closes F-02), `apiedge tls self-signed`, tenant truststores and keystores (admin API `/tenants/{id}/tls/...`, permissions `tls:read` / `tls:manage`, console page TLS & certificates), the `mtls` client-certificate policy (gateway listener or trusted proxy header). Try: `apiedge tls self-signed --out-dir tls`, set `APIEDGE_TLS_CERT_FILE` / `APIEDGE_TLS_KEY_FILE` (and the `APIEDGE_GATEWAY_TLS_*` pair), `apiedge run`, open https://localhost:8080/. Slice 1b delivered: upstream TLS profiles (`/tenants/{id}/tls/profiles`, migration 0009; console TLS & certificates and the API form's Upstream TLS profile) with tenant truststores and keystore client certificates for upstream mTLS. Slice 2 delivered: a built-in OAuth 2.0 authorization server and OpenID Connect provider per tenant on the gateway (`/<tenant>/oauth2/`: discovery, JWKS, authorize, token, introspect, revoke, userinfo; client credentials, authorization code with mandatory PKCE S256, rotating refresh tokens with reuse detection; RS256 access and ID tokens from per-tenant encrypted signing keys with rotation), admin API `/tenants/{id}/oauth/...` (`oauth:read` / `oauth:manage`, migration 0010), console page OAuth & OIDC, and the JWT policy's Built-in issuer option (ADR 0015, `docs/user-guide/oauth.md`). Try: register a client on OAuth & OIDC, then `curl -u <client id>:<secret> -d grant_type=client_credentials http://localhost:8081/<tenant>/oauth2/token`. Remaining: basic auth with LDAP/AD, HMAC signatures, JSON/XML threat protection, WAF rules, bot and IP reputation, HashiCorp Vault integration, console SSO.

- [ ] **T-024** (P2) Multi-protocol support
  - Support SOAP/WSDL import, SOAP↔REST conversion and WS-Security.
  - Support GraphQL (proxy, schema, depth and cost limits) and gRPC (with JSON transcoding).
  - Support WebSocket and SSE.
  - Support event and async APIs (Kafka, MQTT, AMQP, IBM MQ connectors, AsyncAPI import).
  - Depends on: T-022

- [ ] **T-025** (P1) Advanced traffic management
  - Add load-balancing algorithms, active and passive health checks, a circuit breaker, and retries with backoff.
  - Add canary, weighted and blue-green routing, and traffic mirroring.
  - Add service discovery (DNS SRV, Consul, Kubernetes).
  - Add response caching with invalidation, compression, spike arrest, quotas and concurrency limits.
  - Depends on: T-008

- [ ] **T-026** (P1) HA, clustering and distributed gateways
  - Run multiple gateway nodes with config sync, and remote/federated gateways managed by one control plane.
  - Support rolling upgrades and backup and restore.
  - Add declarative YAML config (GitOps) and an `apiedge` CLI for import and export.
  - Depends on: T-007

- [ ] **T-027** (P2) Consumer organizations and monetization
  - Add consumer organizations, app registration, credential rotation and plan approval workflows.
  - Add usage metering and billing export.
  - Depends on: T-014

- [ ] **T-028** (P2) Observability integrations
  - Add OpenTelemetry tracing, log shipping (syslog, Splunk, ELK), alerting rules (email, webhook, Slack) and SLA monitoring.
  - Depends on: T-013

- [ ] **T-029** (P2) API testing and service virtualization
  - Add built-in API test suites, contract tests against OpenAPI, and mock and virtual services.
  - Depends on: T-011

- [ ] **T-030** (P3) AI gateway
  - Add an LLM provider proxy, token-based rate limits and quotas, a prompt guard with PII redaction, a semantic cache, and model routing and fallback.
  - Depends on: T-025

- [ ] **T-035** (P2) MFA enforcement policy (from VP-009)
  - Require TOTP enrolment for SuperAdmins by default (platform setting, configurable), and optionally for all users of a tenant (tenant setting), with a grace period at first sign-in. Closes finding F-03.
  - Depends on: T-003
  > Customer decision (2026-11-05): VP-009 accepted; MFA is required for SuperAdmin by default and the requirement is configurable.

- [ ] **T-036** (P2) Custom domains and host-based routing (from VP-003)
  - Let a tenant attach its own host names to APIs, with a TLS certificate per domain (SNI), in addition to `/<tenant slug><base path>` on the shared listener.
  - Depends on: T-023
  > Customer decision (2026-11-05): VP-003 accepted as P2.

- [ ] **T-037** (P2) Upstream authentication (from VP-004)
  - Inject backend credentials (basic, static bearer, OAuth 2.0 client-credentials tokens fetched and cached by the gateway, signed requests) from encrypted secrets, so backend credentials never travel in client requests or plain transform headers.
  - Depends on: T-008
  > Customer decision (2026-11-05): VP-004 accepted as P2.

- [ ] **T-038** (P3) Custom policy plug-in SDK (from VP-005)
  - A documented SDK for packaged custom Python policies, installed by an administrator, versioned and listed in the flow builder; complements the sandboxed script policy of T-010.
  - Depends on: T-009, T-010
  > Customer decision (2026-11-05): VP-005 accepted as P3.

- [ ] **T-039** (P3) HTTP/2 between clients and the gateway (from VP-006)
  - Serve HTTP/2 on the gateway listener (the current ASGI server speaks HTTP/1.1); prerequisite for native gRPC in T-024.
  - Depends on: T-007
  > Customer decision (2026-11-05): VP-006 accepted as P3.

- [ ] **T-040** (P3) Kubernetes ingress / Gateway API and a Terraform provider (from VP-007)
  - Kubernetes ingress controller or Gateway API support, and a Terraform provider for the admin API, beyond the Helm chart of T-016.
  - Depends on: T-016, T-026
  > Customer decision (2026-11-05): VP-007 accepted as P3.

## Phase 8: Public release

- [~] **T-031** (P1) Make the GitHub repository public
  > Customer decision (2026-11-04): the repository was made public ahead of the other tasks so CI can run on GitHub-hosted runners. Before switching, the full history was scanned for secrets and personal data (none found). The remaining T-031 items (public-project files, branch protection, code scanning, Dependabot, first release) stay open.
  - Do this last, once every other task in this file is `[x]`.
  - Pre-publication checks:
    - scan the full git history for secrets (gitleaks or similar) and fix anything found;
    - confirm no internal or personal data is in the repo;
    - confirm LICENSE (Apache-2.0), NOTICE and THIRD_PARTY_LICENSES are complete;
    - the README is complete, with screenshots;
    - CI is green on all three OSs.
  - Add public-project files: `SECURITY.md` (vulnerability disclosure policy), `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and issue and pull-request templates.
  - Then set the repository to **public** (`gh repo edit --visibility public`).
  - After it is public:
    - enable CodeQL result upload to GitHub code scanning, Dependabot alerts and updates, and secret scanning with push protection;
    - protect `main` (pull requests and passing checks required);
    - set the repository description, topics and website;
    - publish the first GitHub Release.
  - Depends on: every other task (T-001 to T-030)

---

## Vendor Proposals

The development team writes suggested improvements here. Move one into a phase above to approve it.

- **VP-001** (P1, proposed 2026-10-31) Move the supported Python range to 3.11-3.13. Python 3.10 reached end of life in October 2026, and it blocks security fixes (for example filelock 4.2.1 needs Python 3.11 or newer). The customer would need to update `docs/PROJECT_GUIDE.md`, which currently says "Python 3.10-3.12".
  > Customer decision (2026-11-05): accepted; moved to T-032.
- **VP-002** (P2, proposed 2026-10-31) Add the PostgreSQL driver (`psycopg[binary]`) to the hash-locked runtime set, or to an optional `postgres.lock`, so the installer can set up PostgreSQL deployments without unpinned downloads.
  > Customer decision (2026-11-05): resolved with pg8000 (BSD-3-Clause) in runtime.lock instead of psycopg (LGPL-3.0); moved to T-033.
- **VP-003** (P2, proposed 2026-11-02, from T-020) Custom domains and host-based routing: let a tenant attach its own host names to APIs, with a TLS certificate per domain (SNI), instead of only `/<tenant slug><base path>` on the shared listener.
  > Customer decision (2026-11-05): accepted (P2); moved to T-036.
- **VP-004** (P1, proposed 2026-11-02, from T-020) Upstream authentication: inject backend credentials (basic, static bearer, OAuth 2.0 client-credentials tokens fetched and cached by the gateway, signed requests) from encrypted secrets, so backend credentials never live in client requests or plain transform headers.
  > Customer decision (2026-11-05): accepted (P2); moved to T-037.
- **VP-005** (P3, proposed 2026-11-02, from T-020) A documented plug-in SDK for packaged custom Python policies (installed by an administrator, versioned, listed in the flow builder), complementing the sandboxed script policy of T-010.
  > Customer decision (2026-11-05): accepted (P3); moved to T-038.
- **VP-006** (P2, proposed 2026-11-02, from T-020) HTTP/2 between clients and the gateway (the current ASGI server speaks HTTP/1.1). Native gRPC in T-024 needs it.
  > Customer decision (2026-11-05): accepted (P3); moved to T-039.
- **VP-007** (P3, proposed 2026-11-02, from T-020) Kubernetes ingress controller / Gateway API support and a Terraform provider for the admin API, beyond the Helm chart of T-016.
  > Customer decision (2026-11-05): accepted (P3); moved to T-040.
- **VP-008** (P1, proposed 2026-11-02, from T-017) A secrets-key re-encryption command (`apiedge rotate-secrets`): re-encrypt MFA secrets, policy secrets and stored captures with the current master key, so an old key can be removed from `APIEDGE_SECRET_KEY_PREVIOUS` after a rotation. Today the old key must be kept as long as data encrypted with it exists.
  > Customer decision (2026-11-05): accepted (P1); moved to T-034.
- **VP-009** (P2, proposed 2026-11-02, from T-018) An MFA enforcement policy: require TOTP enrolment for SuperAdmins (platform setting) and optionally for all users of a tenant (tenant setting), with a grace period at first sign-in. Today MFA is optional for every account (finding F-03 in `docs/security-verification.md`). Changes the sign-in flow, so it needs a customer decision.
  > Customer decision (2026-11-05): accepted; MFA required for SuperAdmin by default, configurable; moved to T-035.
- **VP-010** (P1, proposed 2026-11-06, from T-023) LDAP / Active Directory client for basic auth with LDAP, the authorization server's user registry and console SSO. The only maintained pure-Python LDAP client, `ldap3`, is LGPL-3.0; `python-ldap` (permissive) publishes no wheels and needs a C compiler and OpenLDAP headers; `bonsai` (MIT) has Windows/macOS wheels but needs the system libldap on Linux. Options: (a) APIEdge's own minimal LDAPv3 client on the standard library (simple bind and search over LDAPS or StartTLS, BER encoding written and fuzz-tested in-house, about the size of the X.509 reader of ADR 0013) - recommended; (b) accept `ldap3` as an LGPL-3.0 dependency used unmodified (needs a license-policy exception); (c) `bonsai` with a documented libldap prerequisite on Linux. Until decided, the LDAP part of T-023 is not started; the user registry interface is ready for it.
