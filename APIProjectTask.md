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

- [ ] **T-008** (P2) Built-in policies
  - Add API key auth (keys stored hashed), JWT validation, rate limit/quota, header/body transform, CORS, IP allow/deny, cache and mock response policies, each configurable in the console.
  - Depends on: T-007

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

- [ ] **T-012** (P1) Packet inspector
  - Capture traffic per API, route or consumer, opt-in and time-boxed, with ring-buffer and retention limits.
  - Record full exchanges with timings and a policy-by-policy trace.
  - Add a live view (WebSocket/SSE), filters, a detail pane, HAR export and replay (replay goes through the SSRF guard).
  - Mask sensitive data by default; unmasked viewing needs a separate permission and is audit-logged.
  - Write the Inspector Guide.
  - Depends on: T-008

- [~] **T-013** (P1) Analytics interface for admins
  - Collect per-request metrics and aggregate them into time buckets.
  - Add dashboards for traffic, p50/p95/p99 latency, error rate and status codes, with top APIs and consumers and time-range and API/consumer filters.
  - Add CSV export and a Prometheus `/metrics` endpoint.
  - Write the Analytics Guide.
  - Depends on: T-007
  > Vendor decision: the error rate counts 4xx and 5xx responses (both are also shown separately). Until consumers exist (T-014) all traffic is attributed to the anonymous consumer. `/metrics` is served on the console port and is off unless `APIEDGE_METRICS_TOKEN` is set (bearer token), because the metrics cover every tenant.

## Phase 5: Consumers

- [ ] **T-014** (P2) Plans, consumers and subscriptions
  - Depends on: T-008

- [ ] **T-015** (P3) Developer portal
  - Depends on: T-014

## Phase 6: Shipping

- [ ] **T-016** (P1) Cross-platform packaging and release
  - Build the wheel with the console bundled inside.
  - Package the one-click installer as a downloadable zip per OS on GitHub Releases.
  - Build a multi-arch Docker image with docker-compose, and a Kubernetes Helm chart.
  - Generate the SBOM (CycloneDX), checksums and signatures.
  - Add a GitHub Actions release workflow that publishes to GitHub Releases on a version tag.
  - Smoke-test the install on all three OSs in CI.
  - Depends on: T-007

- [ ] **T-017** (P1) Complete documentation set
  - Write the Installation Guide (per OS, one-click installer, Docker, pip), Administrator Guide, User Guide (no-code and low-code), Inspector Guide, Analytics Guide, the API reference (OpenAPI plus rendered HTML), Security and OWASP mapping, Upgrade notes, and a Troubleshooting guide.
  - Publish the docs site with MkDocs, built in CI and shipped in the release bundle.
  - Depends on: T-016

- [ ] **T-018** (P1) Security verification before release
  - Run an OWASP ZAP baseline scan against the console and the gateway in CI.
  - Review the ASVS L2 checklist.
  - Fix every high and critical finding, and record the results in `docs/SECURITY.md`.
  - Depends on: T-012, T-013, T-016

## Phase 7: Enterprise feature parity (IBM API Connect / DataPower and leading gateways)

- [ ] **T-020** (P1) Feature parity matrix
  - Research the capabilities of IBM API Connect / DataPower, Kong, Apigee, Azure APIM, AWS API Gateway, MuleSoft, WSO2, Tyk and Gravitee.
  - Write `docs/FEATURE_MATRIX.md` (feature → which gateways have it → APIEdge task and status).
  - Propose tasks for any gaps not covered below in Vendor Proposals.
  - Depends on: T-001

- [ ] **T-021** (P1) Catalogs, environments and API lifecycle governance
  - Add catalogs/environments (dev, test, prod) with promotion, versions and revisions, approval workflows, API linting rules, change history and diff.
  - Depends on: T-006

- [ ] **T-022** (P1) Assembly policies
  - Add invoke, proxy, switch, operation-switch, if, throw, catch/error flows, set-variable, visual data map, parse, validate (JSON Schema, XML Schema, OpenAPI), redact, log, XSLT, and JSON↔XML conversion, all usable in the flow builder.
  - Depends on: T-009

- [ ] **T-023** (P1) Advanced security
  - Add a built-in OAuth 2.0 authorization server (client credentials, authorization code with PKCE, refresh, introspection, revocation), OIDC, and JWT generation.
  - Add basic auth with LDAP/AD, mTLS, and HMAC signatures.
  - Add JSON and XML threat protection, WAF rules, bot and IP reputation.
  - Add management of TLS profiles, keystores and truststores, and secrets-vault integration (HashiCorp Vault).
  - Add console SSO (OIDC, SAML, LDAP).
  - Depends on: T-008

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

## Phase 8: Public release

- [ ] **T-031** (P1) Make the GitHub repository public
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
- **VP-002** (P2, proposed 2026-10-31) Add the PostgreSQL driver (`psycopg[binary]`) to the hash-locked runtime set, or to an optional `postgres.lock`, so the installer can set up PostgreSQL deployments without unpinned downloads.
