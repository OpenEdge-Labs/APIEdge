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

- [ ] **T-002** (P1) Security foundation (OWASP baseline)
  - Add security headers and CSP middleware, a CORS allow-list, request body-size limits, CSRF protection for cookie auth, a global error handler with no stack traces in production, and structured JSON logging with secret masking.
  - Add the secrets-encryption helper and an SSRF guard utility for upstream URLs.
  - Create `docs/SECURITY.md` with an OWASP mapping table.
  - Add pip-audit, bandit and CodeQL to CI.
  - Depends on: T-001

- [ ] **T-003** (P1) Authentication, multi-tenancy and RBAC core
  - Add tenants, users, roles, permissions and role assignments (scoped to a tenant or a product), with built-in roles seeded.
  - Use Argon2id hashing, a password policy, login throttling and lockout, JWT access tokens plus rotating refresh cookies, and TOTP MFA.
  - Add tenant-filtered data access and an RBAC FastAPI dependency.
  - Add an audit log.
  - Write tests for RBAC denial, BOLA (accessing another object by ID) and cross-tenant denial.
  - Depends on: T-002

- [ ] **T-004** (P1) Admin panel UI
  - Add the console login (including MFA) and app shell.
  - Add screens for tenants, users, roles and permissions, the audit log viewer and system settings.
  - Show navigation and actions according to the user's permissions.
  - First run forces a change of the admin password.
  - Depends on: T-003

## Phase 2: Products and APIs

- [ ] **T-005** (P1) Product management
  - Add CRUD for Products (name, description, owners, lifecycle) through the admin API and console.
  - Depends on: T-004

- [ ] **T-006** (P1) API management inside Products
  - Add CRUD for APIs in a Product: base path, version, upstreams (validated by the SSRF guard), routes, lifecycle.
  - Add a no-code form editor.
  - Depends on: T-005

- [ ] **T-007** (P1) Gateway runtime
  - Use FastAPI/ASGI with httpx to proxy published APIs, with timeouts, retries, load balancing and TLS.
  - Config hot-reloads through Redis pub/sub, or in-process when Redis is absent.
  - The gateway enforces deprecated and retired APIs.
  - Depends on: T-006

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

- [ ] **T-013** (P1) Analytics interface for admins
  - Collect per-request metrics and aggregate them into time buckets.
  - Add dashboards for traffic, p50/p95/p99 latency, error rate and status codes, with top APIs and consumers and time-range and API/consumer filters.
  - Add CSV export and a Prometheus `/metrics` endpoint.
  - Write the Analytics Guide.
  - Depends on: T-007

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

---

## Vendor Proposals

The development team writes suggested improvements here. Move one into a phase above to approve it.

- **VP-001** (P1, proposed 2026-10-31) Move the supported Python range to 3.11-3.13. Python 3.10 reached end of life in October 2026, and it blocks security fixes (for example filelock 4.2.1 needs Python 3.11 or newer). The customer would need to update `docs/PROJECT_GUIDE.md`, which currently says "Python 3.10-3.12".
- **VP-002** (P2, proposed 2026-10-31) Add the PostgreSQL driver (`psycopg[binary]`) to the hash-locked runtime set, or to an optional `postgres.lock`, so the installer can set up PostgreSQL deployments without unpinned downloads.
