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
- **G-7 Bundled dependencies:** every third-party package (Python wheels for all supported OSs and Python versions, dev tools, console npm packages and the prebuilt console) is committed to the repo. After `git clone` or `git pull`, APIEdge installs and runs with **no downloads**; Python is the only prerequisite. No Git LFS. Details are in `docs/PROJECT_GUIDE.md`, under "Vendored dependencies".

## Task format

```
- [ ] **T-XXX** (P1) Short title
  - Details / acceptance criteria
  - Depends on: T-YYY
```

---

## Phase 1: Foundation

- [ ] **T-001** (P1) Project scaffolding (Python/FastAPI)
  - Set up `pyproject.toml` with the `src/apiedge` package, the `apiedge` CLI (`init`, `migrate`, `run`, `create-admin`), pydantic-settings config and `platformdirs` data dirs.
  - Add SQLAlchemy and Alembic, with SQLite as the default and PostgreSQL optional.
  - Create `console/` as a React + Vite + TS skeleton, built into `src/apiedge/static`.
  - Configure ruff, mypy, bandit, pytest and pre-commit, plus `.env.example`.
  - Add a GitHub Actions CI matrix (Windows, Linux, macOS × Python 3.10–3.12).
  - Write `docs/ARCHITECTURE.md`, a README quick start, LICENSE and NOTICE.
  - Set up the `vendor/` structure from the start (see T-019).

- [ ] **T-019** (P1) Bundled, offline dependency system
  - Create `vendor/python/{runtime,dev,bootstrap}` wheelhouses for Windows, Linux (x86_64 and aarch64) and macOS (x86_64 and arm64) × Python 3.10–3.12, with hash-locked `requirements.lock` and `requirements-dev.lock`.
  - Create `vendor/node/offline-mirror`, configured so the console builds offline.
  - Commit the prebuilt console in `src/apiedge/static/`.
  - Add `scripts/install.ps1`, `scripts/install.sh` and `scripts/install.py`, which create a venv and install with `--no-index --find-links vendor/...` only.
  - Add `scripts/vendor-refresh.py` for maintainers.
  - Generate `vendor/THIRD_PARTY_LICENSES.md` and add a license check that fails on GPL, AGPL or SSPL.
  - Add a CI job that runs with **network disabled** after checkout and installs, tests and starts APIEdge on all three OSs.
  - Document the offline install in the README and the Installation Guide.
  - Report the size of `vendor/` in the delivery note.
  - Depends on: T-001 (do it together with T-001, before any feature work)

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
  - Build an offline bundle per OS (wheelhouse with all dependencies, plus `install.ps1` and `install.sh`).
  - Build PyInstaller executables for Windows, Linux and macOS (x86_64 and arm64), and a multi-arch Docker image with docker-compose.
  - Generate the SBOM (CycloneDX), checksums and signatures.
  - Add a GitHub Actions release workflow that publishes to GitHub Releases on a version tag.
  - Smoke-test the install on all three OSs in CI.
  - Depends on: T-007

- [ ] **T-017** (P1) Complete documentation set
  - Write the Installation Guide (per OS, online and offline), Administrator Guide, User Guide (no-code and low-code), Inspector Guide, Analytics Guide, the API reference (OpenAPI plus rendered HTML), Security and OWASP mapping, Upgrade notes, and a Troubleshooting guide.
  - Publish the docs site with MkDocs, built in CI and shipped in the release bundle.
  - Depends on: T-016

- [ ] **T-018** (P1) Security verification before release
  - Run an OWASP ZAP baseline scan against the console and the gateway in CI.
  - Review the ASVS L2 checklist.
  - Fix every high and critical finding, and record the results in `docs/SECURITY.md`.
  - Depends on: T-012, T-013, T-016

---

## Vendor Proposals

The development team writes suggested improvements here. Move one into a phase above to approve it.

