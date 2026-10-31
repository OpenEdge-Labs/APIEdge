# APIEdge — Project Guide

This guide defines the product scope, architecture, technology stack and engineering rules for APIEdge.
Work is planned and tracked in **`APIProjectTask.md`**.

- **Product:** APIEdge, an on-premise, multi-tenant API Gateway
- **Author:** Alingan Patra
- **License:** Apache-2.0
- **Repository:** https://github.com/alinganpatra20004/APIEdge

## Product vision

**APIEdge** is an API Gateway with a web console where teams design, configure, secure, publish, debug and monitor APIs using **no-code** (visual configuration and flow builders) and **low-code** (small scripted policies/transforms) tools.

### Domain model

```
Tenant (Organization)          ← hard isolation boundary
 └── Product                   (bundle of APIs with owners, plans, lifecycle)
      └── API                  (base path, version, upstream(s), lifecycle: draft → published → deprecated → retired)
           └── Route / Operation   (method + path, request/response schema)
                └── Policy chain   (auth, rate limit, transform, cache, mock, script, ...)
 Consumer / Application  → subscribes to Products via Plans → receives API keys / OAuth clients
```

### Core capabilities

1. **Gateway runtime**: reverse proxying, routing, load balancing to upstreams, timeouts/retries, a policy pipeline, hot reload of config without restart.
2. **Admin API**: REST API (OpenAPI documented, served by FastAPI) for everything the console can do. The console uses only this API.
3. **Web console**:
   - Admin panel: tenants, users, roles, permissions, audit log, system settings
   - Product management: products, the APIs inside each product, plans, lifecycle
   - **No-code**: form-based API and route configuration, a drag-and-drop policy flow builder, OpenAPI import, mock responses
   - **Low-code**: sandboxed Python script policies and transforms, with an in-browser editor and test runner
   - **Packet inspector**: live and recorded capture of gateway traffic for debugging (see below)
   - **Analytics**: an admin interface showing traffic, latency, errors, top consumers and status codes (see below)
   - Developer portal (later phase): API catalog, docs, key self-service
4. **RBAC everywhere**: permissions are `resource:action` (for example `product:create`, `api:publish`, `inspector:view`). Roles bundle permissions. Assignments are scoped to a Tenant, or to a Product within it. Built-in roles are `SuperAdmin`, `TenantAdmin`, `ProductOwner`, `APIDeveloper`, `Viewer` and `Consumer`. Every admin API route enforces permissions server-side, and every privileged action is written to the audit log.
5. **Multi-tenancy**: every tenant-owned row carries `tenant_id`. Queries are tenant-filtered in the data-access layer, never only in route handlers. Cross-tenant access is tested explicitly.

### Packet inspector (debugging)

- The gateway records HTTP exchanges (request/response line, headers, body up to a size cap, timings, upstream chosen, and each policy's decision) for selected APIs, routes or consumers.
- Capture is opt-in per API and time-boxed, with ring-buffer and retention limits so it cannot exhaust disk or memory.
- The console has a live view (WebSocket/SSE), filters, a detail pane with a policy-by-policy trace, HAR export, and replay of a captured request.
- Sensitive data is masked by default (Authorization, Cookie, API keys, configurable JSON fields). Viewing unmasked data needs a separate permission and is audit-logged.
- Requires the `inspector:view` and `inspector:capture` permissions, and is tenant-scoped.

### Analytics (admin)

- The gateway emits per-request metrics: tenant, product, API, route, consumer, status, latency, bytes and errors. They are aggregated into time buckets.
- The console has dashboards with time-range filters, broken down by API, consumer and status code: p50/p95/p99 latency, error rates, and top-N lists. Data can be exported as CSV.
- A Prometheus `/metrics` endpoint is available for external monitoring.

## Technology stack (mandatory)

| Layer | Choice |
|-------|--------|
| Language | Python 3.10+ (type-hinted, `mypy --strict` on core packages) |
| Admin API + gateway | **FastAPI** on Uvicorn; gateway proxying via `httpx` (async) |
| Validation / settings | Pydantic v2, pydantic-settings |
| Database | SQLAlchemy 2.x + Alembic migrations. **SQLite by default** (zero-dependency install), **PostgreSQL** supported for production |
| Cache / rate limit / config pub-sub | Redis optional; in-process fallback when Redis is not configured |
| Auth (console) | Argon2id password hashing, short-lived JWT access tokens plus rotating refresh tokens in HttpOnly/Secure/SameSite cookies, TOTP MFA; OIDC SSO later |
| Low-code sandbox | Restricted Python (RestrictedPython) executed in an isolated worker process with CPU/time/memory limits and no network or filesystem access |
| Web console | React + Vite + TypeScript, React Flow (flow builder), Monaco (editor). **The console is built at release time and shipped as static files inside the Python package**, so end users need no Node.js |
| Tests | pytest, pytest-asyncio, httpx test client; Playwright for E2E |
| Quality / security tooling | ruff, mypy, bandit, pip-audit, npm audit, Semgrep or CodeQL in CI |

### Repository layout

```
src/apiedge/
  admin/        admin API (FastAPI routers, RBAC dependencies)
  gateway/      data plane: router, proxy, policy pipeline
  policies/     built-in policies
  inspector/    packet capture, storage, masking, replay
  analytics/    metrics collection and aggregation
  security/     auth, RBAC, crypto, OWASP controls
  db/           models, Alembic migrations
  cli.py        `apiedge` command (init, migrate, run, create-admin)
  static/       built web console (generated and committed, never hand-edited)
console/        web console source (React)
tests/          unit, integration, security, e2e
docs/           ARCHITECTURE.md, SECURITY.md, adr/, user-guide/, admin-guide/, PROGRESS.md
packaging/      Docker, PyInstaller specs
scripts/        offline install scripts, vendor-refresh
vendor/         ALL third-party dependencies (see "Vendored dependencies")
APIProjectTask.md   customer task inbox
```

## Security baseline (OWASP)

APIEdge must satisfy the **OWASP Top 10 (2021)**, the **OWASP API Security Top 10 (2023)** and **OWASP ASVS 4.0 Level 2**. `docs/SECURITY.md` maps each item to the code and tests that cover it, and must be kept current. At minimum:

- **Access control (A01 / API1 BOLA, API3, API5):** deny by default; every route uses an RBAC dependency; object-level and tenant-level ownership checks; tests for both kinds of denial.
- **Cryptography (A02):** TLS support on the gateway and console; secrets such as upstream credentials and keys are encrypted at rest (Fernet/AES-GCM with a key from env or a key file); API keys are stored hashed.
- **Injection (A03):** ORM or parameterised queries only; validate every input with Pydantic; no `eval` or `exec` outside the sandbox; console output encoding plus a strict CSP.
- **Insecure design (A04) / resource consumption (API4):** rate limits and body-size limits on the gateway and admin API; login throttling and lockout; timeouts everywhere.
- **Misconfiguration (A05 / API8):** secure defaults; security headers (HSTS, CSP, X-Content-Type-Options, frame-ancestors); CORS allow-list; no debug mode or stack traces in production; first-run forces an admin password change.
- **Vulnerable components (A06 / API10):** pinned and hash-locked dependencies; pip-audit and npm audit in CI fail the build on high-severity issues; an SBOM (CycloneDX) is generated for each release.
- **Authentication (A07 / API2):** Argon2id; password policy; TOTP MFA; refresh-token rotation and revocation; session invalidation on password or role change.
- **Integrity (A08):** signed release artifacts and checksums; CSRF protection for cookie-authenticated requests.
- **Logging (A09):** structured audit and security logs, with no secrets or PII in logs (the same masking as the inspector).
- **SSRF (A10 / API7):** upstream URLs are validated against an allow/deny policy (private, link-local and metadata ranges are blocked by default and configurable for on-prem use); scripts and the inspector's replay cannot reach arbitrary hosts.
- **Inventory (API9):** API lifecycle and version tracking; deprecated and retired APIs are enforced by the gateway.

## Cross-platform shipping

APIEdge must install and run on **Windows, Linux and macOS** (x86_64 and arm64):

- A pip-installable wheel (`pip install apiedge`) with the built console included.
- **Offline install straight from the git checkout**, using the vendored wheelhouse described in the next section, plus offline release bundles per OS.
- Standalone executables built with PyInstaller for each OS.
- A multi-arch Docker image and `docker-compose.yml` (APIEdge, PostgreSQL and Redis).
- GitHub Actions CI runs lint and tests on a matrix of `windows-latest`, `ubuntu-latest` and `macos-latest`, and builds the release artifacts.
- Code uses `pathlib` and avoids OS-specific shell calls. Data and config directories follow each OS's conventions (`platformdirs`).

## Vendored dependencies (customer requirement)

**Every third-party dependency is committed to this repository.** After `git clone` or `git pull`, APIEdge must install, build, test and run **with no internet access**. The only prerequisite is a Python 3.10–3.12 interpreter. External services are optional, because SQLite is the default database and Redis has an in-process fallback.

```
vendor/
  python/
    runtime/        wheels needed to run APIEdge, for every supported platform
    dev/            wheels for tests and tooling (pytest, ruff, mypy, bandit, pip-audit, ...)
    bootstrap/      pip, setuptools and wheel, so even pip itself needs no download
    requirements.lock       runtime lock with hashes (pip-compile --generate-hashes)
    requirements-dev.lock   dev lock with hashes
  node/
    offline-mirror/ npm package tarballs for console development (an npm offline mirror)
  THIRD_PARTY_LICENSES.md   every vendored package with its version, license and source URL
src/apiedge/static/         prebuilt web console, committed, so running APIEdge never needs Node.js
scripts/
  install.ps1 / install.sh / install.py    offline install: `pip install --no-index --find-links vendor/python/...`
  vendor-refresh.py                        maintainer-only: downloads wheels for every platform and updates the locks
```

- **Platforms vendored:** `win_amd64`, `manylinux x86_64` and `aarch64`, and `macosx x86_64` and `arm64`, for Python 3.10, 3.11 and 3.12. Pure-Python and `abi3` wheels are stored once.
- **Install path:** every install script uses `--no-index --find-links` only, never PyPI. CI includes a job with **networking disabled** that clones, installs, tests and runs APIEdge on Windows, Linux and macOS to prove this works.
- **Adding or upgrading a dependency:** pin it in the lock with hashes, run `scripts/vendor-refresh.py` to fetch wheels for every platform, commit the wheels, the lock and the updated `THIRD_PARTY_LICENSES.md` together, and run pip-audit on the vendored set.
- **Licenses:** only Apache-2.0-compatible licenses are allowed (MIT, BSD, Apache-2.0, ISC, PSF, MPL-2.0 used as a dependency). GPL, AGPL and SSPL are not allowed.
- **Size discipline:** prefer few, well-maintained dependencies. Every wheel must stay under 100 MB (GitHub's per-file limit), and `vendor/` should stay under about 1 GB. If it grows past that, raise it in Vendor Proposals rather than dropping platforms silently. **Do not use Git LFS**, because LFS content is downloaded separately.
- Node.js is needed only by developers who change the console source, and its packages come from `vendor/node/offline-mirror`.

## Documentation shipped with every release

README, Installation Guide (per OS, online and offline), Administrator Guide, User Guide (no-code and low-code), Packet Inspector Guide, Analytics Guide, the Admin API reference (OpenAPI plus a rendered HTML version), Architecture, Security (with the OWASP mapping), Upgrade notes, CHANGELOG, LICENSE (Apache-2.0) and NOTICE.

## Engineering rules

- Each task is delivered as a vertical slice (API, UI and tests) where it applies.
- Every new admin route declares its permission and has tests for RBAC denial and tenant-isolation denial.
- Schema changes go through Alembic migrations only.
- Use no secrets in code; document new settings in `.env.example` and the Administrator Guide.
- `ruff`, `mypy`, `bandit` and `pytest` must pass before a task is marked done.
- Keep `docs/PROGRESS.md`, `CHANGELOG.md`, `docs/SECURITY.md` and the task statuses in `APIProjectTask.md` up to date.
- **Git:** after a task is done and verified, commit it with a conventional-commit message referencing the task ID (for example `feat(T-004): product CRUD`) and push it to `origin main`. Never commit secrets, `.env` files or captured traffic.
