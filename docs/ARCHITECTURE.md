# APIEdge Architecture

> Status: T-001 to T-003 (foundation, security baseline, auth/tenancy/RBAC). Sections marked *(planned)* describe the target design from
> `docs/PROJECT_GUIDE.md` and are filled in as tasks land.

## 1. Overview

APIEdge is a single Python application (FastAPI on Uvicorn). One process serves:

| Surface | Path | Delivered in |
|---|---|---|
| Liveness / readiness probes | `GET /healthz`, `GET /readyz` | T-001 |
| Admin API (OpenAPI 3) | `/api/v1/...`, schema at `/api/v1/openapi.json` | T-003: auth, tenants, users, roles, audit |
| Web console (static SPA) | `/` | T-001 shell, T-004+ screens |
| Gateway data plane | API base paths | T-007 *(planned)* |

```
          browser ──► /            static console (React build, committed in src/apiedge/static)
                 └──► /api/v1/*    admin API ──► RBAC dependency ──► services ──► SQLAlchemy ──► SQLite / PostgreSQL
API consumers ──────► /<api base>  gateway ──► policy pipeline ──► httpx ──► upstreams   (planned, T-007)
```

## 2. Package layout

| Module | Responsibility |
|---|---|
| `apiedge.config` | `Settings` (pydantic-settings, `APIEDGE_*` env vars, `.env`), OS data dir via `platformdirs` |
| `apiedge.app` | `create_app()` factory: health probes, admin API routers, console mount |
| `apiedge.cli` | `apiedge init | migrate | run | create-admin | version` |
| `apiedge.db` | Declarative `Base` (with constraint naming convention), engine/session factories, Alembic migrations in `db/migrations` |
| `apiedge.security` | Argon2id passwords (T-001); HTTP hardening middleware, secret masking, AES-256-GCM secrets box, SSRF guard (T-002); auth and RBAC (T-003) |
| `apiedge.logs` | Structured JSON logging with secret masking and request ids (T-002) |
| `apiedge.admin` | Admin API routers (`auth_routes`, `tenants`, `users`, `roles`) and RBAC dependencies (`deps`) (T-003) |
| `apiedge.db.tenancy` | Tenant-bound sessions: automatic `tenant_id` criteria and cross-tenant write guard (T-003) |
| `apiedge.security.auth`, `rbac`, `audit` | Tokens, refresh rotation, throttling, lockout, TOTP; permission catalog and evaluation; audit writer (T-003) |
| `apiedge.gateway`, `policies`, `inspector`, `analytics` | Placeholders for later tasks |
| `console/` | React + Vite + TypeScript source; `npm run build` writes to `src/apiedge/static` |

## 3. Data

* SQLAlchemy 2.x ORM, Alembic migrations only (`apiedge migrate`, run automatically by `apiedge run`,
  `init` and `create-admin`). Migrations use `render_as_batch` so they also work on SQLite.
* Default database: SQLite file `apiedge.db` in the data directory (WAL mode, foreign keys on).
  PostgreSQL: set `APIEDGE_DATABASE_URL=postgresql+psycopg://...` and install the `postgres` extra.
* Schema (migrations 0001-0002): `tenants`; `users` (one tenant each, or platform SuperAdmin with
  `tenant_id` NULL; lockout, MFA and `token_version` columns); `permissions` (catalog);
  `roles` (built-in global or per tenant) and `role_permissions`; `role_assignments` (tenant or
  product scope); `refresh_tokens` (SHA-256 only); `audit_log`.
* Tenancy ([ADR 0004](adr/0004-auth-tenancy-rbac.md)): every tenant-owned row carries `tenant_id`.
  The RBAC dependency binds the request's session to the tenant in the path, and
  `apiedge.db.tenancy` then filters every ORM query and refuses cross-tenant writes.

## 4. Configuration and data directories

| Setting | Default |
|---|---|
| `APIEDGE_DATA_DIR` | `platformdirs.user_data_path("APIEdge", "APIEdge")` |
| `APIEDGE_DATABASE_URL` | `sqlite:///<data dir>/apiedge.db` |
| `APIEDGE_HOST` / `APIEDGE_PORT` | `127.0.0.1` / `8080` (secure default: not exposed on the network) |
| `APIEDGE_ENV` | `production` (interactive API docs disabled) |

## 5. Dependencies and installation

See [ADR 0002](adr/0002-online-hash-locked-installer.md). Third-party packages are **not** committed.
`requirements/*.lock` pin every package with the sha256 of every published file; the one-click
installer (`install.bat`, `install.command`, `install.sh` → `scripts/install.py`) creates a venv and
installs with `pip --require-hashes`. The prebuilt console is committed, so users never need Node.js.

## 6. Security

The OWASP mapping lives in `docs/SECURITY.md`. T-001 baseline: loopback bind by default, docs UI
off in production, health probes expose no version or error details, Argon2id for passwords,
generated admin password shown once, DB password redacted in CLI output.

T-002 (ADR 0003) adds the HTTP hardening stack, applied to every console and admin API response
(outermost first): security headers and CSP, request context (request id, access log, global error
barrier), CORS allow-list, body-size limit, CSRF (double-submit cookie plus Origin check). It also
adds structured JSON logging with masking, the AES-256-GCM secrets box (master key from
`APIEDGE_SECRET_KEY` or `<data dir>/secret.key`, exposed as `app.state.secret_box`) and the SSRF guard
(`apiedge.security.ssrf.check_url`) that every outbound call site must use.

T-003 (ADR 0004) adds authentication and authorization. Request flow for a tenant route:

```
Bearer header / apiedge_session cookie -> TokenSigner.verify -> load user (active, token_version,
tenant active) -> Principal (grants) -> require("resource:action"): tenant membership (404) and
permission (403) -> bind_tenant(session) -> handler -> audit() -> commit
```

## 7. Cross-platform

Pure `pathlib`, no shell calls from Python (installer subprocesses use argument lists). CI runs the
test suite on Windows, Linux and macOS × Python 3.10–3.12, and runs each OS's one-click installer.
