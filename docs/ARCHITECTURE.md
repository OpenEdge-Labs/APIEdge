# APIEdge Architecture

> Status: T-001 to T-003 (foundation, security baseline, auth/tenancy/RBAC). Sections marked *(planned)* describe the target design from
> `docs/PROJECT_GUIDE.md` and are filled in as tasks land.

## 1. Overview

APIEdge is a single Python application (FastAPI on Uvicorn). One process serves:

| Surface | Path | Delivered in |
|---|---|---|
| Liveness / readiness probes | `GET /healthz`, `GET /readyz` | T-001 |
| Admin API (OpenAPI 3) | `/api/v1/...`, schema at `/api/v1/openapi.json` | T-003: auth, tenants, users, roles, audit; T-005: products; T-006: APIs in products; T-013: analytics |
| Prometheus metrics (off unless `APIEDGE_METRICS_TOKEN` is set) | `GET /metrics` | T-013 |
| Web console (static SPA) | `/` | T-004 admin panel (sign-in, MFA, tenants, users, roles, audit, settings); T-005 products; T-006 API form editor; later tasks add screens |
| Gateway data plane (own port, `APIEDGE_GATEWAY_PORT`, default 8081) | `/<tenant slug><base path>/...`, probes `/-/healthz`, `/-/readyz` | T-007 |

```
          browser ──► /            static console (React build, committed in src/apiedge/static)
                 └──► /api/v1/*    admin API ──► RBAC dependency ──► services ──► SQLAlchemy ──► SQLite / PostgreSQL
API consumers ──────► :8081/<tenant>/<api base>  gateway ──► (policy pipeline, T-008) ──► guarded httpx ──► upstreams
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
| `apiedge.admin` | Admin API routers (`auth_routes`, `tenants`, `users`, `roles`, `products`, `apis`, `analytics`, `policies`) and RBAC dependencies (`deps`) (T-003) |
| `apiedge.db.tenancy` | Tenant-bound sessions: automatic `tenant_id` criteria and cross-tenant write guard (T-003) |
| `apiedge.security.auth`, `rbac`, `audit` | Tokens, refresh rotation, throttling, lockout, TOTP; permission catalog and evaluation; audit writer (T-003) |
| `apiedge.gateway` | Data plane (T-007, [ADR 0007](adr/0007-gateway-runtime.md)): `app` (proxy ASGI app, retries, headers, errors), `snapshot` (routing snapshot, lifecycle states, weighted balancer), `transport` (SSRF-guarded connection pool, TLS), `bus` (config change events: in-process, Redis) |
| `apiedge.analytics` | T-013, [ADR 0008](adr/0008-analytics.md): `metrics` (per-request collector, minute aggregates with latency histograms, flush, Prometheus text), `query` (sums, percentiles, series, export rows) |
| `apiedge.policies` | T-008, [ADR 0009](adr/0009-policies.md): `config` (policy chain models, validated on save and load), `base` (pipeline, request context, decision trace, fail-closed placeholder), `builtin` (API key, JWT, rate limit, transform, CORS, IP filter, cache, mock; pipeline builder), `jwt` (verifier, JWKS cache), `stores` (rate-limit windows in memory or Redis, response cache) |
| `inspector` | Placeholder for T-012 |
| `console/` | React + Vite + TypeScript source; `npm run build` writes to `src/apiedge/static` |

## 3. Data

* SQLAlchemy 2.x ORM, Alembic migrations only (`apiedge migrate`, run automatically by `apiedge run`,
  `init` and `create-admin`). Migrations use `render_as_batch` so they also work on SQLite.
* Default database: SQLite file `apiedge.db` in the data directory (WAL mode, foreign keys on).
  PostgreSQL: set `APIEDGE_DATABASE_URL=postgresql+psycopg://...` and install the `postgres` extra.
* Schema (migrations 0001-0003): `tenants`; `users` (one tenant each, or platform SuperAdmin with
  `tenant_id` NULL; lockout, MFA and `token_version` columns); `permissions` (catalog);
  `roles` (built-in global or per tenant) and `role_permissions`; `role_assignments` (tenant or
  product scope, `product_id` references `products`); `refresh_tokens` (SHA-256 only); `audit_log`;
  `products` (name unique per tenant, lifecycle) and `product_owners` (T-005,
  [ADR 0005](adr/0005-products.md)); `apis` (base path unique per tenant, version, timeout,
  lifecycle), `api_upstreams` and `api_routes` (T-006, [ADR 0006](adr/0006-apis.md));
  `analytics_buckets` (insert-only per-minute aggregates with latency histogram columns, T-013,
  [ADR 0008](adr/0008-analytics.md)).
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

## Web console (T-004)

The console is a React single-page app with no router or state library: the location hash
(`#/users`) selects the page, so the server only serves `index.html` at `/`. It talks only to the
admin API through `console/src/api.ts`, which keeps the session in the HttpOnly cookies, echoes the
`apiedge_csrf` cookie in `X-CSRF-Token` on unsafe requests, and renews the session once on `401`
via `POST /auth/refresh`. After sign-in the console reads `GET /auth/me`: a pending password
change shows only the change-password form; otherwise `console/src/access.ts` derives the visible
navigation and actions from the user's permissions (UX only, the server enforces). SuperAdmins pick
the tenant to work in; other users work in their own tenant. Console unit tests run with Node's
built-in test runner on the TypeScript compiler output (`npm test`), so no test framework is added.

## Gateway runtime (T-007)

See [ADR 0007](adr/0007-gateway-runtime.md) and the [gateway guide](user-guide/gateway.md).

```
request /<slug>/<base>/<rest> -> snapshot.resolve (tenant, longest base path) -> lifecycle (404/410)
  -> route match (404/405) -> body limit (413) -> forward headers (hop-by-hop out, X-Forwarded-*)
  -> weighted pick -> httpx -> GuardedNetworkBackend (resolve, SSRF-check all IPs, connect to a
     checked IP; Host/SNI unchanged) -> retry on another upstream if allowed -> stream response
admin commit (tenant/product/API rows) -> after_commit hook -> ConfigBus (in-process | Redis)
  -> gateway reloader -> load_snapshot (worker thread) -> atomic swap; periodic reload as safety net
```

`apiedge run` serves the console/admin app and the gateway app in one event loop and shares one
`ConfigBus` between them.

## Analytics (T-013)

See [ADR 0008](adr/0008-analytics.md) and the [Analytics Guide](user-guide/analytics.md).

```
gateway proxy -> _Meter (status, latency to last byte, bytes, route, method) -> MetricsCollector
  -> per-minute aggregates + 13-bucket latency histogram  --(every 10 s, worker thread)-->
     analytics_buckets (insert-only; retention purge hourly)
  -> cumulative per tenant/API counters -> GET /metrics (bearer token, same process)
console Analytics page -> GET /tenants/{id}/analytics/summary | export.csv (analytics:view,
  tenant-bound session, product scope) -> SQL SUM per group -> percentiles from merged histograms
```
