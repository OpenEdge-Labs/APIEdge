# Changelog

All notable changes to APIEdge are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Security
- T-002: OWASP baseline: security headers and strict CSP, CORS allow-list (closed by default), request body-size limit (413), CSRF protection (double-submit cookie plus Origin check) for cookie-authenticated requests, global error handler without stack traces, 422 responses that never echo input, structured JSON logging with secret masking and request ids, AES-256-GCM secrets encryption helper with key rotation (`pycryptodome`), SSRF guard for upstream URLs, `docs/SECURITY.md` with the OWASP mapping, CodeQL in CI. A CodeQL finding is accepted only with both an inline `codeql[<rule id>]` justification and a row in the `docs/SECURITY.md` "Accepted findings" table, enforced by `scripts/codeql-gate.py`.

### Changed
- T-003: the password policy now also rejects passwords that contain the username or are common, and caps length at 128.

### Fixed
- T-001/T-019: lock files now carry per-target PEP 508 environment markers and are verified on every platform x Python 3.10-3.12 target (fixes developer installs on Python 3.11 and 3.12).

### Added
- T-005: product management. Admin API `/api/v1/tenants/{id}/products` (list with lifecycle filter, create, get, update, lifecycle change, delete) with tenant-wide or product-scoped `product:*` permissions, owners chosen from the tenant's users, lifecycle draft -> published -> deprecated -> retired, and audit events. Console Products screen and a product scope for role grants on the Users screen. Migration 0003 adds `products` and `product_owners` and the foreign key from product-scoped role grants to products (ADR 0005).
- T-004: web console admin panel. Sign-in with TOTP step, forced password change on first sign-in, app shell with permission-aware navigation and a tenant selector for SuperAdmins; screens for tenants, users (create, enable/disable, unlock, reset MFA, reset password, delete, role grants), roles and permissions (custom role editor limited to held permissions), audit log (filter, paging, all-tenants view for SuperAdmins), read-only system settings, and My account (password change, MFA set-up and removal). New admin API route `GET /api/v1/system/settings` (SuperAdmins, never returns secrets). Console unit tests run with Node's built-in test runner (`npm test`, also in CI); no new npm dependencies.
- T-003: authentication, multi-tenancy and RBAC core. Admin API `/api/v1`: sign-in with Argon2id passwords, password policy, per-IP throttling and account lockout, 15-minute JWT access tokens (Bearer or HttpOnly cookie) with rotating refresh cookies and reuse detection, forced password change, TOTP MFA; tenants, users, built-in and custom roles, `resource:action` permission catalog, tenant- and product-scoped role grants with anti-escalation rules; tenant-filtered data access in the database layer; audit log with tenant and platform views. New settings `APIEDGE_ACCESS_TOKEN_TTL_SECONDS`, `APIEDGE_REFRESH_TOKEN_TTL_HOURS`, `APIEDGE_LOGIN_*`, `APIEDGE_JWT_SECRET`, `APIEDGE_COOKIE_SECURE`. New dependencies `pyjwt` 2.15.1 and `pyotp` 2.10.0 (MIT).
- T-001: `apiedge` Python package (FastAPI, pydantic-settings, SQLAlchemy 2 + Alembic, SQLite default / PostgreSQL optional), CLI `init | migrate | run | create-admin | version`, `/healthz` and `/readyz` probes, Argon2id-hashed bootstrap SuperAdmin, React + Vite + TypeScript console shell prebuilt into `src/apiedge/static`, ruff / mypy --strict / bandit / pytest / pre-commit config, `.env.example`, GitHub Actions CI (Windows, Linux, macOS x Python 3.10-3.12), architecture docs and ADRs.
- T-019: one-click installers `install.bat` (Windows), `install.command` (macOS) and `install.sh` (Linux) on top of the shared `scripts/install.py`: Python check with guidance, venv, hash-locked install from PyPI (`requirements/*.lock`), migrations, first admin, shortcuts, start at logon, `--unattended`, `--proxy`, `--index-url`, `--uninstall`, install log. Lock tooling (`scripts/update-locks.py`), license gate and `THIRD_PARTY_LICENSES.md` (`scripts/check-licenses.py`), CI installer smoke test on all three OSs.
- Project guide (`docs/PROJECT_GUIDE.md`) and task list (`APIProjectTask.md`).
