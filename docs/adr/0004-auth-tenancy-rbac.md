# ADR 0004: Authentication, multi-tenancy and RBAC core

- Status: Accepted
- Date: 2026-11-01
- Task: T-003

## Context

T-003 needs console authentication (Argon2id, password policy, throttling, lockout, JWT access
tokens with rotating refresh cookies, TOTP MFA), tenants, users, roles, permissions and role
assignments scoped to a tenant or a product, tenant-filtered data access, an RBAC FastAPI
dependency and an audit log. `docs/PROJECT_GUIDE.md` requires tenant filtering in the data-access
layer rather than in route handlers.

## Decision

1. **Dependencies:** `pyjwt` 2.15.1 (MIT) for HS256 access tokens and `pyotp` 2.10.0 (MIT) for
   TOTP. Both are pure Python (no wheel-availability risk on any target).
2. **Tokens:** access tokens are 15-minute HS256 JWTs with pinned algorithm, issuer, audience and
   `typ`. They carry `ver` = `users.token_version`; bumping it invalidates all earlier tokens.
   Refresh tokens are opaque random values stored as SHA-256, rotated on every use, grouped in a
   family per sign-in with an absolute lifetime; reuse of a consumed token revokes the family.
   The signing key is `APIEDGE_JWT_SECRET`, or an HMAC-derived subkey of the secrets master key
   (`SecretBox.derive_key`), or, with neither, a random per-process key.
3. **Cookies:** `apiedge_session` (path `/api`) and `apiedge_refresh` (path `/api/v1/auth`), both
   HttpOnly and `SameSite=Strict`, `Secure` over HTTPS or with `APIEDGE_COOKIE_SECURE`. The T-002
   CSRF middleware applies to them. Scripts may use the Bearer header instead.
4. **Users belong to one tenant** (`users.tenant_id`); SuperAdmins are platform users
   (`tenant_id` NULL, `is_superadmin`). Usernames are globally unique, so sign-in needs no tenant
   selector. Role assignments always lie in the user's tenant, optionally narrowed to a product.
5. **Tenant filter:** sessions bound to a tenant (`apiedge.db.tenancy.bind_tenant`) add
   `tenant_id` criteria (`with_loader_criteria`) to every ORM SELECT of models marked
   `TenantOwned` (strict) or `TenantOrGlobal` (own rows plus global rows such as built-in roles),
   and refuse to flush rows of other tenants or global rows. The `require(permission)` dependency
   binds the session after checking membership (404 for foreign tenants) and the permission (403).
6. **Permission catalog in code**, seeded by migration 0002 (a frozen copy). A test fails if the
   migrated catalog and the code drift apart; catalog changes need a new migration.
7. **Anti-escalation:** non-SuperAdmins can only put permissions they hold into custom roles,
   only grant roles whose permissions they hold, and only manage users whose permissions are a
   subset of their own. Platform permissions (`tenant:create`, `tenant:delete`,
   `settings:update`) are never grantable through tenant roles.
8. **Throttling** is in-process (per client IP sliding window) for now; the Redis-backed shared
   limiter arrives with clustering (T-026).

## Consequences

- Route handlers cannot forget tenant filtering for ORM queries; Core `update`/`delete`
  statements are not filtered and must only target non-tenant tables or carry explicit criteria.
- Users cannot belong to several tenants; a person who needs two tenants gets two accounts.
- Restarting APIEdge does not end sessions unless no secrets master key is configured.
- With several APIEdge processes, the login rate limit is per process until T-026.
