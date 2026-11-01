# Access control: sign-in, tenants, users, roles and audit

APIEdge is multi-tenant. A **tenant** (organization) is the isolation boundary: its users, roles
and (later) products and APIs are invisible to other tenants. **SuperAdmins** are platform users
outside every tenant; they create tenants and can act inside any of them.

The console uses the admin API below (base `/api/v1`). Every route checks a permission on the
server; the console only hides what you cannot do.

## Signing in

| Step | API |
|---|---|
| Sign in | `POST /auth/login` `{"username", "password", "totp_code"?}` |
| Who am I, what may I do | `GET /auth/me` (permissions held tenant-wide and per product) |
| Renew the session | `POST /auth/refresh` (uses the refresh cookie) |
| Sign out | `POST /auth/logout` |
| Change own password | `POST /auth/change-password` `{"current_password", "new_password"}` |
| Turn on MFA | `POST /auth/mfa/setup` (returns the secret and an `otpauth://` URI for an authenticator app), then `POST /auth/mfa/enable` `{"code"}` |
| Turn off MFA | `POST /auth/mfa/disable` `{"password", "code"}` |

* Sign-in returns a 15-minute access token, both in the JSON body (for scripts: send it as
  `Authorization: Bearer <token>`) and in the HttpOnly `apiedge_session` cookie (for the console).
  A refresh cookie (`apiedge_refresh`, HttpOnly, only sent to `/api/v1/auth`) renews it; every
  renewal issues a new refresh token, and presenting an old one ends the whole session.
* Browser requests that change data must send the `apiedge_csrf` cookie value in the
  `X-CSRF-Token` header.
* **Password policy:** 12-128 characters, not starting or ending with a space, not containing the
  username, not a common password. Passphrases are encouraged; there are no composition rules.
* **Lockout:** after 5 failed sign-ins (wrong password or wrong MFA code) the account locks for
  15 minutes. An administrator can unlock it earlier. Too many attempts from one address in a
  minute get `429`.
* **First sign-in:** new users, the first SuperAdmin and users whose password was reset must
  change their password before they can do anything else (`403 password_change_required`).
* Changing or resetting a password, granting or revoking a role, and disabling a user end all of
  that user's sessions.

Error codes in `detail`: `invalid_credentials`, `account_locked`, `mfa_required`,
`invalid_mfa_code`, `too_many_attempts`, `invalid_token`, `password_change_required`,
`permission_denied`.

## Tenants

| API | Permission |
|---|---|
| `GET /tenants` | any user (lists the tenants you can see) |
| `POST /tenants` `{"slug", "name"}` | `tenant:create` (SuperAdmin) |
| `GET /tenants/{id}` | `tenant:read` |
| `PATCH /tenants/{id}` `{"name"?, "is_active"?}` | `tenant:update`; suspending (`is_active`) is SuperAdmin-only |
| `DELETE /tenants/{id}` | `tenant:delete` (SuperAdmin); deletes the tenant's users and roles |

Users of a suspended tenant cannot sign in, and their current sessions stop working.
A tenant you do not belong to answers `404`, so its existence is not disclosed.

## Users

| API | Permission |
|---|---|
| `GET /tenants/{id}/users` | `user:read` |
| `POST /tenants/{id}/users` `{"username", "password", "email"?, "must_change_password"?, "role_ids"?}` | `user:create` (+ `role:assign` for `role_ids`) |
| `PATCH /tenants/{id}/users/{uid}` `{"email"?, "is_active"?, "unlock"?, "reset_mfa"?}` | `user:update` |
| `POST /tenants/{id}/users/{uid}/reset-password` `{"new_password"}` | `user:update` |
| `DELETE /tenants/{id}/users/{uid}` | `user:delete` |

Each user belongs to exactly one tenant. Usernames are unique across the installation.
You cannot disable or delete yourself, and you cannot manage a user who holds permissions you do
not hold.

## Roles and permissions

Permissions are `resource:action` (for example `user:create`, `api:publish`, `inspector:view`);
`GET /permissions` lists them. Roles bundle permissions. Built-in roles:

| Role | Summary |
|---|---|
| SuperAdmin | Everything, in every tenant, plus platform permissions (`tenant:create`, `tenant:delete`, `settings:update`). Created with `apiedge create-admin`; not assignable through the API |
| TenantAdmin | Every tenant permission |
| ProductOwner | Products (read/update/publish), APIs, policies, scripts, plans, subscriptions, inspector, analytics |
| APIDeveloper | Read products, create and change APIs, policies and scripts, inspector, analytics |
| Viewer | Read-only access, analytics, masked inspector |
| Consumer | Read products, APIs, plans and own subscriptions |

| API | Permission |
|---|---|
| `GET /tenants/{id}/roles`, `GET .../roles/{rid}` | `role:read` |
| `POST /tenants/{id}/roles` `{"name", "description"?, "permissions"}` | `role:create` |
| `PATCH /tenants/{id}/roles/{rid}` | `role:update` (custom roles only) |
| `DELETE /tenants/{id}/roles/{rid}` | `role:delete` (custom roles that are not granted) |
| `GET /tenants/{id}/users/{uid}/roles` | `role:read` |
| `POST /tenants/{id}/users/{uid}/roles` `{"role_id", "product_id"?}` | `role:assign` |
| `DELETE /tenants/{id}/users/{uid}/roles/{assignment_id}` | `role:assign` |

A role grant applies to the whole tenant, or only to one product when `product_id` is set
(products arrive with T-005). You can only put permissions you hold into a custom role, and only
grant roles whose permissions you hold.

## Audit log

| API | Permission |
|---|---|
| `GET /tenants/{id}/audit?limit=&before_id=&action=` | `audit:read` (this tenant's events) |
| `GET /audit?limit=&before_id=&action=&tenant_id=` | SuperAdmin (all events) |

Recorded: sign-ins (success and failure, with the client address), lockouts, refresh-token reuse,
password changes and resets, MFA changes, and every create/update/delete of tenants, users, roles
and role grants. Details are masked like the logs; passwords are never recorded.
