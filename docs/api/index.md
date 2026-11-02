<!-- Copyright 2026 OpenEdge Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Admin API guide

Everything the web console does goes through the **admin API**, a JSON REST API under `/api/v1`
on the console port (default `http://127.0.0.1:8080/api/v1`). You can use it from scripts, CI
pipelines or your own tools.

| Resource | Where |
|---|---|
| Reference: every operation, the permission it needs, parameters, bodies and schemas | [Admin API reference](reference.md) |
| OpenAPI 3.1 document (generate clients, import into API tools) | [openapi.json](openapi.json), or `GET /api/v1/openapi.json` on any installation |
| Interactive explorer | `/api/docs`, only when `APIEDGE_ENV=development` |

The reference and `openapi.json` are generated from the application by
`scripts/export-openapi.py`, and CI fails if they differ from the code.

## Authenticating from a script

1. Sign in:

    ```
    curl -s -X POST http://127.0.0.1:8080/api/v1/auth/login \
      -H 'content-type: application/json' \
      -d '{"username": "ci-bot", "password": "...", "totp_code": "123456"}'
    ```

    `totp_code` is needed only when the user has MFA turned on. The answer is
    `{"access_token": "...", "token_type": "bearer", "expires_in": 900, "must_change_password": false}`.
    A user with `must_change_password: true` must call `POST /auth/change-password` first;
    everything else answers `403 password_change_required` until then.

2. Send the token on every request:

    ```
    curl -s http://127.0.0.1:8080/api/v1/auth/me -H "Authorization: Bearer $TOKEN"
    ```

3. Access tokens live `APIEDGE_ACCESS_TOKEN_TTL_SECONDS` (15 minutes by default). Sign in again
   when a request answers `401`.

Use a dedicated user for automation with only the roles it needs (for example `APIDeveloper`
scoped to one product). Store its password in your CI secret store.

**Do not send the session cookies from scripts.** Sign-in also sets HttpOnly cookies for the
console. A request that carries the `apiedge_session` or `apiedge_refresh` cookie is treated as a
browser request: unsafe methods (POST, PUT, PATCH, DELETE) must then echo the `apiedge_csrf`
cookie in an `X-CSRF-Token` header and come from a trusted `Origin`, or they answer
`403 CSRF validation failed`. Bearer-only requests need no CSRF token. (HTTP clients with a
cookie jar, such as a `requests.Session`, keep these cookies; use a plain client or clear them.)

## Tenants and IDs

Most operations live under `/api/v1/tenants/{tenant_id}/...`. Find your tenant id with
`GET /api/v1/tenants` (users see their own tenant; SuperAdmins see all). Products, APIs, users
and roles are addressed by numeric ids returned when they are created and by the list
operations.

## Errors

| Status | Meaning |
|---|---|
| `400` | Malformed request (for example an invalid `Content-Length`) |
| `401` | Not signed in, or the token expired or was revoked (`detail`: `not_authenticated`, `invalid_token`, ...) |
| `403` | Signed in but not allowed (`permission_denied`, `password_change_required`, `CSRF validation failed`) |
| `404` | Not found, **or** in a tenant or product you cannot access (APIEdge does not reveal whether it exists) |
| `409` | Conflict with existing data (for example a duplicate name or base path) or with the current lifecycle state |
| `413` | Request body larger than `APIEDGE_MAX_REQUEST_BODY_BYTES` |
| `422` | Validation failed; `detail` lists the fields, without echoing the submitted values |
| `429` | Too many sign-in attempts from your address |
| `500` | Unexpected error; the body has a `request_id` to give to your administrator, never internal details |

Every response carries an `X-Request-ID` header that also appears in the server log.

## Conventions

* JSON in and out (`content-type: application/json`), except the CSV analytics export, the HAR
  export and the Server-Sent Events stream of the packet inspector.
* Timestamps are ISO 8601 in UTC.
* Secrets you send (passwords, policy secrets) are write-only: they are never returned.
  Generated API keys are returned only once, in the response that creates them.
* Every change made through the API is checked against the same permissions as in the console
  and recorded in the audit log.
* The API is versioned in the path (`/api/v1`). Changes are listed in the CHANGELOG; breaking
  changes will be called out in the [upgrade notes](../upgrading.md).
