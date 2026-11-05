<!-- Copyright 2026 OpenEdge Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Troubleshooting

Start with the log (standard error of `apiedge run`, `journalctl --user -u apiedge`,
`docker logs`, or `<data dir>/install.log` for the installer) and the `X-Request-ID` of the
failing response: it appears in the matching log lines.

## Installation

| Symptom | Cause and fix |
|---|---|
| "APIEdge needs Python 3.11, 3.12 or 3.13" | Install one of them (the message shows the python.org link and the winget, Homebrew or package-manager command for your OS; on Linux include the `venv` module) and run the installer again |
| `THESE PACKAGES DO NOT MATCH THE HASHES` | A proxy or mirror changed the files. Use a mirror that serves the original PyPI files (`--index-url`), or fix the proxy. Hash checking cannot be turned off |
| Downloads fail behind a corporate proxy | `--proxy http://proxy:3128`, or `HTTPS_PROXY`; for a TLS-inspecting proxy also set `PIP_CERT` to its CA bundle |
| macOS: "install.command cannot be opened" | Right-click it and choose **Open** the first time (Gatekeeper) |
| Linux: `Permission denied` running `install.sh` | `chmod +x install.sh scripts/install.sh`, or run `sh install.sh` |
| An installation is broken | Run the installer again: it repairs the environment. `--uninstall` then a fresh install keeps the data directory |

## Starting

| Symptom | Cause and fix |
|---|---|
| `address already in use` | Another program uses 8080 or 8081. Set `APIEDGE_PORT` / `APIEDGE_GATEWAY_PORT` (or `apiedge run --port`) |
| "secrets encryption unavailable: no secret key" | The data directory has no `secret.key`. Run `apiedge init`, or set `APIEDGE_SECRET_KEY`. If you had a key, restore it from the backup: data encrypted with it cannot be read without it |
| "console sessions will not survive a restart" | No secrets key and no `APIEDGE_JWT_SECRET`: a random signing key is used, so everyone is signed out at each restart. Create or configure the secrets key |
| A setting is rejected at start (validation error) | The message names the variable. Lists such as `APIEDGE_CORS_ALLOW_ORIGINS` and `*_CIDRS` are comma-separated; CORS origins are `scheme://host[:port]` without a path, and `*` is not allowed |
| `/readyz` answers 503 | The database is unreachable: check `APIEDGE_DATABASE_URL`, the PostgreSQL server and its credentials. With SQLite, check that the data directory is writable |

## Signing in

| Symptom | Cause and fix |
|---|---|
| Lost the generated first admin password | It is shown once and never logged. Create another SuperAdmin with `apiedge create-admin --username <new name>` (it must change its password at first sign-in) and reset the old account from **Users** |
| `account_locked` | Too many failed sign-ins. Wait `APIEDGE_LOGIN_LOCKOUT_MINUTES` (15 by default) or ask an administrator to unlock the user |
| `too_many_attempts` (429) | Too many attempts from your address in a minute (`APIEDGE_LOGIN_RATE_LIMIT_PER_MINUTE`) |
| `mfa_required` / `invalid_mfa_code` | Enter the current code of your authenticator app; check the device clock. A lost device: an administrator can reset MFA from **Users** |
| `password_change_required` | Change the password first (the console shows only that form) |
| Signed out after every restart, or signed out on another process | Configure the same secrets key (or `APIEDGE_JWT_SECRET`) on every process |
| Sign-in works over HTTP but not behind the HTTPS proxy, or the reverse | Set `APIEDGE_COOKIE_SECURE=true` behind a TLS-terminating proxy and forward the original `Host` header |
| `403 CSRF validation failed` | A browser or script sent session cookies without a matching `X-CSRF-Token` header, or from an untrusted `Origin`. Scripts should use only the Bearer token (see the [Admin API guide](api/index.md)); another web origin must be listed in `APIEDGE_CORS_ALLOW_ORIGINS` |

## Configuring APIs

| Symptom | Cause and fix |
|---|---|
| Saving an upstream fails with an SSRF message | The host resolves to a private, loopback, link-local or metadata address. An administrator can allow your backend networks with `APIEDGE_SSRF_ALLOW_CIDRS` (preferred) or `APIEDGE_SSRF_ALLOW_PRIVATE=true` |
| Cannot publish an API | It needs at least one upstream and one route |
| Cannot change the base path | Only drafts can change it |
| Cannot delete a product | Delete or retire and delete its APIs first; only draft and retired products can be deleted |
| A button is missing in the console | You lack the permission. Ask a TenantAdmin to grant a role (tenant-wide or for the product) |

## Calling APIs through the gateway

| Answer | Cause and fix |
|---|---|
| 404 `not_found` | Wrong tenant slug, base path or route; the API is a draft; or the tenant is disabled. The URL is `http://<gateway>:8081/<tenant slug><base path><route>` |
| 405 `method_not_allowed` | The route exists but not for this method |
| 410 `api_retired` | The API or its product is retired |
| 413 `payload_too_large` | Body over `APIEDGE_GATEWAY_MAX_REQUEST_BODY_BYTES` |
| 401 | The API key or JWT policy rejected the request (missing, unknown, revoked or expired key; invalid token) |
| 403 | The IP filter denied the client address. Behind a proxy, set `APIEDGE_GATEWAY_TRUSTED_PROXIES` so the real client address is used |
| 429 | Rate limit or quota reached; `Retry-After` says when to retry |
| 502 `bad_gateway` | The upstream is unreachable, refused the connection, failed TLS verification (internal CA: set `APIEDGE_GATEWAY_CA_BUNDLE`), or resolves to an address the SSRF policy blocks |
| 503 | A stored policy cannot be used (for example its secret cannot be decrypted after the secrets key changed). Restore the key or re-save the policy |
| 504 `gateway_timeout` | The upstream did not answer within the API's timeout |
| Changes do not show up on another process | Set `APIEDGE_REDIS_URL`; otherwise wait for the periodic reload (`APIEDGE_GATEWAY_RELOAD_INTERVAL_SECONDS`) |

Use the [packet inspector](user-guide/inspector.md) to see which policy made the decision.

## Analytics and inspector

| Symptom | Cause and fix |
|---|---|
| Analytics shows nothing | Only traffic through the gateway is counted, written every `APIEDGE_ANALYTICS_FLUSH_INTERVAL_SECONDS`; check the time range and filters |
| `/metrics` answers 404 | Set `APIEDGE_METRICS_TOKEN` (at least 16 characters) and send it as `Authorization: Bearer <token>` |
| A capture records nothing | Captures cover one API (optionally one route or consumer) for a limited time; check that it is active and that requests reach that API |
| Captured values show `***` | Masking is on by default; unmasked views need `inspector:unmask` and are audit-logged |
| The live view never updates behind a proxy | Disable response buffering for Server-Sent Events on the proxy |
