# Configuration (Administrator Guide)

APIEdge reads `APIEDGE_*` environment variables, optionally from a `.env` file in the working
directory (see `.env.example`). Command-line options `--data-dir` and `--database-url` override them.

| Variable | Default | Notes |
|---|---|---|
| `APIEDGE_ENV` | `production` | `development` enables the interactive API docs at `/api/docs` |
| `APIEDGE_DATA_DIR` | OS user data dir | Holds the SQLite database and the installer venv |
| `APIEDGE_DATABASE_URL` | SQLite in the data dir | PostgreSQL: `postgresql+psycopg://user:pass@host/db` (install `apiedge[postgres]`) |
| `APIEDGE_HOST` | `127.0.0.1` | Set `0.0.0.0` to accept remote connections (put a TLS-terminating proxy in front until TLS ships with T-016/T-023) |
| `APIEDGE_PORT` | `8080` | |
| `APIEDGE_LOG_LEVEL` | `info` | `critical`, `error`, `warning`, `info`, `debug` |
| `APIEDGE_LOG_FORMAT` | `json` | `json` (one masked JSON object per line) or `text`. Credentials are masked in both |
| `APIEDGE_CORS_ALLOW_ORIGINS` | empty (same-origin only) | Comma-separated exact origins (`https://host[:port]`) allowed to call the admin API with credentials; `*` is rejected |
| `APIEDGE_MAX_REQUEST_BODY_BYTES` | `2097152` (2 MiB) | Larger request bodies get `413` |
| `APIEDGE_HSTS_MAX_AGE` | `31536000` | HSTS max-age, sent only on HTTPS requests; `0` disables |
| `APIEDGE_SECRET_KEY` | unset | Base64url 32-byte master key for secrets encryption. If unset, `<data dir>/secret.key` (created by `apiedge init`) is used. **Back it up** |
| `APIEDGE_SECRET_KEY_PREVIOUS` | empty | Comma-separated old keys still accepted for decryption during rotation |
| `APIEDGE_SECRET_KEY_FILE` | `<data dir>/secret.key` | Alternative key file location |
| `APIEDGE_SSRF_ALLOW_PRIVATE` | `false` | Allow private, loopback and link-local upstreams (on-prem). Cloud metadata stays blocked |
| `APIEDGE_SSRF_ALLOW_CIDRS` | empty | Comma-separated CIDRs always allowed as upstreams (preferred over `ALLOW_PRIVATE`) |
| `APIEDGE_SSRF_DENY_CIDRS` | empty | Comma-separated CIDRs always blocked (wins over every allow) |
| `APIEDGE_GATEWAY_ENABLED` | `true` | Serve the gateway (data plane) from `apiedge run` |
| `APIEDGE_GATEWAY_HOST` | `127.0.0.1` | Gateway bind address; `0.0.0.0` to accept API consumers from the network |
| `APIEDGE_GATEWAY_PORT` | `8081` | Gateway port. APIs are served at `/<tenant slug><base path>` (see [the gateway guide](../user-guide/gateway.md)) |
| `APIEDGE_GATEWAY_MAX_REQUEST_BODY_BYTES` | `10485760` (10 MiB) | Larger request bodies get `413` from the gateway |
| `APIEDGE_GATEWAY_RETRIES` | `1` | Extra attempts (0-5) on another upstream: connection failures for every method, timeouts and 502/503/504 only for idempotent methods |
| `APIEDGE_GATEWAY_CA_BUNDLE` | public CAs | PEM file of CAs trusted for HTTPS upstreams (internal CAs). Certificates are always verified |
| `APIEDGE_GATEWAY_RELOAD_INTERVAL_SECONDS` | `30` | Periodic configuration reload as a safety net (`0` = only on change events) |
| `APIEDGE_REDIS_URL` | unset | Optional Redis (`redis://[:password@]host:6379/0`, `rediss://` for TLS) carrying configuration change events between processes and hosts, and the rate-limit counters of the policies (T-008). Without it, changes reach the gateway in the same process at once and other processes via the periodic reload |
| `APIEDGE_GATEWAY_TRUSTED_PROXIES` | empty | Comma-separated CIDRs of load balancers / reverse proxies in front of the gateway. Only when the direct peer is one of them is `X-Forwarded-For` used (read from the right) to find the client address for IP filters and rate limits. Never list networks that untrusted clients can connect from |
| `APIEDGE_GATEWAY_CACHE_MAX_BYTES` | `67108864` (64 MiB) | Memory for the response cache policy per gateway process (least recently used entries are evicted; `0` turns caching off) |
| `APIEDGE_GATEWAY_RATE_LIMIT_MAX_KEYS` | `100000` | Rate-limit windows kept in memory per process. With `APIEDGE_REDIS_URL` the counters live in Redis and are shared by all gateway processes; while Redis is unreachable each process falls back to its own counters |
| `APIEDGE_ANALYTICS_FLUSH_INTERVAL_SECONDS` | `10` | How often the gateway writes its per-minute analytics aggregates to the database (1-300) |
| `APIEDGE_ANALYTICS_RETENTION_DAYS` | `30` | Analytics older than this are deleted (checked hourly; 1-3650) |
| `APIEDGE_INSPECTOR_POLL_INTERVAL_SECONDS` | `1.0` | How often the gateway picks up capture sessions and writes captured exchanges (0.1-60) |
| `APIEDGE_INSPECTOR_MAX_DURATION_MINUTES` | `60` | Longest capture a user may start (1-1440) |
| `APIEDGE_INSPECTOR_MAX_EXCHANGES` | `1000` | Largest ring buffer (exchanges kept) per capture |
| `APIEDGE_INSPECTOR_MAX_BODY_BYTES` | `65536` | Largest body size captured per request/response (0-1 MiB) |
| `APIEDGE_INSPECTOR_MAX_ACTIVE_SESSIONS` | `10` | Active captures per tenant |
| `APIEDGE_INSPECTOR_RETENTION_HOURS` | `24` | Captured exchanges are deleted this long after their capture ended |
| `APIEDGE_INSPECTOR_QUEUE_MAX_BYTES` | `16777216` | Memory the gateway may hold for exchanges not yet written; beyond it exchanges are dropped |
| `APIEDGE_INSPECTOR_MASK_FIELDS` | empty | Comma-separated field, header and parameter names masked in every capture, on top of the built-in list. See the [Packet Inspector Guide](../user-guide/inspector.md) |
| `APIEDGE_METRICS_TOKEN` | unset | Enables the Prometheus endpoint `GET /metrics` on the console port, protected by this bearer token (at least 16 characters). Unset: the endpoint answers 404. See the [Analytics Guide](../user-guide/analytics.md) |
| `APIEDGE_ACCESS_TOKEN_TTL_SECONDS` | `900` | Lifetime of console access tokens (60-3600) |
| `APIEDGE_REFRESH_TOKEN_TTL_HOURS` | `12` | Absolute lifetime of a sign-in session (refresh token family) |
| `APIEDGE_LOGIN_MAX_FAILURES` | `5` | Failed sign-ins (password or MFA code) before the account locks |
| `APIEDGE_LOGIN_LOCKOUT_MINUTES` | `15` | How long a locked account stays locked (admins can unlock earlier) |
| `APIEDGE_LOGIN_RATE_LIMIT_PER_MINUTE` | `20` | Sign-in attempts per client IP per minute (429 above) |
| `APIEDGE_JWT_SECRET` | derived from the secrets key | Access-token signing key (at least 32 bytes). Without it and without a secrets key, a random per-process key is used and sessions end at restart |
| `APIEDGE_COOKIE_SECURE` | `false` | Always mark session cookies `Secure` (set behind a TLS-terminating proxy; HTTPS requests get it automatically) |

## Commands

| Command | Purpose |
|---|---|
| `apiedge init` | Create the data directory and database (runs migrations) |
| `apiedge migrate` | Apply database migrations (idempotent) |
| `apiedge run [--host H] [--port P] [--open]` | Start the console, admin API and gateway (migrates first) |
| `apiedge create-admin [--username U] [--generate-password \| --password-stdin] [--if-missing]` | Create a SuperAdmin. The password is Argon2id-hashed. A generated password is printed once |
| `apiedge version` | Print the version |

## Health probes

`GET /healthz` returns 200 `{"status":"ok"}` while the process is up. `GET /readyz` returns 200 when the
database is reachable and 503 `{"status":"unavailable"}` otherwise. Both are unauthenticated and
disclose no version or error details.

Users, roles, tenants and the audit log are described in [access-control.md](access-control.md).

See `docs/SECURITY.md` for what each security setting protects against and how to rotate the
secrets key.
