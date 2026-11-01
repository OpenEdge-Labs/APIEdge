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

See `docs/SECURITY.md` for what each security setting protects against and how to rotate the
secrets key.
