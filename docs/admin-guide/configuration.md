# Configuration (Administrator Guide)

APIEdge reads `APIEDGE_*` environment variables, optionally from a `.env` file in the working
directory (see `.env.example`). Command-line options `--data-dir` and `--database-url` override them.

| Variable | Default | Notes |
|---|---|---|
| `APIEDGE_ENV` | `production` | `development` enables the interactive API docs at `/api/docs` |
| `APIEDGE_DATA_DIR` | OS user data dir | Holds the SQLite database and the installer venv |
| `APIEDGE_DATABASE_URL` | SQLite in the data dir | PostgreSQL: `postgresql+psycopg://user:pass@host/db` (install `apiedge[postgres]`) |
| `APIEDGE_HOST` | `127.0.0.1` | Set `0.0.0.0` to accept remote connections (put TLS in front until T-002/T-007) |
| `APIEDGE_PORT` | `8080` | |
| `APIEDGE_LOG_LEVEL` | `info` | `critical`, `error`, `warning`, `info`, `debug` |

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
