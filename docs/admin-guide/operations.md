<!-- Copyright 2026 OpenEdge Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Operations

How to run APIEdge day to day: as a service, behind TLS, backed up, monitored and kept within
its disk and memory budget. Settings named here are described in
[configuration](configuration.md).

## What runs where

`apiedge run` starts one process that serves

* the **web console and admin API** on `APIEDGE_HOST:APIEDGE_PORT` (default `127.0.0.1:8080`),
* the **gateway** on `APIEDGE_GATEWAY_HOST:APIEDGE_GATEWAY_PORT` (default `127.0.0.1:8081`),
  unless `APIEDGE_GATEWAY_ENABLED=false`.

It applies pending database migrations first (skip with `--no-migrate`). Stop it with Ctrl+C or
by stopping the service; in-flight analytics aggregates are flushed on a clean shutdown.

## Running as a service

The one-click installer can register APIEdge to start at logon for the installing user, with no
administrator rights (`--service`, or answer yes when asked):

| OS | What is registered | Manage it with |
|---|---|---|
| Linux | systemd user unit `~/.config/systemd/user/apiedge.service` (restarts on failure) | `systemctl --user status|restart|stop apiedge` |
| macOS | launchd agent `~/Library/LaunchAgents/com.apiedge.gateway.plist`, output in `<data dir>/apiedge.log` | `launchctl unload|load -w <plist>` |
| Windows | Startup-folder shortcut `APIEdge.lnk` (starts minimised at the next logon) | delete the shortcut, or `install.bat --no-service` |

A systemd *user* unit only runs while the user is logged in unless lingering is enabled
(`loginctl enable-linger <user>`). For a machine-wide service, run `apiedge run --no-migrate`
from your own system unit, Windows service wrapper or container, as an unprivileged user, with
the same environment. The [container image and Helm chart](../installation.md#10-docker-and-docker-compose)
are the supported server deployments.

## Exposing APIEdge on the network (TLS)

APIEdge does not terminate TLS itself yet (TLS profiles, keystores and mTLS are task T-023).
Keep both ports bound to `127.0.0.1` and put a TLS-terminating reverse proxy or load balancer in
front (nginx, HAProxy, Apache httpd, Traefik, or a Kubernetes ingress via the Helm chart's
`ingress.*` values). Then:

* set `APIEDGE_COOKIE_SECURE=true`, so session cookies are only sent over HTTPS;
* set `APIEDGE_GATEWAY_TRUSTED_PROXIES` to the proxy's address range, so IP filters and per-client
  rate limits see the real client address from `X-Forwarded-For` (never list networks that
  untrusted clients can connect from);
* keep `APIEDGE_CORS_ALLOW_ORIGINS` empty unless another web origin must call the admin API;
* HSTS is sent automatically on HTTPS requests (`APIEDGE_HSTS_MAX_AGE`);
* forward the `Host` header and allow Server-Sent Events (no response buffering) for
  `/api/v1/tenants/*/inspector/exchanges/stream`, the packet inspector's live view.

If you must bind directly to the network, set `APIEDGE_HOST` / `APIEDGE_GATEWAY_HOST` to
`0.0.0.0` and restrict access with a firewall.

## Backup and restore

Everything APIEdge keeps is in the **data directory** (`APIEDGE_DATA_DIR`; see the
[Installation Guide](../installation.md#2-run-the-one-click-installer) for the default per OS):

| File | What it is | Back up? |
|---|---|---|
| `apiedge.db` (with `apiedge.db-wal` / `apiedge.db-shm` while running) | SQLite database: tenants, users, products, APIs, policies, API key hashes, audit log, analytics, encrypted captures | yes (unless `APIEDGE_DATABASE_URL` points to PostgreSQL; then back up that database) |
| `secret.key` | Secrets master key (unless `APIEDGE_SECRET_KEY` / `APIEDGE_SECRET_KEY_FILE` is used) | **yes, and store it separately and securely** |
| `install.log`, `apiedge.log` | Installer log, macOS service output | optional |
| `venv/` | The installer's virtual environment | no (the installer recreates it) |

Without the secrets key, encrypted data cannot be recovered: MFA secrets, policy secrets (for
example JWT shared secrets) and captured traffic. Console sessions also end, because the session
signing key is derived from it unless `APIEDGE_JWT_SECRET` is set.

**Back up (SQLite)**, either with APIEdge stopped by copying `apiedge.db` and `secret.key`, or
while it runs with SQLite's online backup, using the Python of the APIEdge environment:

```
<venv>/bin/python -c "import sqlite3,sys; s=sqlite3.connect(sys.argv[1]); d=sqlite3.connect(sys.argv[2]); s.backup(d); d.close(); s.close()" <data dir>/apiedge.db apiedge-backup.db
```

(On Windows use `<venv>\Scripts\python.exe` and double quotes as shown.) Do not copy only
`apiedge.db` of a running instance: recent changes may still be in `apiedge.db-wal`.

**Back up (PostgreSQL)** with `pg_dump`, and back up the secrets key as above. With Docker
Compose, back up the `postgres-data` and `apiedge-data` volumes.

**Restore:** stop APIEdge, install the same (or a newer) APIEdge version, put the database and
`secret.key` back into the data directory (or restore the PostgreSQL dump), and start it.
`apiedge run` applies any newer migrations. Restoring into an *older* APIEdge version is not
supported.

## The secrets key

* Created by `apiedge init` (the installer and the container run it) as `<data dir>/secret.key`,
  readable only by the owner where the OS supports it. Or provide it with `APIEDGE_SECRET_KEY`
  (base64url-encoded 32 bytes) or `APIEDGE_SECRET_KEY_FILE`; in Kubernetes use the chart's
  `secretKey.existingSecret`.
* **Rotation:** set the new key as `APIEDGE_SECRET_KEY` and list the old key in
  `APIEDGE_SECRET_KEY_PREVIOUS`. New data is encrypted with the new key; existing data stays
  readable with the old one. There is no re-encryption command yet, so **keep the old key in
  `APIEDGE_SECRET_KEY_PREVIOUS` for as long as data encrypted with it exists**. Rotating the key
  also ends all console sessions (unless `APIEDGE_JWT_SECRET` is set).

## Logs

APIEdge writes structured logs to standard error: one JSON object per line by default
(`APIEDGE_LOG_FORMAT=json`), or readable text (`text`). Level: `APIEDGE_LOG_LEVEL`. Every request
gets an id, returned in the `X-Request-ID` response header and included in log lines and error
documents, so a user's error report can be matched to the log. Credentials (passwords, tokens,
API keys, cookies, `Authorization` headers) are masked, and the access log omits query strings.

Collect the logs with your service manager (`journalctl --user -u apiedge`), the container
runtime (`docker logs`, `kubectl logs`) or the macOS log file. Shipping to syslog, Splunk or ELK
is planned (T-028).

Security-relevant events (access denied, lockouts) are logged under `apiedge.security`.
Privileged changes are recorded in the **audit log** (console **Audit log**, or
`GET /api/v1/tenants/{id}/audit`), which is kept in the database.

## Monitoring

| Check | Endpoint | Meaning |
|---|---|---|
| Liveness | `GET /healthz` (console port) | the process is up |
| Readiness | `GET /readyz` (console port) | the database is reachable (503 otherwise) |
| Gateway liveness / readiness | `GET /-/healthz`, `GET /-/readyz` (gateway port) | the gateway is up / has loaded its configuration |
| Metrics | `GET /metrics` (console port, `Authorization: Bearer <APIEDGE_METRICS_TOKEN>`) | Prometheus counters and latency histograms per tenant and API; 404 until a token is set |

The probes are unauthenticated and disclose no version or error details. See the
[Analytics Guide](../user-guide/analytics.md#prometheus) for the metric names and a scrape
configuration.

## Disk and memory budget

| What grows | Bounded by |
|---|---|
| Analytics aggregates (per API, route, consumer, status and minute) | `APIEDGE_ANALYTICS_RETENTION_DAYS` (default 30) |
| Captured traffic | opt-in captures only; `APIEDGE_INSPECTOR_MAX_EXCHANGES`, `..._MAX_BODY_BYTES`, `..._MAX_DURATION_MINUTES`, `..._MAX_ACTIVE_SESSIONS`, deleted `APIEDGE_INSPECTOR_RETENTION_HOURS` after the capture ends |
| Capture write queue (memory) | `APIEDGE_INSPECTOR_QUEUE_MAX_BYTES` (exchanges beyond it are dropped) |
| Response cache (memory, per gateway process) | `APIEDGE_GATEWAY_CACHE_MAX_BYTES` |
| Rate-limit windows (memory, without Redis) | `APIEDGE_GATEWAY_RATE_LIMIT_MAX_KEYS` |
| Audit log | not purged automatically; it is the record of privileged changes |
| Request bodies | `APIEDGE_MAX_REQUEST_BODY_BYTES` (admin API), `APIEDGE_GATEWAY_MAX_REQUEST_BODY_BYTES` (gateway) |

## Scaling and high availability

One `apiedge run` process serves everything, and SQLite suits a single host. For more:

* use **PostgreSQL** (`APIEDGE_DATABASE_URL`, see the [Installation Guide](../installation.md#10-docker-and-docker-compose)
  for the driver) so several processes can share the configuration;
* set `APIEDGE_REDIS_URL` so configuration changes reach every gateway process at once and
  rate-limit counters are shared; without Redis, other processes pick changes up within
  `APIEDGE_GATEWAY_RELOAD_INTERVAL_SECONDS` and count rate limits separately;
* give every process the same secrets key and `APIEDGE_JWT_SECRET`.

Analytics in `/metrics` and the response cache are per process. Clustering, distributed gateways
managed by one control plane and rolling upgrades are planned (T-026); the Helm chart therefore
runs a single replica today.
