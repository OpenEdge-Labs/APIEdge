# APIEdge

**APIEdge** is an on-premise, multi-tenant **API Gateway** with a web console for designing, securing, publishing, debugging and monitoring APIs, using **no-code** and **low-code** tools.

> Status: early development (foundation delivered: T-001, T-019). Features are being delivered task by task; see [APIProjectTask.md](APIProjectTask.md) and [CHANGELOG.md](CHANGELOG.md).

## Quick start

You need **Python 3.10, 3.11 or 3.12**. The installer downloads everything else from PyPI and checks each file against pinned sha256 hashes. No Node.js is needed.

```
git clone https://github.com/OpenEdge-Labs/APIEdge.git
cd APIEdge
```

| Windows | macOS | Linux |
|---|---|---|
| double-click **`install.bat`** | double-click **`install.command`** | run **`./install.sh`** |

The installer creates a virtual environment and the database, asks for the first admin password (or generates one and shows it once), then starts APIEdge and opens the console at **http://localhost:8080/**. Run it again to upgrade or repair, or with `--uninstall` to remove it. Unattended: `--unattended`. All options are in the [Installation Guide](docs/installation.md).

Once installed, the `apiedge` command is available inside the environment:

```
apiedge run --open          # start the console, admin API and gateway
apiedge migrate             # apply database migrations
apiedge create-admin        # create a SuperAdmin
```

The console's admin panel (sign-in with MFA, tenants, users, roles and permissions, audit log, system settings) is described in [docs/admin-guide/access-control.md](docs/admin-guide/access-control.md); product management in [docs/user-guide/products.md](docs/user-guide/products.md); APIs and the no-code form editor in [docs/user-guide/apis.md](docs/user-guide/apis.md); calling published APIs through the gateway (default `http://127.0.0.1:8081/<tenant>/<base path>`) in [docs/user-guide/gateway.md](docs/user-guide/gateway.md); traffic dashboards, CSV export and the Prometheus `/metrics` endpoint in the [Analytics Guide](docs/user-guide/analytics.md).

Health probes: `GET /healthz` (liveness) and `GET /readyz` (database reachable).

## Planned features

- **Gateway runtime** (Python/FastAPI): routing, proxying, load balancing, a policy pipeline, hot reload
- **Products → APIs → Routes → Policies**, with lifecycle management
- **No-code**: form-based API configuration, a drag-and-drop policy flow builder, OpenAPI import/export, mocks
- **Low-code**: sandboxed Python script policies with an in-browser editor
- **Packet inspector**: live and recorded traffic capture, policy traces, HAR export, replay
- **Analytics**: traffic, latency and error dashboards for admins, plus Prometheus metrics
- **Security**: designed against the OWASP Top 10, the OWASP API Security Top 10 and ASVS L2
- **Runs everywhere**: Windows, Linux and macOS, with one-click installers, pip, standalone executables and Docker

## Development

```
python scripts/install.py --local --dev --no-start    # ./.venv with ruff, mypy, bandit, pytest, pip-audit
.venv/bin/ruff check . && .venv/bin/mypy && .venv/bin/pytest     # Windows: .venv\Scripts\...
cd console && npm ci && npm test && npm run build     # only when changing the console (Node.js 20+)
```

Dependencies are pinned with hashes in `requirements/*.lock`. To change them, edit `requirements/*.in` and run `python scripts/update-locks.py`. Third-party packages are never committed; the prebuilt console in `src/apiedge/static/` is. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [ADR 0002](docs/adr/0002-online-hash-locked-installer.md).

## Documentation

- [Installation Guide](docs/installation.md)
- [Configuration (Administrator Guide)](docs/admin-guide/configuration.md)
- [Access control: sign-in, tenants, users, roles, audit](docs/admin-guide/access-control.md)
- [Products (User Guide)](docs/user-guide/products.md)
- [APIs (User Guide)](docs/user-guide/apis.md)
- [Gateway (User Guide)](docs/user-guide/gateway.md)
- [Analytics Guide](docs/user-guide/analytics.md)
- [Security and OWASP mapping](docs/SECURITY.md)
- [Architecture](docs/ARCHITECTURE.md) and [ADRs](docs/adr/)
- [Third-party licenses](THIRD_PARTY_LICENSES.md)

## License

Licensed under the [Apache License 2.0](LICENSE). Copyright © 2026 OpenEdge Labs.
