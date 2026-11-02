# APIEdge

**APIEdge** is an on-premise, multi-tenant **API Gateway** with a web console for designing, securing, publishing, debugging and monitoring APIs, using **no-code** and **low-code** tools.

> Status: early development (0.1 pre-releases). The console, admin API, gateway with built-in policies, packet inspector, analytics and release packaging are delivered; low-code scripting, the flow builder, consumers and plans are upcoming. See [APIProjectTask.md](APIProjectTask.md), the [feature parity matrix](docs/FEATURE_MATRIX.md) and [CHANGELOG.md](CHANGELOG.md).

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

Other ways to run it: a pip wheel, a multi-arch Docker image with `docker compose` (APIEdge, PostgreSQL and Valkey) and a Helm chart; see the [Installation Guide](docs/installation.md) sections 9 to 12, which also explain how to verify release checksums and the CycloneDX SBOM. Maintainers: [docs/releasing.md](docs/releasing.md).

Once installed, the `apiedge` command is available inside the environment:

```
apiedge run --open          # start the console, admin API and gateway
apiedge migrate             # apply database migrations
apiedge create-admin        # create a SuperAdmin
```

The console's admin panel (sign-in with MFA, tenants, users, roles and permissions, audit log, system settings) is described in [docs/admin-guide/access-control.md](docs/admin-guide/access-control.md); product management in [docs/user-guide/products.md](docs/user-guide/products.md); APIs and the no-code form editor in [docs/user-guide/apis.md](docs/user-guide/apis.md); calling published APIs through the gateway (default `http://127.0.0.1:8081/<tenant>/<base path>`) in [docs/user-guide/gateway.md](docs/user-guide/gateway.md); API keys, JWT validation, rate limits, transforms, CORS, IP filters, caching and mocks in [docs/user-guide/policies.md](docs/user-guide/policies.md); traffic dashboards, CSV export and the Prometheus `/metrics` endpoint in the [Analytics Guide](docs/user-guide/analytics.md); traffic capture, policy traces, HAR export and replay in the [Packet Inspector Guide](docs/user-guide/inspector.md).

Health probes: `GET /healthz` (liveness) and `GET /readyz` (database reachable).

## Features

Available now:

- **Gateway runtime**: per-tenant routing, weighted load balancing, timeouts and retries, verified TLS to upstreams, SSRF guard at connect time, lifecycle enforcement, hot reload
- **Products -> APIs -> Routes -> Policies**, with lifecycle management and no-code form editors
- **Policies**: API key, JWT validation, rate limits and quotas, transforms, CORS, IP allow/deny, response cache, mock responses
- **Packet inspector**: opt-in captures, policy-by-policy traces, live view, masking, HAR export, replay
- **Analytics**: traffic, latency and error dashboards, CSV export, Prometheus metrics
- **Security**: RBAC on every admin route, tenant isolation in the data layer, TOTP MFA, audit log; designed against the OWASP Top 10, the OWASP API Security Top 10 and ASVS L2
- **Runs everywhere**: Windows, Linux and macOS, with one-click installers, pip, Docker / Compose and Helm

Upcoming: the drag-and-drop policy flow builder (T-009), sandboxed Python script policies (T-010), OpenAPI import/export (T-011), plans and consumers (T-014), the developer portal (T-015) and the enterprise capabilities in the [feature parity matrix](docs/FEATURE_MATRIX.md).

## Development

```
python scripts/install.py --local --dev --no-start    # ./.venv with ruff, mypy, bandit, pytest, pip-audit
.venv/bin/ruff check . && .venv/bin/mypy && .venv/bin/pytest     # Windows: .venv\Scripts\...
cd console && npm ci && npm test && npm run build     # only when changing the console (Node.js 20+)
.venv/bin/python scripts/export-openapi.py             # after changing admin routes: regenerate the API reference
```

Dependencies are pinned with hashes in `requirements/*.lock`. To change them, edit `requirements/*.in` and run `python scripts/update-locks.py`. Third-party packages are never committed; the prebuilt console in `src/apiedge/static/` is. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [ADR 0002](docs/adr/0002-online-hash-locked-installer.md).

## Documentation

The documentation is also built as a static site (`mkdocs build --strict`, see [docs/releasing.md](docs/releasing.md)) and shipped with every release as `apiedge-<version>-docs.zip`.

- [Documentation home](docs/index.md)
- [Installation Guide](docs/installation.md) and [Upgrade notes](docs/upgrading.md)
- Administrator Guide: [overview](docs/admin-guide/index.md), [configuration](docs/admin-guide/configuration.md), [access control](docs/admin-guide/access-control.md), [operations (TLS, backup, monitoring)](docs/admin-guide/operations.md)
- User Guide: [overview and first API](docs/user-guide/index.md), [products](docs/user-guide/products.md), [APIs](docs/user-guide/apis.md), [policies](docs/user-guide/policies.md), [gateway](docs/user-guide/gateway.md), [low-code status](docs/user-guide/low-code.md)
- [Packet Inspector Guide](docs/user-guide/inspector.md) and [Analytics Guide](docs/user-guide/analytics.md)
- Admin API: [guide](docs/api/index.md), [reference](docs/api/reference.md), [OpenAPI document](docs/api/openapi.json)
- [Troubleshooting](docs/troubleshooting.md)
- [Security and OWASP mapping](docs/SECURITY.md)
- [Architecture](docs/ARCHITECTURE.md) and [decision records](docs/adr/index.md)
- [Feature parity matrix](docs/FEATURE_MATRIX.md)
- [Third-party licenses](THIRD_PARTY_LICENSES.md)

## License

Licensed under the [Apache License 2.0](LICENSE). Copyright © 2026 OpenEdge Labs.
