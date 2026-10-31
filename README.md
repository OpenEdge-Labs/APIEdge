# APIEdge

**APIEdge** is an on-premise, multi-tenant **API Gateway** with a web console for designing, securing, publishing, debugging and monitoring APIs, using **no-code** and **low-code** tools.

> Status: early development. Features are being delivered task by task; see [APIProjectTask.md](APIProjectTask.md) and [CHANGELOG.md](CHANGELOG.md).

## Planned features

- **Gateway runtime** (Python/FastAPI): routing, proxying, load balancing, a policy pipeline, hot reload
- **Products → APIs → Routes → Policies**, with lifecycle management
- **No-code**: form-based API configuration, a drag-and-drop policy flow builder, OpenAPI import/export, mocks
- **Low-code**: sandboxed Python script policies with an in-browser editor
- **RBAC and multi-tenancy** throughout, with an admin panel and an audit log
- **Packet inspector**: live and recorded traffic capture, policy traces, HAR export, replay
- **Analytics**: traffic, latency and error dashboards for admins, plus Prometheus metrics
- **Security**: designed against the OWASP Top 10, the OWASP API Security Top 10 and ASVS L2
- **Runs everywhere**: Windows, Linux and macOS, with pip, offline bundles, standalone executables and Docker

## Documentation

Installation, administrator, user, inspector, analytics, API reference and security guides will be published in [docs/](docs/) as features land.

## License

Licensed under the [Apache License 2.0](LICENSE). Copyright © 2026 Alingan Patra.
