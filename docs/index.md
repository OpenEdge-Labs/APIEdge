<!-- Copyright 2026 OpenEdge Labs
     SPDX-License-Identifier: Apache-2.0 -->

# APIEdge documentation

**APIEdge** is an on-premise, multi-tenant **API Gateway** with a web console. Teams design,
secure, publish, debug and monitor APIs with no-code forms, and the gateway serves them. It runs
on Windows, macOS and Linux, from a one-click installer, a pip wheel, a container image or a Helm
chart.

> APIEdge is in early development (0.1 pre-releases). This documentation describes what is
> delivered today. Features that are planned but not yet available are marked as **upcoming**,
> with the task that will deliver them; see the [feature parity matrix](FEATURE_MATRIX.md) for the
> full roadmap.

## Where to start

| I want to... | Read |
|---|---|
| Install APIEdge (Windows, macOS, Linux, pip, Docker, Kubernetes) | [Installation Guide](installation.md) |
| Upgrade an existing installation | [Upgrade notes](upgrading.md) |
| Configure, secure, back up and run APIEdge | [Administrator Guide](admin-guide/index.md) |
| Publish my first API through the gateway | [User Guide](user-guide/index.md) |
| Debug live traffic | [Packet Inspector Guide](user-guide/inspector.md) |
| See traffic, latency and errors | [Analytics Guide](user-guide/analytics.md) |
| Automate APIEdge from scripts or CI | [Admin API guide](api/index.md) and [reference](api/reference.md) |
| Fix a problem | [Troubleshooting](troubleshooting.md) |
| Review the security design | [Security and OWASP mapping](SECURITY.md) |
| Understand the internals | [Architecture](ARCHITECTURE.md) and [decision records](adr/index.md) |

## What is in the box

| Area | Available now |
|---|---|
| Console and admin API | Sign-in with TOTP MFA, tenants, users, built-in and custom roles, product-scoped grants, audit log, read-only system settings |
| Products and APIs | Products with owners and lifecycle; APIs with base path, version, weighted upstreams, routes and lifecycle, edited in a no-code form |
| Gateway | Routing per tenant, load balancing, timeouts and retries, verified TLS to upstreams, SSRF guard at connect time, lifecycle enforcement, hot reload |
| Policies | API key, JWT validation, rate limit and quota, header/query/body transform, CORS, IP allow/deny, response cache, mock response |
| Packet inspector | Opt-in, time-boxed captures with policy-by-policy traces, live view, masking, HAR export and replay |
| Analytics | Per-minute aggregates, p50/p95/p99 latency, errors, top APIs and consumers, CSV export, Prometheus `/metrics` |
| Shipping | One-click installers, wheel, multi-arch image, Docker Compose, Helm chart, CycloneDX SBOM, checksums |

**Upcoming** (not available yet): the visual policy flow builder (T-009), low-code Python script
policies (T-010, see [Low-code](user-guide/low-code.md)), OpenAPI import and export of APIs
(T-011), plans, consumers and subscriptions (T-014) and the developer portal (T-015).

## Ports at a glance

| Port (default) | Serves |
|---|---|
| `8080` (`APIEDGE_PORT`) | Web console, admin API (`/api/v1`), `/healthz`, `/readyz`, `/metrics` |
| `8081` (`APIEDGE_GATEWAY_PORT`) | The gateway: published APIs at `/<tenant slug><base path>`, probes `/-/healthz`, `/-/readyz` |

Both bind to `127.0.0.1` by default. See [Configuration](admin-guide/configuration.md) to expose
them.

## License

APIEdge is licensed under the Apache License 2.0. Copyright 2026 OpenEdge Labs. The repository
contains the `LICENSE` and `NOTICE` files and `THIRD_PARTY_LICENSES.md`, which lists the license
of every third-party package.
