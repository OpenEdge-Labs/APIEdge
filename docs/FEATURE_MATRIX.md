<!--
Copyright 2026 OpenEdge Labs
SPDX-License-Identifier: Apache-2.0
-->

# APIEdge feature parity matrix

This is the living capability matrix for APIEdge (task T-020). For each capability it shows
which reference gateways offer it and where APIEdge stands, with the task that delivers it.
Every APIEdge entry is our own design and implementation. The descriptions below are written in
our own words and name capabilities only. They do not reproduce any vendor's code, UI text,
configuration formats or branding.

Last reviewed: 2026-11-02, against the code at the commit that adds this file.

## How to read the matrix

**Reference gateways** (column abbreviations):

| Column | Product family |
|--------|----------------|
| IBM | IBM API Connect with DataPower Gateway |
| Kong | Kong Gateway / Konnect |
| Apigee | Google Apigee |
| Azure | Azure API Management |
| AWS | Amazon API Gateway |
| Mule | MuleSoft Anypoint (Flex Gateway, API Manager) |
| WSO2 | WSO2 API Manager |
| Tyk | Tyk |
| Grav | Gravitee |

**Reference marks:** `Y` offered (built in, or as a first-party add-on or edition), `P` partial or
limited (for example only through another product of the same vendor, or only some of the
listed variants), `-` not offered natively. The marks are a coarse summary of public product
documentation as of late 2026. Several capabilities need a paid edition. The marks guide our
priorities and are not a procurement comparison.

**APIEdge status:**

| Status | Meaning |
|--------|---------|
| **Done** | Implemented, tested and documented; the task is closed |
| **Partial** | Part of the capability is done (the note says which part); the rest is planned |
| **Planned** | Covered by an open task in `APIProjectTask.md` |
| **Proposed** | Not covered by any task yet; proposed to the customer in "Vendor Proposals" |

## Summary

| Area | Done | Partial | Planned | Proposed |
|------|-----:|--------:|--------:|---------:|
| Lifecycle and governance | 4 | 2 | 5 | 0 |
| Console, administration and access control | 5 | 0 | 1 | 0 |
| Policy pipeline and assembly | 3 | 1 | 8 | 1 |
| Security | 4 | 2 | 10 | 1 |
| Protocols | 1 | 0 | 6 | 1 |
| Traffic management | 5 | 3 | 7 | 1 |
| Consumers and monetization | 0 | 1 | 4 | 0 |
| Operations and deployment | 3 | 1 | 6 | 1 |
| Observability | 4 | 0 | 4 | 0 |
| Testing | 0 | 1 | 2 | 0 |
| AI gateway | 0 | 0 | 5 | 0 |

## Lifecycle and governance

| Capability | IBM | Kong | Apigee | Azure | AWS | Mule | WSO2 | Tyk | Grav | APIEdge | Task | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Products that bundle APIs, with owners and a lifecycle | Y | P | Y | Y | P | Y | Y | Y | Y | **Done** | T-005 | Draft, published, deprecated, retired; owners are contacts, access comes from role grants |
| API lifecycle enforced at runtime | Y | P | P | P | P | Y | Y | P | Y | **Done** | T-006, T-007 | Deprecated APIs are served with a `Deprecation` header; retired APIs and APIs of retired products answer 410 |
| Hard multi-tenant isolation | Y | Y | Y | P | P | Y | Y | Y | Y | **Done** | T-003 | `tenant_id` on every tenant-owned row, filtered in the data-access layer; cross-tenant tests |
| Audit log of privileged actions | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Done** | T-003 | Viewable and filterable in the console |
| API versions | Y | P | Y | Y | Y | Y | Y | Y | Y | **Partial** | T-006, T-021 | Each API has a version label; version sets and revisions come with T-021 |
| OpenAPI import and export | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Partial** | T-011 | The admin API itself is OpenAPI-documented; importing and exporting gateway APIs is T-011 |
| Catalogs or environments (dev, test, prod) with promotion | Y | Y | Y | P | Y | Y | Y | P | Y | **Planned** | T-021 | |
| Revisions, change history and diff | Y | P | Y | Y | Y | Y | Y | P | Y | **Planned** | T-021 | The audit log already records who changed what, without a content diff |
| Approval workflows (publish, subscribe) | Y | P | P | Y | - | Y | Y | P | Y | **Planned** | T-021, T-027 | |
| API linting and style rules | Y | Y | Y | P | - | Y | Y | - | P | **Planned** | T-021 | |
| Deprecation and sunset notices to consumers | Y | P | P | P | - | Y | Y | P | Y | **Planned** | T-014, T-015 | Needs consumers and the developer portal |

## Console, administration and access control

| Capability | IBM | Kong | Apigee | Azure | AWS | Mule | WSO2 | Tyk | Grav | APIEdge | Task | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Web console for configuration (no-code forms) | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Done** | T-004 to T-008 | Tenants, users, roles, products, APIs, routes, upstreams, policies, inspector, analytics |
| Admin REST API covering everything the console does | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Done** | T-003 onward | OpenAPI document and interactive docs at `/docs` |
| Role-based access control with scoped grants | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Done** | T-003 | `resource:action` permissions, six built-in roles, custom roles, grants scoped to a tenant or a product |
| Multi-factor authentication for console users | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Done** | T-003 | TOTP with a replay guard |
| Session security (short-lived tokens, rotation, revocation) | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Done** | T-003 | Refresh rotation; all sessions end on password, role, MFA or status change |
| Console single sign-on (OIDC, SAML, LDAP) | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Planned** | T-023 | |

## Policy pipeline and assembly

| Capability | IBM | Kong | Apigee | Azure | AWS | Mule | WSO2 | Tyk | Grav | APIEdge | Task | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Ordered policy chain per API and per route | Y | Y | Y | Y | P | Y | Y | Y | Y | **Done** | T-008 | Fails closed; every policy decision is recorded for the packet inspector |
| Header, query and JSON body transformation | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Done** | T-008 | Set or remove headers, query parameters and JSON fields on request and response |
| Mock responses | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Done** | T-008 | Fixed status, headers and body |
| Visual drag-and-drop flow builder | Y | P | P | - | - | Y | Y | - | Y | **Partial** | T-009 | The form-based chain editor (add, reorder, enable) is done; the visual canvas is T-009 |
| Conditional flow (switch, operation switch, if) | Y | P | Y | Y | - | Y | Y | P | Y | **Planned** | T-022 | |
| Error flows (throw and catch) | Y | P | Y | Y | P | Y | Y | P | Y | **Planned** | T-022 | |
| Variables and visual data mapping | Y | P | Y | Y | Y | Y | Y | P | Y | **Planned** | T-022 | |
| Message validation (JSON Schema, XML Schema, OpenAPI) | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Planned** | T-022 | |
| Redaction and message logging policies | Y | Y | Y | Y | P | Y | Y | P | Y | **Planned** | T-022 | Inspector masking (T-012) already redacts captured traffic |
| XSLT and JSON-to-XML conversion | Y | P | Y | Y | - | Y | Y | Y | Y | **Planned** | T-022 | |
| Request routing to another backend by rule (invoke, proxy) | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Planned** | T-022 | Today each API proxies to its own weighted upstreams |
| Low-code scripted policies in a sandbox | Y | Y | Y | Y | P | Y | Y | Y | Y | **Planned** | T-010 | Restricted Python in an isolated worker |
| Packaged custom policy plug-ins (SDK) | P | Y | P | - | P | Y | Y | Y | Y | **Proposed** | VP-005 | |

## Security

| Capability | IBM | Kong | Apigee | Azure | AWS | Mule | WSO2 | Tyk | Grav | APIEdge | Task | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| API key authentication | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Done** | T-008 | Keys stored hashed; bound to a product until consumers arrive (T-014) |
| JWT validation (HMAC, RSA, RSA-PSS, ECDSA; JWKS) | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Done** | T-008 | Algorithm allow-list, no `none`, algorithm-confusion and weak-key protection, JWKS fetched through the SSRF guard |
| IP allow and deny lists | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Done** | T-008 | Trusted-proxy aware |
| CORS | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Done** | T-008 | |
| Upstream TLS | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Partial** | T-007, T-023 | Upstream certificates are always verified, with an optional CA bundle; TLS profiles and per-API trust stores are T-023 |
| Secrets protection | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Partial** | T-002, T-023 | Secrets are AES-256-GCM encrypted at rest with key rotation; vault integration is T-023 |
| OAuth 2.0 authorization server (client credentials, code with PKCE, refresh, introspection, revocation) | Y | Y | Y | P | P | P | Y | Y | Y | **Planned** | T-023 | |
| OpenID Connect | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Planned** | T-023 | |
| JWT generation | Y | Y | Y | P | - | Y | Y | Y | Y | **Planned** | T-023 | |
| Basic authentication with LDAP or Active Directory | Y | Y | P | P | P | Y | Y | Y | Y | **Planned** | T-023 | |
| Mutual TLS client authentication | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Planned** | T-023 | |
| HMAC request signatures | Y | Y | P | P | - | P | P | Y | Y | **Planned** | T-023 | |
| JSON and XML threat protection | Y | P | Y | Y | - | Y | Y | P | Y | **Planned** | T-023 | A global request body-size limit is already enforced (T-007) |
| WAF rules, bot detection and IP reputation | Y | P | P | P | Y | P | P | - | P | **Planned** | T-023 | |
| Gateway and console TLS termination with keystores | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Planned** | T-023 | Today both listeners serve HTTP and are meant to sit behind a TLS-terminating proxy |
| Secrets vault integration | Y | Y | P | Y | Y | Y | Y | Y | Y | **Planned** | T-023 | |
| Upstream (backend) authentication and credential injection | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Proposed** | VP-004 | |

## Protocols

| Capability | IBM | Kong | Apigee | Azure | AWS | Mule | WSO2 | Tyk | Grav | APIEdge | Task | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| REST / HTTP reverse proxy | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Done** | T-007 | Route matching with path parameters and wildcards, 404/405, hop-by-hop header handling, `X-Forwarded-*` |
| SOAP and WSDL, SOAP-to-REST, WS-Security | Y | P | Y | Y | P | Y | Y | P | Y | **Planned** | T-024 | |
| GraphQL proxy with depth and cost limits | Y | Y | Y | Y | P | Y | Y | Y | Y | **Planned** | T-024 | |
| gRPC with JSON transcoding | Y | Y | Y | Y | - | Y | Y | Y | Y | **Planned** | T-024 | |
| WebSocket | Y | Y | P | Y | Y | Y | Y | Y | Y | **Planned** | T-024 | |
| Server-Sent Events | Y | Y | Y | Y | P | Y | Y | Y | Y | **Planned** | T-024 | Responses are streamed today, but SSE is not yet a tested, supported mode |
| Event and async APIs (Kafka, MQTT, AMQP, IBM MQ; AsyncAPI) | Y | Y | P | P | P | Y | Y | P | Y | **Planned** | T-024 | |
| HTTP/2 to clients | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Proposed** | VP-006 | Also a prerequisite for native gRPC (T-024) |

## Traffic management

| Capability | IBM | Kong | Apigee | Azure | AWS | Mule | WSO2 | Tyk | Grav | APIEdge | Task | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Weighted load balancing across upstreams | Y | Y | Y | Y | P | Y | Y | Y | Y | **Done** | T-006, T-007 | Smooth weighted round-robin |
| Per-API timeouts | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Done** | T-007 | 504 on timeout |
| Rate limits and quotas | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Done** | T-008 | Fixed windows per consumer, IP or API; Redis-backed when configured, per process otherwise |
| Response caching | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Done** | T-008 | TTL, vary headers, optional per-caller caching of authenticated responses |
| Configuration hot reload without restart | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Done** | T-007 | In-process events, or Redis pub/sub across processes |
| Retries | Y | Y | Y | Y | P | Y | Y | Y | Y | **Partial** | T-007, T-025 | Connection failures are retried; timeouts and retryable statuses only for idempotent methods; backoff is T-025 |
| Canary, weighted and blue-green routing | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Partial** | T-006, T-025 | Weighted upstreams can split traffic; version-aware canary and blue-green switching are T-025 |
| Cache invalidation | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Partial** | T-008, T-025 | Entries expire by TTL; explicit invalidation is T-025 |
| More load-balancing algorithms (least connections, hashing, latency) | Y | Y | P | P | - | Y | Y | Y | Y | **Planned** | T-025 | |
| Active and passive health checks | Y | Y | Y | P | - | Y | Y | Y | Y | **Planned** | T-025 | |
| Circuit breaker | Y | Y | P | Y | - | Y | Y | Y | Y | **Planned** | T-025 | |
| Traffic mirroring | P | Y | P | P | - | P | P | P | Y | **Planned** | T-025 | |
| Service discovery (DNS SRV, Consul, Kubernetes) | P | Y | P | P | P | Y | Y | Y | Y | **Planned** | T-025 | |
| Response compression | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Planned** | T-025 | |
| Spike arrest and concurrency limits | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Planned** | T-025 | |
| Custom domains and host-based routing with per-domain certificates | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Proposed** | VP-003 | Today every API is reached under `/<tenant slug><base path>` on one listener |

## Consumers and monetization

| Capability | IBM | Kong | Apigee | Azure | AWS | Mule | WSO2 | Tyk | Grav | APIEdge | Task | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Consumer identification in analytics | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Partial** | T-008, T-013, T-014 | Analytics groups traffic by API key name or JWT subject; real consumers are T-014 |
| Plans, consumers, applications and subscriptions | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Planned** | T-014 | |
| Consumer organizations, app registration, credential rotation, plan approval | Y | P | Y | Y | P | Y | Y | Y | Y | **Planned** | T-027 | |
| Usage metering and billing export | Y | P | Y | P | P | P | Y | P | P | **Planned** | T-027 | Per-minute usage aggregates already exist (T-013) |
| Developer portal with try-it and SDK generation | Y | Y | Y | Y | P | Y | Y | Y | Y | **Planned** | T-015 | |

## Operations and deployment

| Capability | IBM | Kong | Apigee | Azure | AWS | Mule | WSO2 | Tyk | Grav | APIEdge | Task | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| On-premise installation | Y | Y | Y | Y | - | Y | Y | Y | Y | **Done** | T-001, T-019 | One-click installers for Windows, Linux and macOS; hash-verified dependencies |
| Separate control plane and data plane | Y | Y | Y | Y | - | Y | Y | Y | Y | **Done** | T-007 | Console and admin API on one port, gateway on another |
| Embedded default database, production database option | P | Y | - | - | - | - | Y | P | P | **Done** | T-001 | SQLite by default, PostgreSQL for production |
| Multi-node gateways with configuration sync | Y | Y | Y | Y | - | Y | Y | Y | Y | **Partial** | T-007, T-026 | Redis pub/sub already notifies every gateway process; clustering and node management are T-026 |
| Remote or federated gateways under one control plane | Y | Y | Y | Y | - | Y | Y | Y | Y | **Planned** | T-026 | |
| Rolling upgrades, backup and restore | Y | Y | P | Y | - | Y | Y | Y | Y | **Planned** | T-026 | |
| Declarative configuration (YAML, GitOps) and CLI import and export | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Planned** | T-026 | The `apiedge` CLI already covers init, migrate, run and create-admin |
| Container image and Docker Compose | Y | Y | Y | Y | - | Y | Y | Y | Y | **Planned** | T-016 | |
| Kubernetes Helm chart | Y | Y | Y | Y | - | Y | Y | Y | Y | **Planned** | T-016 | |
| Signed releases, SBOM and checksums | Y | Y | Y | Y | - | Y | Y | Y | Y | **Planned** | T-016 | |
| Kubernetes ingress controller / Gateway API and a Terraform provider | P | Y | P | Y | Y | P | Y | Y | Y | **Proposed** | VP-007 | |

## Observability

| Capability | IBM | Kong | Apigee | Azure | AWS | Mule | WSO2 | Tyk | Grav | APIEdge | Task | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Traffic debugger with a per-policy trace | Y | P | Y | Y | P | P | P | P | Y | **Done** | T-012 | Opt-in, time-boxed captures; live view (SSE); masking by default; HAR export; replay through the SSRF guard |
| Analytics dashboards (traffic, p50/p95/p99, errors, top APIs and consumers) | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Done** | T-013 | Time-range and API/consumer filters, CSV export |
| Prometheus metrics endpoint | Y | Y | - | P | - | P | Y | Y | Y | **Done** | T-013 | Token-protected |
| Structured logs with secret masking | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Done** | T-002 | JSON logs with request ids |
| OpenTelemetry tracing | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Planned** | T-028 | |
| Log shipping (syslog, Splunk, ELK) | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Planned** | T-028 | |
| Alerting (email, webhook, Slack) | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Planned** | T-028 | |
| SLA monitoring | Y | P | Y | P | P | Y | P | P | P | **Planned** | T-028 | |

## Testing

| Capability | IBM | Kong | Apigee | Azure | AWS | Mule | WSO2 | Tyk | Grav | APIEdge | Task | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Mocking and service virtualization | Y | Y | Y | Y | Y | Y | Y | Y | Y | **Partial** | T-008, T-029 | The mock policy returns fixed responses; virtual services are T-029 |
| API test suites | Y | Y | P | P | P | Y | P | P | P | **Planned** | T-029 | |
| Contract tests against OpenAPI | Y | Y | P | P | - | Y | P | P | P | **Planned** | T-029 | |

## AI gateway

| Capability | IBM | Kong | Apigee | Azure | AWS | Mule | WSO2 | Tyk | Grav | APIEdge | Task | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| LLM provider proxy | Y | Y | Y | Y | P | Y | Y | Y | Y | **Planned** | T-030 | |
| Token-based rate limits and quotas | Y | Y | Y | Y | P | Y | Y | Y | Y | **Planned** | T-030 | |
| Prompt guard and PII redaction | Y | Y | Y | Y | P | Y | Y | P | Y | **Planned** | T-030 | |
| Semantic cache | P | Y | Y | Y | - | P | Y | P | P | **Planned** | T-030 | |
| Model routing and fallback | P | Y | Y | Y | P | Y | Y | Y | Y | **Planned** | T-030 | |

## APIEdge platform hardening (beyond parity)

These controls are part of the APIEdge baseline whatever the reference gateways do. They are
mapped to OWASP items in `docs/SECURITY.md`.

| Control | Status | Task |
|---|---|---|
| SSRF guard on upstream URLs, JWKS fetches and inspector replay (private, link-local and metadata ranges blocked by default) | **Done** | T-002, T-006, T-008, T-012 |
| Security headers, strict CSP, CORS allow-list, CSRF protection for cookie sessions | **Done** | T-002 |
| Body-size limits on the admin API and the gateway; login throttling and lockout | **Done** | T-002, T-003, T-007 |
| Captured traffic encrypted at rest and masked by default; unmasked access audit-logged | **Done** | T-012 |
| Hash-locked dependencies, license gate, pip-audit and CodeQL in CI | **Done** | T-001, T-002, T-019 |
| OWASP ZAP baseline and ASVS L2 review before release | **Planned** | T-018 |

## Gaps proposed as new tasks

Capabilities that the reference gateways offer and that no task in `APIProjectTask.md` covers
yet are proposed to the customer as Vendor Proposals:

| Proposal | Capability |
|---|---|
| VP-003 | Custom domains and host-based routing, with per-domain TLS certificates (SNI) |
| VP-004 | Upstream authentication: inject backend credentials (basic, bearer, OAuth client-credentials tokens, signed requests) from encrypted secrets |
| VP-005 | A documented plug-in SDK for packaged custom Python policies |
| VP-006 | HTTP/2 between clients and the gateway |
| VP-007 | Kubernetes ingress controller / Gateway API support and a Terraform provider |

## Maintaining this matrix

- When a task changes a capability's status, update its row in the same commit and the summary
  counts above.
- Statuses must reflect the code, not task titles: mark a row **Done** only when the capability
  is implemented, tested and documented.
- Describe capabilities in our own words. Do not copy vendor documentation, UI text, policy
  names that are product-specific, or configuration formats.
