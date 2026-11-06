<!-- Copyright 2026 OpenEdge Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Architecture decision records

Each record states the context, the decision and its consequences. New significant decisions
(dependencies, services, data model, protocols) get a new record; accepted records are not
rewritten, they are superseded.

| ADR | Decision | Task |
|---|---|---|
| [0001](0001-python-fastapi-sqlite-default.md) | Python/FastAPI single process, SQLite by default | T-001 |
| [0002](0002-online-hash-locked-installer.md) | Online, hash-locked one-click installer | T-019 |
| [0003](0003-security-foundation.md) | Security foundation: HTTP hardening, secrets encryption, SSRF guard | T-002 |
| [0004](0004-auth-tenancy-rbac.md) | Authentication, multi-tenancy and RBAC core | T-003 |
| [0005](0005-products.md) | Products, owners and product-scoped access | T-005 |
| [0006](0006-apis.md) | APIs, upstreams and routes inside products | T-006 |
| [0007](0007-gateway-runtime.md) | Gateway runtime | T-007 |
| [0008](0008-analytics.md) | Gateway analytics and Prometheus metrics | T-013 |
| [0009](0009-policies.md) | Built-in policies and the policy pipeline | T-008 |
| [0010](0010-packet-inspector.md) | Packet inspector | T-012 |
| [0011](0011-release-packaging.md) | Release packaging, SBOM and signing | T-016 |
| [0012](0012-documentation-site.md) | Documentation site and generated Admin API reference | T-017 |
| [0013](0013-tls-and-client-certificates.md) | Native TLS, keystores, truststores and client certificates | T-023 |
| [0014](0014-python-3-11-to-3-13.md) | Supported Python range 3.11 to 3.13 | T-032 |
| [0015](0015-oauth-authorization-server.md) | Built-in OAuth 2.0 authorization server and OpenID Connect provider | T-023 |
| [0016](0016-ldap-client.md) | In-house LDAPv3 client and the basic-ldap policy | T-023 |
