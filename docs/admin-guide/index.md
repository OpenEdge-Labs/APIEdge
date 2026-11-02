<!-- Copyright 2026 OpenEdge Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Administrator Guide

This guide is for the people who install, configure and operate APIEdge. Users who build and
publish APIs should read the [User Guide](../user-guide/index.md).

| Page | Covers |
|---|---|
| [Configuration](configuration.md) | Every `APIEDGE_*` setting, the `apiedge` commands, health probes, container-only settings |
| [Access control](access-control.md) | Signing in and MFA, tenants, users, roles and permissions, product-scoped grants, system settings, the audit log |
| [Operations](operations.md) | Running as a service, exposing APIEdge with TLS, backup and restore, the secrets key, logs, monitoring, data retention, scaling |
| [Upgrade notes](../upgrading.md) | Upgrading each kind of installation, and version-specific notes |
| [Troubleshooting](../troubleshooting.md) | Symptoms, causes and fixes |
| [Security](../SECURITY.md) | The OWASP mapping, CI security gates and security-relevant settings |

## First steps after installing

1. **Sign in** at `http://localhost:8080/` as the first SuperAdmin (`admin` unless you chose
   another name) with the password you entered or that the installer generated. You must choose a
   new password at once (12-128 characters, not containing the username, not a common password).
2. **Turn on MFA** for your account under **My account** (any TOTP authenticator app).
3. **Create a tenant** under **Tenants**. A tenant is the isolation boundary: its users, products,
   APIs, captures and analytics are invisible to every other tenant. Its *slug* becomes the first
   path segment of its APIs on the gateway (`/<slug>/...`).
4. **Create users** in the tenant under **Users** and grant them roles, tenant-wide or for one
   product (see [access control](access-control.md)). The built-in roles are `TenantAdmin`,
   `ProductOwner`, `APIDeveloper`, `Viewer` and `Consumer`; `SuperAdmin` is platform-wide.
5. **Review the configuration** under **System settings** (read-only) and change it with
   `APIEDGE_*` environment variables or a `.env` file (see [configuration](configuration.md)).
6. **Back up** the data directory, in particular the secrets key (see [operations](operations.md)).

## Who can do what

APIEdge permissions have the form `resource:action` (for example `api:publish`). Every admin API
route checks its permission on the server; the console only hides what you cannot do. The
permission each operation needs is listed in the [Admin API reference](../api/reference.md), and
every privileged change is written to the audit log.
