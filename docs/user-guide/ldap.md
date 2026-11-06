<!-- Copyright 2026 OpenEdge Labs
     SPDX-License-Identifier: Apache-2.0 -->

# LDAP and Active Directory

APIs can accept HTTP Basic credentials and check them against your LDAP or Active Directory server.
You set this up in two steps: add the **directory** to the tenant, then add a **Basic
authentication (LDAP)** policy to the API.

## Add a directory

Open **LDAP directories** in the console (permission `ldap:manage`).

| Setting | Meaning |
|---|---|
| Host, port | The directory server. It must pass the [SSRF guard](../admin-guide/configuration.md): private addresses need `APIEDGE_SSRF_ALLOW_PRIVATE` or `APIEDGE_SSRF_ALLOW_CIDRS` |
| Security | **LDAPS** (default, port 636), **StartTLS** (port 389) or **Plain LDAP** (no encryption: passwords cross the network readable, so use it only on isolated lab networks) |
| CAs that verify the server | A truststore from **TLS & certificates**, or the system certificate store. The certificate and host name are always verified |
| Service account bind DN and password | The account used to search for users. Leave empty to search anonymously or to use a DN template |
| User base DN and filter | Where and how to find a user. `{username}` is replaced by the escaped user name |
| User DN template | Instead of searching, bind directly as this DN, for example `uid={username},ou=people,dc=example,dc=com` or `{username}@corp.example` |
| User name attribute | The attribute shown as the consumer name in analytics |

Typical values:

| Server | User base DN | User filter |
|---|---|---|
| OpenLDAP | `ou=people,dc=example,dc=com` | `(uid={username})` |
| Active Directory | `dc=corp,dc=example,dc=com` | `(&(objectClass=user)(sAMAccountName={username}))` |

Select **Test** to connect and sign in with the service account.

The service account's password is stored encrypted and is never shown again. You have to enter it
again when you change the host, port, security or truststore, so nobody can have the stored
password sent to a different server.

A directory used by a policy cannot be deleted, and a truststore used by a directory cannot be
deleted.

## Protect an API

Add the **Basic authentication (LDAP)** policy to the API's chain:

| Setting | Meaning |
|---|---|
| Directory id | The id shown on the LDAP directories page. The directory must belong to the same tenant |
| Realm | The name browsers show when asking for credentials |
| Remember results for (s) | How long a checked password is remembered, default 60; 0 asks the directory on every request |
| Do not forward the credentials | Removes the `Authorization` header before the upstream (on by default) |
| Send the user name in header | Optional: the verified user name is sent upstream in this header; a value sent by the client is replaced |

Call the API with the user's credentials over HTTPS:

```bash
curl -u alice https://gateway.example.com/acme/orders/items
```

| Answer | Meaning |
|---|---|
| **401** with `WWW-Authenticate: Basic` | Credentials are missing, malformed or wrong, the user is unknown, or the filter matched more than one user |
| **503** | The directory cannot be used: unreachable, TLS failure, service account refused, blocked by the SSRF guard, or the directory was deleted. No request gets through while this lasts |

Consumers appear in analytics as `ldap:<user name>`, and a rate limit keyed by consumer applies per
user.

## Good to know

- A disabled user or changed password can keep working until the remembered result expires. Set
  **Remember results for** to 0 if that matters more to you than the extra load on the directory.
- Refused credentials are remembered for at most 30 seconds, so a client that repeats a wrong
  password does not lock the account in the directory. Different wrong passwords do reach it, so
  put a [rate limit](policies.md) in front of this policy, keyed by client address.
- Passwords are not stored by the gateway: only a salted digest is kept, in memory, and it is
  cleared when the configuration reloads.
- Referrals are not followed, and only simple binds are supported.
- LDAP sign-in for the OAuth authorization server and for the console is not available yet.
