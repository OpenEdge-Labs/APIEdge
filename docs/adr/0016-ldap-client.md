<!-- Copyright 2026 OpenEdge Labs
     SPDX-License-Identifier: Apache-2.0 -->

# ADR 0016: In-house LDAPv3 client and the basic-ldap policy

- Status: accepted
- Date: 2026-11-06
- Task: T-023 (VP-010)

## Context

T-023 asks for basic authentication against LDAP or Active Directory. The only maintained
pure-Python client, `ldap3`, is LGPL-3.0, which the license policy does not allow. `python-ldap`
publishes no wheels and needs a C compiler and OpenLDAP headers, which conflicts with the
one-click installer. `bonsai` needs the system libldap on Linux.

## Decision

- **A minimal LDAPv3 client on the standard library** (`apiedge.security.ldap`): simple bind,
  search, StartTLS and unbind only. No referrals are followed.
- **Transport:** LDAPS by default, or StartTLS, always with certificate and host-name verification
  and TLS 1.2 or later. There is no way to turn verification off. Plain LDAP has to be chosen
  explicitly for a directory; the console labels it as being for isolated lab networks.
- **Hostile input:** BER decoding accepts definite lengths and low tag numbers only and bounds
  message size, nesting depth and element count. One response and one whole search each have a
  deadline, so a server that trickles data cannot hold a worker. User names only reach filters
  through RFC 4515 escaping and DNs through RFC 4514 escaping. Filter templates are parsed into BER
  by our own parser, which refuses malformed input.
- **Unauthenticated binds are refused:** an empty DN or password never reaches the server, because
  many servers report success for such a bind (RFC 4513 5.1.2).
- **Directories are tenant data** (`ldap_directories`, permissions `ldap:read` and `ldap:manage`).
  The service account's password is encrypted with the secrets box, bound to tenant and directory,
  never returned, and covered by `apiedge rotate-secrets`.
- **A stored password cannot be redirected:** changing a directory's host, port, security mode or
  truststore requires entering the password again. Otherwise anyone who can edit a directory could
  have the stored password sent to a server of their choice.
- **SSRF guard:** the host is checked when saved and on every connection, and the client connects
  to the addresses that were checked, not to a re-resolved name.
- **The `basic-ldap` policy** reads HTTP Basic credentials, runs the blocking check in a worker
  thread (at most 8 at once, 64 in total, then 503) and answers 503 if the directory cannot be
  used, so an outage never lets a request through and is not reported as a wrong password. It
  remembers results under an HMAC with a random per-policy salt: 60 seconds by default, at most 30
  seconds for refused credentials. A repeated wrong password therefore does not lock the account
  in the directory. A reload of the configuration empties this memory.

## Consequences

- We own a protocol implementation. It is small and is tested with malformed and fuzzed input, and
  against a real OpenLDAP server in CI (job `ldap-integration`, image pinned by digest, not shipped).
- A disabled account or changed password can keep working for up to the policy's `cache_seconds`.
  Setting it to 0 asks the directory on every request.
- Not covered yet: LDAP as the OAuth server's user registry and console single sign-on, both of
  which need a mapping from directory users to APIEdge user ids. SASL binds and client certificates
  towards the directory are not implemented.
