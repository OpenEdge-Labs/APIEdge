# ADR 0013: Native TLS, keystores, truststores and client certificates

- Status: accepted
- Date: 2026-11-03
- Task: T-023

## Context

APIEdge served HTTP only; TLS needed a reverse proxy (security finding F-02). T-023 asks for TLS
profiles, keystores and truststores, and mTLS. The runtime set has no X.509 library: the
`cryptography` package was rejected in T-002 (no macOS x86_64 wheel for current releases, open
advisories on the last one with that wheel), and dependencies must be pure Python or have
wheels for every supported platform. The gateway is multi-tenant on one shared listener: a
client certificate trusted for one tenant must not open another tenant's APIs.

## Decision

* **Listeners**: the console and gateway listeners terminate TLS with the standard library
  `ssl` module, configured from PEM files in settings (`APIEDGE_TLS_*`,
  `APIEDGE_GATEWAY_TLS_*`): TLS 1.2 minimum (1.3 optional), forward secret AEAD ciphers, no
  compression or renegotiation. Listener certificates are platform configuration (files owned
  by the operator), not tenant data.
* **Client certificates** are asked for by the gateway listener (`optional` or `required`)
  against a platform CA bundle. A uvicorn protocol subclass adds the ASGI TLS extension
  (`client_cert_chain`) to each request. Behind a TLS-terminating proxy the certificate can
  come in a header, read only from trusted proxies and removed before forwarding.
* **Tenant isolation for mTLS**: the `mtls` policy verifies the certificate again against a
  **truststore of the API's tenant** (path building with signature checks, validity, CA flags
  and client-authentication usage), plus optional subject and fingerprint allow-lists. A
  truststore of another tenant is never loaded for a policy (fails closed with 503).
* **X.509 in pure Python**: `apiedge.security.x509` is a small, bounded DER reader and
  certificate builder; signatures use pycryptodome (RSA PKCS#1 v1.5, ECDSA, Ed25519). SHA-1/MD5
  signatures and RSA-PSS certificates are not accepted. No new dependency.
* **Keystores** (certificate chain plus private key) and **truststores** (CA bundles) are
  tenant-owned rows managed through `/tenants/{id}/tls/...` with the new permissions `tls:read`
  and `tls:manage`. Private keys are checked against the certificate, stored only encrypted with
  the secrets box (bound to tenant and keystore) and never returned.
* `apiedge tls self-signed` writes a test certificate (EC P-256) for trying TLS.

## Consequences

* F-02 is closed: APIEdge can be exposed with TLS and without a proxy.
* Listener certificates are read at start-up; renewal needs a restart (hot reload is later work).
* Revocation (CRL, OCSP) is not checked; mitigations are fingerprint pinning and removing CAs.
* Only the leaf client certificate is available from the standard library before Python 3.13,
  so a truststore must contain the CA that issued client certificates directly (intermediate
  CAs can be added to the truststore as anchors).
* Keystores are stored for upstream mTLS and TLS profiles, which use them in a later slice.
