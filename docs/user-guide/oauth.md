<!-- Copyright 2026 OpenEdge Labs
     SPDX-License-Identifier: Apache-2.0 -->

# OAuth 2.0 and OpenID Connect

Every tenant has its own OAuth 2.0 authorization server and OpenID Connect provider, served by
the gateway. Applications get tokens from it, and APIs accept those tokens with a JWT validation
policy that has **Built-in issuer** switched on.

## Endpoints

The issuer is `<gateway public URL>/<tenant slug>/oauth2`, for example
`https://api.example.com/acme/oauth2` (the administrator sets the public URL with
`APIEDGE_GATEWAY_PUBLIC_URL`). The console page **OAuth & OIDC** shows the exact addresses.

| Path below the issuer | Use |
|---|---|
| `/.well-known/openid-configuration` | discovery document |
| `/jwks` | public signing keys |
| `/authorize` | user sign-in for the authorization code flow |
| `/token` | token endpoint |
| `/introspect` | token introspection (confidential clients) |
| `/revoke` | token revocation |
| `/userinfo` | OpenID Connect user information |

## Clients

On **OAuth & OIDC**, users with `oauth:manage` register clients:

| Setting | Meaning |
|---|---|
| Type | **Confidential** clients get a secret (shown once; **New secret** issues another). **Public** clients (browser and mobile apps) have no secret and can only use the authorization code grant |
| Grant types | **Client credentials** for service-to-service calls; **Authorization code** to sign users in (PKCE with `S256` is always required); **Refresh token** to renew a user's tokens |
| Redirect URIs | Exact addresses the sign-in may return to: `https://...`, `http://127.0.0.1:<port>/...` or `http://localhost/...` for desktop apps, or an app scheme such as `com.example.app:/callback` |
| Allowed scopes | Scopes the client may request. `openid`, `profile` and `email` enable OpenID Connect ID tokens |
| Audiences | Values of the access token's `aud` claim, so APIs can check that a token was meant for them |
| Token lifetimes | Access token (default 10 minutes) and refresh token (default 1 day) |

Disabling a client stops it from getting tokens and ends its refresh tokens; deleting it removes
it altogether.

## Getting tokens

Client credentials (the secret goes in HTTP Basic authentication or in the form):

```bash
curl -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d grant_type=client_credentials -d scope=orders.read \
  https://api.example.com/acme/oauth2/token
```

Authorization code with PKCE: send the user to `/authorize` with `response_type=code`,
`client_id`, `redirect_uri`, `scope`, `state`, `code_challenge` and `code_challenge_method=S256`
(add `nonce` for OpenID Connect). The user signs in with their APIEdge user name and password in
this tenant, and their authenticator code if they use MFA. The browser returns to the redirect
URI with `code`, `state` and `iss`. Exchange the code within 60 seconds at `/token` with
`grant_type=authorization_code`, the same `redirect_uri` and the `code_verifier`.

Refresh tokens are single-use: each refresh returns a new one. If an old refresh token is used
again, APIEdge treats it as stolen and ends that whole sign-in, so the user has to sign in again.

## Protecting an API

Add a **JWT validation** policy to the API with the algorithm `RS256` and **Built-in issuer**
switched on, and leave the shared secret, public key, JWKS URL and issuer empty. Add the
audiences the API expects, if any. Requests then need `Authorization: Bearer <access token>` from
this tenant's server; tokens of other tenants are refused. The policy checks signatures locally,
so a revoked access token stays usable until it expires: keep access tokens short-lived.

## Signing keys

The first client creates the tenant's signing key. **Rotate key** creates a new key that signs
from then on; the previous key stays in the JWKS as *retired*, so tokens it signed remain valid
until they expire. Delete a retired key once those tokens have expired. Private keys are stored
encrypted and are never shown.

## Permissions

| Permission | Allows |
|---|---|
| `oauth:read` | view the server, clients and keys (TenantAdmin, ProductOwner, APIDeveloper, Viewer) |
| `oauth:manage` | register, change and delete clients, issue secrets, rotate and delete keys (TenantAdmin) |
