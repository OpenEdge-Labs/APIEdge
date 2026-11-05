# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""The tenants' OAuth 2.0 authorization servers and OpenID Connect providers (T-023, ADR 0015).

Served by the gateway under ``/<tenant slug>/oauth2/`` (API base paths may not start with
``/oauth2``). The issuer is ``<APIEDGE_GATEWAY_PUBLIC_URL>/<tenant slug>/oauth2``.

| Endpoint | Purpose |
|---|---|
| ``GET .well-known/openid-configuration`` | discovery document (RFC 8414 / OIDC Discovery) |
| ``GET jwks`` | the tenant's public signing keys (active and retired) |
| ``GET/POST authorize`` | authorization code flow; PKCE ``S256`` is mandatory |
| ``POST token`` | ``client_credentials``, ``authorization_code``, ``refresh_token`` |
| ``POST introspect`` | RFC 7662, for confidential clients of the tenant |
| ``POST revoke`` | RFC 7009; refresh tokens revoke their whole family |
| ``GET/POST userinfo`` | OIDC UserInfo for access tokens with the ``openid`` scope |

End users sign in at ``authorize`` against the tenant's user registry (its console users; see
:mod:`apiedge.security.user_registry`). Access tokens are RS256 JWTs (``typ: at+jwt``); refresh
tokens and codes are opaque, single-use and stored only hashed. Using a refresh token or code a
second time revokes every refresh token descended from the same sign-in.
"""

from __future__ import annotations

import base64
import binascii
import html
import json
import logging
import secrets
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qsl, unquote_plus, urlencode, urlsplit

import anyio.to_thread
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session, sessionmaker
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from apiedge.db.models import (
    OAuthClient,
    OAuthCode,
    OAuthRefreshToken,
    OAuthRevokedToken,
    OAuthSigningKey,
    Tenant,
    utcnow,
)
from apiedge.db.tenancy import bind_tenant
from apiedge.policies.jwt import (
    IssuerKeys,
    JwtError,
    JwtVerifier,
    KeysUnavailableError,
    parse_jwks,
)
from apiedge.security import oauth
from apiedge.security.audit import audit
from apiedge.security.auth import LoginThrottle
from apiedge.security.crypto import CryptoError, SecretBox
from apiedge.security.user_registry import ConsoleUserRegistry, RegistryUser, UserRegistry

log = logging.getLogger("apiedge.gateway.oauth")

MAX_FORM_BYTES = 64 * 1024
CODE_TTL_SECONDS = 60
SIGN_IN_TTL_SECONDS = 600
# Token, introspection and revocation requests per client address and minute (per process).
TOKEN_REQUESTS_PER_MINUTE = 600
CSRF_COOKIE = "apiedge_oauth_csrf"
ENDPOINTS = frozenset(
    {
        ".well-known/openid-configuration",
        "jwks",
        "authorize",
        "token",
        "introspect",
        "revoke",
        "userinfo",
    }
)
_NO_STORE = {"cache-control": "no-store", "pragma": "no-cache"}


class OAuthError(Exception):
    """An RFC 6749 error answer."""

    def __init__(self, error: str, description: str, status: int = 400) -> None:
        super().__init__(description)
        self.error = error
        self.description = description
        self.status = status


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)  # SQLite drops the offset


def _list(text: str) -> list[str]:
    try:
        value = json.loads(text or "[]")
    except ValueError:
        return []
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


# --------------------------------------------------------------------------- issuer keys


def public_keys(session: Session, tenant_id: int) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(OAuthSigningKey)
        .where(OAuthSigningKey.tenant_id == tenant_id)
        .order_by(OAuthSigningKey.id.desc())
    )
    out = []
    for row in rows:
        try:
            jwk = json.loads(row.public_jwk)
        except ValueError:
            continue
        if isinstance(jwk, dict):
            out.append(jwk)
    return out


def load_issuers(factory: sessionmaker[Session], public_url: str) -> dict[int, IssuerKeys]:
    """tenant id -> issuer and public keys, for ``jwt`` policies with the built-in issuer."""
    out: dict[int, IssuerKeys] = {}
    with factory() as session:
        slugs = {t.id: t.slug for t in session.scalars(select(Tenant).where(Tenant.is_active))}
        tenants = set(session.scalars(select(OAuthSigningKey.tenant_id).distinct()))
        for tenant_id in tenants:
            if tenant_id not in slugs:
                continue
            try:
                keys = tuple(parse_jwks({"keys": public_keys(session, tenant_id)}))
            except ValueError:
                log.error("tenant %s: signing keys unreadable", tenant_id)
                continue
            out[tenant_id] = IssuerKeys(oauth.issuer_url(public_url, slugs[tenant_id]), keys)
    return out


# --------------------------------------------------------------------------- the server


@dataclass(frozen=True)
class TenantRef:
    id: int
    slug: str
    issuer: str


@dataclass(frozen=True)
class Issued:
    body: dict[str, Any]


class OAuthServer:
    """Protocol logic. Methods taking a ``Session`` run in a worker thread."""

    def __init__(
        self,
        factory: sessionmaker[Session],
        box: SecretBox | None,
        public_url: str,
        registry: UserRegistry,
        throttle: LoginThrottle,
        token_throttle: LoginThrottle | None = None,
    ) -> None:
        self.factory = factory
        self.box = box
        self.public_url = public_url
        self.registry = registry
        self.throttle = throttle  # sign-in attempts per client address
        self.token_throttle = token_throttle or LoginThrottle(TOKEN_REQUESTS_PER_MINUTE)
        self._signers: dict[str, oauth.SigningKey] = {}

    # ---------------------------------------------------------------- helpers

    def tenant(self, session: Session, slug: str) -> TenantRef | None:
        t = session.scalar(select(Tenant).where(Tenant.slug == slug, Tenant.is_active))
        if t is None:
            return None
        bind_tenant(session, t.id)
        return TenantRef(t.id, t.slug, oauth.issuer_url(self.public_url, t.slug))

    def metadata(self, tenant: TenantRef) -> dict[str, Any]:
        base = tenant.issuer
        return {
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "introspection_endpoint": f"{base}/introspect",
            "revocation_endpoint": f"{base}/revoke",
            "userinfo_endpoint": f"{base}/userinfo",
            "jwks_uri": f"{base}/jwks",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": list(oauth.GRANT_TYPES),
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": [oauth.SIGNING_ALG],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            "introspection_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "revocation_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": sorted(oauth.OIDC_SCOPES),
            "claims_supported": [
                "sub",
                "iss",
                "aud",
                "exp",
                "iat",
                "auth_time",
                "nonce",
                "preferred_username",
                "email",
            ],
            "authorization_response_iss_parameter_supported": True,
        }

    def signer(self, session: Session, tenant_id: int) -> oauth.SigningKey:
        row = session.scalar(
            select(OAuthSigningKey)
            .where(OAuthSigningKey.tenant_id == tenant_id, OAuthSigningKey.status == "active")
            .order_by(OAuthSigningKey.id.desc())
        )
        if row is None:
            raise OAuthError("server_error", "no signing key is configured", 503)
        cached = self._signers.get(row.kid)
        if cached is not None:
            return cached
        if self.box is None:
            raise OAuthError("server_error", "the secrets key is not configured", 503)
        try:
            pem = self.box.decrypt_str(row.private_key, oauth.signing_key_aad(tenant_id, row.kid))
            signer = oauth.SigningKey.from_pem(row.kid, pem)
        except (CryptoError, ValueError) as exc:
            log.error("tenant %s: signing key %s unusable", tenant_id, row.kid)
            raise OAuthError("server_error", "the signing key is unusable", 503) from exc
        if len(self._signers) > 1000:
            self._signers.clear()
        self._signers[row.kid] = signer
        return signer

    def client_by_id(self, session: Session, tenant_id: int, client_id: str) -> OAuthClient | None:
        c = session.scalar(
            select(OAuthClient).where(
                OAuthClient.tenant_id == tenant_id, OAuthClient.client_id == client_id
            )
        )
        return c if c is not None and c.enabled else None

    def authenticate_client(
        self,
        session: Session,
        tenant_id: int,
        form: Mapping[str, str],
        authorization: str | None,
        *,
        allow_public: bool,
    ) -> OAuthClient:
        client_id = secret = None
        basic = False
        if authorization and authorization[:6].lower() == "basic ":
            basic = True
            try:
                raw = base64.b64decode(authorization[6:].strip(), validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError) as exc:
                raise OAuthError("invalid_client", "client authentication failed", 401) from exc
            cid, sep, sec = raw.partition(":")
            if not sep:
                raise OAuthError("invalid_client", "client authentication failed", 401)
            client_id, secret = unquote_plus(cid), unquote_plus(sec)
            if "client_secret" in form or form.get("client_id", client_id) != client_id:
                raise OAuthError("invalid_request", "use one client authentication method")
        else:
            client_id = form.get("client_id")
            secret = form.get("client_secret")
        if not client_id:
            raise OAuthError("invalid_client", "client authentication failed", 401)
        client = self.client_by_id(session, tenant_id, client_id)
        if client is None:
            raise OAuthError("invalid_client", "client authentication failed", 401)
        if client.client_type == "public":
            if secret or not allow_public or basic:
                raise OAuthError("invalid_client", "client authentication failed", 401)
            return client
        if not secret or not oauth.secret_matches(secret, client.secret_hash):
            raise OAuthError("invalid_client", "client authentication failed", 401)
        return client

    def _verifier(self, session: Session, tenant: TenantRef) -> JwtVerifier:
        keys = tuple(parse_jwks({"keys": public_keys(session, tenant.id)}))
        source = IssuerKeys(tenant.issuer, keys)
        return JwtVerifier(
            algorithms=frozenset({oauth.SIGNING_ALG}),
            secret=None,
            public_key=None,
            jwks_url=None,
            jwks_ttl=300,
            jwks=None,
            issuer=None,
            audiences=frozenset(),
            require_exp=True,
            leeway=0,
            issuer_source=lambda: source,
        )

    def verify_access_token(
        self, session: Session, tenant: TenantRef, raw: str
    ) -> dict[str, Any] | None:
        """The claims of a valid, unrevoked access token of this tenant, else None."""
        if raw.startswith((oauth.REFRESH_PREFIX, oauth.CODE_PREFIX)) or len(raw) > 8192:
            return None
        verifier = self._verifier(session, tenant)
        try:
            claims = verifier.verify_builtin(raw)
        except (JwtError, KeysUnavailableError):
            return None
        jti = claims.get("jti")
        if not isinstance(jti, str):
            return None
        revoked = session.scalar(select(OAuthRevokedToken.id).where(OAuthRevokedToken.jti == jti))
        return None if revoked is not None else claims

    def _tokens(
        self,
        session: Session,
        tenant: TenantRef,
        client: OAuthClient,
        *,
        subject: str,
        scope: list[str],
        user: RegistryUser | None = None,
        family: str | None = None,
        auth_time: datetime | None = None,
        nonce: str | None = None,
    ) -> Issued:
        signer = self.signer(session, tenant.id)
        scope_text = " ".join(scope)
        extra: dict[str, Any] = {}
        if user is not None:
            extra["preferred_username"] = user.username
        claims = oauth.access_token_claims(
            issuer=tenant.issuer,
            subject=subject,
            client_id=client.client_id,
            scope=scope_text,
            ttl=client.access_token_ttl,
            audience=_list(client.audiences),
            extra=extra,
        )
        body: dict[str, Any] = {
            "access_token": oauth.sign_jwt(claims, signer, typ="at+jwt"),
            "token_type": "Bearer",  # nosec B105 - token type name
            "expires_in": client.access_token_ttl,
        }
        if scope_text:
            body["scope"] = scope_text
        if user is not None and "openid" in scope:
            id_claims: dict[str, Any] = {
                "iss": tenant.issuer,
                "sub": subject,
                "aud": client.client_id,
                "azp": client.client_id,
                "iat": claims["iat"],
                "exp": claims["iat"] + client.access_token_ttl,
                "auth_time": int(_aware(auth_time or utcnow()).timestamp()),
            }
            if nonce:
                id_claims["nonce"] = nonce
            if "profile" in scope:
                id_claims["preferred_username"] = user.username
            if "email" in scope and user.email:
                id_claims["email"] = user.email
            body["id_token"] = oauth.sign_jwt(id_claims, signer)
        if user is not None and family is not None and "refresh_token" in _list(client.grant_types):
            raw = oauth.new_secret(oauth.REFRESH_PREFIX)
            session.add(
                OAuthRefreshToken(
                    tenant_id=tenant.id,
                    client_pk=client.id,
                    token_hash=oauth.token_hash(raw),
                    family_id=family,
                    user_id=user.user_id,
                    scope=scope_text,
                    auth_time=auth_time or utcnow(),
                    expires_at=utcnow() + timedelta(seconds=client.refresh_token_ttl),
                )
            )
            body["refresh_token"] = raw
        return Issued(body)

    @staticmethod
    def _claim(session: Session, model: type[OAuthCode] | type[OAuthRefreshToken], pk: int) -> bool:
        """Mark a code or refresh token used, atomically: False if another request won."""
        result = session.execute(
            update(model)
            .where(model.id == pk, model.used_at.is_(None))
            .values(used_at=utcnow())
            .execution_options(synchronize_session=False)
        )
        session.commit()  # single use, even if later checks fail
        return bool(getattr(result, "rowcount", 0) == 1)

    def revoke_family(self, session: Session, tenant_id: int, family: str) -> None:
        session.execute(
            update(OAuthRefreshToken)
            .where(
                OAuthRefreshToken.tenant_id == tenant_id,
                OAuthRefreshToken.family_id == family,
                OAuthRefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=utcnow())
        )

    # ---------------------------------------------------------------- token endpoint

    def token(
        self,
        session: Session,
        tenant: TenantRef,
        form: Mapping[str, str],
        authorization: str | None,
        ip: str | None,
    ) -> dict[str, Any]:
        grant = form.get("grant_type", "")
        if grant not in oauth.GRANT_TYPES:
            raise OAuthError("unsupported_grant_type", "the grant type is not supported")
        client = self.authenticate_client(
            session, tenant.id, form, authorization, allow_public=grant != "client_credentials"
        )
        if grant not in _list(client.grant_types):
            raise OAuthError("unauthorized_client", "the client may not use this grant type")
        if grant == "client_credentials":
            return self._client_credentials(session, tenant, client, form)
        if grant == "authorization_code":
            return self._authorization_code(session, tenant, client, form, ip)
        return self._refresh(session, tenant, client, form, ip)

    def _client_credentials(
        self, session: Session, tenant: TenantRef, client: OAuthClient, form: Mapping[str, str]
    ) -> dict[str, Any]:
        requested = oauth.parse_scope(form.get("scope"))
        if requested is None or oauth.OIDC_SCOPES & set(requested):
            raise OAuthError("invalid_scope", "the requested scope is invalid")
        scope = oauth.grant_scope(requested, _list(client.scopes))
        if scope is None:
            raise OAuthError("invalid_scope", "the requested scope is not allowed")
        issued = self._tokens(session, tenant, client, subject=client.client_id, scope=scope)
        session.commit()
        return issued.body

    def _authorization_code(
        self,
        session: Session,
        tenant: TenantRef,
        client: OAuthClient,
        form: Mapping[str, str],
        ip: str | None,
    ) -> dict[str, Any]:
        raw = form.get("code", "")
        verifier = form.get("code_verifier", "")
        if not raw or not verifier:
            raise OAuthError("invalid_request", "code and code_verifier are required")
        code = session.scalar(select(OAuthCode).where(OAuthCode.code_hash == oauth.token_hash(raw)))
        if code is None or code.client_pk != client.id:
            raise OAuthError("invalid_grant", "the authorization code is invalid")
        if code.used_at is not None:
            # A replayed code: someone else may hold it. Revoke what it produced.
            self.revoke_family(session, tenant.id, code.family_id)
            audit(
                session,
                "oauth.code_reuse",
                tenant_id=tenant.id,
                actor_id=code.user_id,
                outcome="failure",
                client_ip=ip,
                resource_type="oauth_client",
                resource_id=client.id,
            )
            session.commit()
            raise OAuthError("invalid_grant", "the authorization code is invalid")
        if not self._claim(session, OAuthCode, code.id):
            raise OAuthError("invalid_grant", "the authorization code is invalid")
        if _aware(code.expires_at) < utcnow():
            raise OAuthError("invalid_grant", "the authorization code has expired")
        if form.get("redirect_uri", "") != code.redirect_uri:
            raise OAuthError("invalid_grant", "redirect_uri does not match")
        if not oauth.pkce_matches(verifier, code.code_challenge):
            raise OAuthError("invalid_grant", "the code verifier does not match")
        user = self.registry.lookup(session, tenant.id, code.user_id)
        if user is None:
            raise OAuthError("invalid_grant", "the user can no longer sign in")
        scope = code.scope.split(" ") if code.scope else []
        issued = self._tokens(
            session,
            tenant,
            client,
            subject=str(user.user_id),
            scope=scope,
            user=user,
            family=code.family_id,
            auth_time=_aware(code.auth_time),
            nonce=code.nonce,
        )
        session.commit()
        return issued.body

    def _refresh(
        self,
        session: Session,
        tenant: TenantRef,
        client: OAuthClient,
        form: Mapping[str, str],
        ip: str | None,
    ) -> dict[str, Any]:
        raw = form.get("refresh_token", "")
        row = session.scalar(
            select(OAuthRefreshToken).where(OAuthRefreshToken.token_hash == oauth.token_hash(raw))
        )
        if row is None or row.client_pk != client.id:
            raise OAuthError("invalid_grant", "the refresh token is invalid")
        if row.used_at is not None and row.revoked_at is None:
            self.revoke_family(session, tenant.id, row.family_id)
            audit(
                session,
                "oauth.refresh_reuse",
                tenant_id=tenant.id,
                actor_id=row.user_id,
                outcome="failure",
                client_ip=ip,
                resource_type="oauth_client",
                resource_id=client.id,
            )
            session.commit()
            raise OAuthError("invalid_grant", "the refresh token is invalid")
        if row.revoked_at is not None or row.used_at is not None:
            raise OAuthError("invalid_grant", "the refresh token is invalid")
        if _aware(row.expires_at) < utcnow():
            raise OAuthError("invalid_grant", "the refresh token has expired")
        granted = row.scope.split(" ") if row.scope else []
        requested = oauth.parse_scope(form.get("scope"))
        if requested is None or not set(requested) <= set(granted):
            raise OAuthError("invalid_scope", "the scope exceeds the original grant")
        scope = requested or granted
        user = self.registry.lookup(session, tenant.id, row.user_id)
        if not self._claim(session, OAuthRefreshToken, row.id):
            raise OAuthError("invalid_grant", "the refresh token is invalid")
        if user is None:
            self.revoke_family(session, tenant.id, row.family_id)
            session.commit()
            raise OAuthError("invalid_grant", "the user can no longer sign in")
        issued = self._tokens(
            session,
            tenant,
            client,
            subject=str(user.user_id),
            scope=scope,
            user=user,
            family=row.family_id,
            auth_time=_aware(row.auth_time),
        )
        session.commit()
        return issued.body

    # ---------------------------------------------------------------- introspection / revocation

    def _refresh_row(self, session: Session, raw: str) -> OAuthRefreshToken | None:
        if not raw.startswith(oauth.REFRESH_PREFIX):
            return None
        return session.scalar(
            select(OAuthRefreshToken).where(OAuthRefreshToken.token_hash == oauth.token_hash(raw))
        )

    def introspect(
        self,
        session: Session,
        tenant: TenantRef,
        form: Mapping[str, str],
        authorization: str | None,
    ) -> dict[str, Any]:
        self.authenticate_client(session, tenant.id, form, authorization, allow_public=False)
        raw = form.get("token", "")
        inactive: dict[str, Any] = {"active": False}
        if not raw:
            return inactive
        row = self._refresh_row(session, raw)
        if row is not None:
            if row.revoked_at or row.used_at or _aware(row.expires_at) < utcnow():
                return inactive
            owner = session.get(OAuthClient, row.client_pk)
            if owner is None or not owner.enabled:
                return inactive
            return {
                "active": True,
                "token_type": "refresh_token",  # nosec B105 - token type name
                "client_id": owner.client_id,
                "sub": str(row.user_id),
                "scope": row.scope,
                "exp": int(_aware(row.expires_at).timestamp()),
                "iss": tenant.issuer,
            }
        claims = self.verify_access_token(session, tenant, raw)
        if claims is None:
            return inactive
        owner = self.client_by_id(session, tenant.id, str(claims.get("client_id", "")))
        if owner is None:
            return inactive
        out = {"active": True, "token_type": "Bearer"}  # nosec B105 - token type name
        for name in ("scope", "client_id", "sub", "aud", "iss", "exp", "iat", "nbf", "jti"):
            if name in claims:
                out[name] = claims[name]
        if "preferred_username" in claims:
            out["username"] = claims["preferred_username"]
        return out

    def revoke(
        self,
        session: Session,
        tenant: TenantRef,
        form: Mapping[str, str],
        authorization: str | None,
    ) -> None:
        client = self.authenticate_client(
            session, tenant.id, form, authorization, allow_public=True
        )
        raw = form.get("token", "")
        if not raw:
            raise OAuthError("invalid_request", "the token parameter is required")
        row = self._refresh_row(session, raw)
        if row is not None:
            if row.client_pk == client.id:
                self.revoke_family(session, tenant.id, row.family_id)
                session.commit()
            return
        claims = self.verify_access_token(session, tenant, raw)
        if claims is None or claims.get("client_id") != client.client_id:
            return  # RFC 7009: invalid tokens are not an error
        exp = claims.get("exp")
        session.add(
            OAuthRevokedToken(
                tenant_id=tenant.id,
                jti=str(claims["jti"]),
                expires_at=datetime.fromtimestamp(
                    exp if isinstance(exp, int) else time.time() + 3600, UTC
                ),
            )
        )
        session.execute(  # housekeeping: entries of expired tokens are no longer needed
            delete(OAuthRevokedToken)
            .where(
                OAuthRevokedToken.tenant_id == tenant.id, OAuthRevokedToken.expires_at < utcnow()
            )
            .execution_options(synchronize_session=False)
        )
        session.commit()

    def userinfo(self, session: Session, tenant: TenantRef, raw: str) -> dict[str, Any]:
        claims = self.verify_access_token(session, tenant, raw)
        if claims is None:
            raise OAuthError("invalid_token", "the access token is not valid", 401)
        scope = str(claims.get("scope", "")).split(" ")
        sub = str(claims.get("sub", ""))
        if "openid" not in scope or not sub.isdigit():
            raise OAuthError("insufficient_scope", "the token has no openid scope", 403)
        user = self.registry.lookup(session, tenant.id, int(sub))
        if user is None:
            raise OAuthError("invalid_token", "the access token is not valid", 401)
        out: dict[str, Any] = {"sub": sub}
        if "profile" in scope:
            out["preferred_username"] = user.username
        if "email" in scope and user.email:
            out["email"] = user.email
        return out

    # ---------------------------------------------------------------- authorization endpoint

    def authorization_request(
        self, session: Session, tenant: TenantRef, params: Mapping[str, str]
    ) -> AuthzRequest:
        """Validate an authorization request. Raises :class:`AuthzError`."""
        client = self.client_by_id(session, tenant.id, params.get("client_id", ""))
        if client is None:
            raise AuthzError("The application is not known.", None)
        registered = _list(client.redirect_uris)
        redirect_uri = params.get("redirect_uri", "")  # always required and matched exactly
        if redirect_uri not in registered:
            raise AuthzError("The redirect address is not registered for this application.", None)
        state = params.get("state")
        if state is not None and len(state) > 500:
            raise AuthzError("The state parameter is too long.", None)
        target = Redirect(redirect_uri, state, tenant.issuer)
        if "authorization_code" not in _list(client.grant_types):
            raise AuthzError("unauthorized_client", target)
        if params.get("response_type") != "code":
            raise AuthzError("unsupported_response_type", target)
        challenge = params.get("code_challenge", "")
        if params.get("code_challenge_method") != "S256" or not oauth.valid_challenge(challenge):
            raise AuthzError("invalid_request", target, "PKCE with S256 is required")
        requested = oauth.parse_scope(params.get("scope"))
        scope = (
            oauth.grant_scope(requested, _list(client.scopes)) if requested is not None else None
        )
        if scope is None:
            raise AuthzError("invalid_scope", target)
        nonce = params.get("nonce")
        if nonce is not None and len(nonce) > 255:
            raise AuthzError("invalid_request", target, "nonce is too long")
        if params.get("prompt") == "none":
            raise AuthzError("login_required", target)
        return AuthzRequest(client, target, scope, challenge, nonce)

    def sign_in(
        self,
        session: Session,
        tenant: TenantRef,
        req: AuthzRequest,
        form: Mapping[str, str],
        ip: str | None,
    ) -> tuple[str | None, str]:
        """(redirect URL, "") on success, else (None, outcome reason)."""
        username = form.get("username", "")[:150]
        outcome = self.registry.authenticate(
            session,
            tenant.id,
            username,
            form.get("password", "")[:1024],
            form.get("totp_code") or None,
        )
        if outcome.user is None:
            if outcome.reason != "mfa_required":
                audit(
                    session,
                    "oauth.authorize",
                    tenant_id=tenant.id,
                    actor_username=username or None,
                    outcome="failure",
                    client_ip=ip,
                    resource_type="oauth_client",
                    resource_id=req.client.id,
                    details={"reason": outcome.reason, "registry": self.registry.name},
                )
            session.commit()
            return None, outcome.reason
        raw = oauth.new_secret(oauth.CODE_PREFIX)
        now = utcnow()
        session.add(
            OAuthCode(
                tenant_id=tenant.id,
                client_pk=req.client.id,
                code_hash=oauth.token_hash(raw),
                user_id=outcome.user.user_id,
                redirect_uri=req.target.uri,
                scope=" ".join(req.scope),
                code_challenge=req.challenge,
                nonce=req.nonce,
                family_id=uuid.uuid4().hex,
                auth_time=now,
                expires_at=now + timedelta(seconds=CODE_TTL_SECONDS),
            )
        )
        audit(
            session,
            "oauth.authorize",
            tenant_id=tenant.id,
            actor_id=outcome.user.user_id,
            actor_username=outcome.user.username,
            client_ip=ip,
            resource_type="oauth_client",
            resource_id=req.client.id,
            details={"client_id": req.client.client_id, "scope": " ".join(req.scope)},
        )
        session.execute(  # housekeeping: expired codes of this tenant
            delete(OAuthCode)
            .where(
                OAuthCode.tenant_id == tenant.id,
                OAuthCode.expires_at < now - timedelta(hours=1),
            )
            .execution_options(synchronize_session=False)
        )
        session.commit()
        return req.target.url({"code": raw}), ""


@dataclass(frozen=True)
class Redirect:
    uri: str
    state: str | None
    issuer: str

    def url(self, params: Mapping[str, str]) -> str:
        query = dict(params)
        if self.state is not None:
            query["state"] = self.state
        query["iss"] = self.issuer
        sep = "&" if urlsplit(self.uri).query else "?"
        return self.uri + sep + urlencode(query)


class AuthzError(Exception):
    """An authorization request error: shown on the page if ``target`` is None, else
    returned to the client's redirect URI."""

    def __init__(self, error: str, target: Redirect | None, description: str = "") -> None:
        super().__init__(error)
        self.error = error
        self.target = target
        self.description = description


@dataclass(frozen=True)
class AuthzRequest:
    client: OAuthClient
    target: Redirect
    scope: list[str]
    challenge: str
    nonce: str | None


# --------------------------------------------------------------------------- HTTP layer

_PARAMS = (
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "code_challenge",
    "code_challenge_method",
    "nonce",
    "prompt",
)
_MESSAGES = {
    "invalid_credentials": "The user name or password is not correct.",
    "locked": "The account is temporarily locked. Try again later.",
    "mfa_required": "Enter the code from your authenticator app.",
    "invalid_mfa_code": "The authenticator code is not correct.",
    "throttled": "Too many attempts. Wait a minute and try again.",
    "csrf": "The sign-in form expired. Please try again.",
}


def _error(exc: OAuthError) -> JSONResponse:
    headers = dict(_NO_STORE)
    if exc.status == 401:
        headers["www-authenticate"] = (
            'Bearer error="invalid_token"'
            if exc.error == "invalid_token"
            else 'Basic realm="oauth"'
        )
    return JSONResponse(
        {"error": exc.error, "error_description": exc.description},
        status_code=exc.status,
        headers=headers,
    )


async def _form(request: Request) -> dict[str, str]:
    ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if ctype != "application/x-www-form-urlencoded":
        raise OAuthError("invalid_request", "use application/x-www-form-urlencoded")
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_FORM_BYTES:
            raise OAuthError("invalid_request", "the request is too large", 413)
    try:
        pairs = parse_qsl(body.decode("utf-8"), keep_blank_values=True, strict_parsing=False)
    except (UnicodeDecodeError, ValueError) as exc:
        raise OAuthError("invalid_request", "the form is malformed") from exc
    out: dict[str, str] = {}
    for k, v in pairs:
        if k in out:
            raise OAuthError("invalid_request", f"parameter {k[:40]} is repeated")
        out[k] = v
    return out


def _query(request: Request) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in request.query_params.multi_items():
        if k in out:
            raise OAuthError("invalid_request", f"parameter {k[:40]} is repeated")
        out[k] = v
    return out


def _page(
    *,
    tenant: TenantRef,
    req: AuthzRequest | None,
    params: Mapping[str, str],
    csrf: str,
    message: str = "",
    ask_totp: bool = False,
    status: int = 200,
    secure: bool = False,
) -> HTMLResponse:
    nonce = secrets.token_urlsafe(16)
    esc = html.escape
    form_action = "'self'"
    if req is not None:
        parts = urlsplit(req.target.uri)
        origin = f"{parts.scheme}://{parts.netloc}" if parts.netloc else f"{parts.scheme}:"
        form_action += " " + origin
    body: list[str] = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        "<title>Sign in</title>",
        f"<style nonce='{nonce}'>body{{font-family:system-ui,sans-serif;max-width:24rem;"
        "margin:4rem auto;padding:0 1rem;color:#1f2328;background:#fff}"
        "label{display:block;margin:.8rem 0 .2rem}input{width:100%;padding:.5rem;"
        "box-sizing:border-box}button{margin-top:1.2rem;padding:.6rem 1.2rem}"
        ".msg{color:#b42318}.app{color:#57606a}</style></head><body>",
    ]
    if req is None:
        body.append(f"<h1>Sign-in error</h1><p class='msg'>{esc(message)}</p></body></html>")
    else:
        body.append(f"<h1>Sign in</h1><p class='app'>to {esc(req.client.name)}</p>")
        if message:
            body.append(f"<p class='msg' role='alert'>{esc(message)}</p>")
        body.append("<form method='post' autocomplete='off'>")
        for name in _PARAMS:
            if name in params:
                body.append(
                    f"<input type='hidden' name='{name}' value='{esc(params[name], quote=True)}'>"
                )
        body.append(f"<input type='hidden' name='csrf' value='{esc(csrf, quote=True)}'>")
        username = esc(params.get("username", ""), quote=True)
        body.append(
            "<label for='u'>User name</label>"
            f"<input id='u' name='username' value='{username}' required maxlength='150'>"
            "<label for='p'>Password</label>"
            "<input id='p' name='password' type='password' required maxlength='1024'>"
        )
        if ask_totp:
            body.append(
                "<label for='t'>Authenticator code</label><input id='t' name='totp_code' "
                "inputmode='numeric' pattern='[0-9]{6}' maxlength='6' required>"
            )
        body.append("<button type='submit'>Sign in</button></form></body></html>")
    csp = (
        f"default-src 'none'; style-src 'nonce-{nonce}'; form-action {form_action}; "
        "frame-ancestors 'none'; base-uri 'none'"
    )
    response = HTMLResponse(
        "".join(body),
        status_code=status,
        headers={
            **_NO_STORE,
            "content-security-policy": csp,
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
        },
    )
    response.set_cookie(
        CSRF_COOKIE,
        csrf,
        max_age=SIGN_IN_TTL_SECONDS,
        path=f"/{tenant.slug}/oauth2/authorize",
        httponly=True,
        secure=secure,
        samesite="strict",
    )
    return response


def _redirect_error(exc: AuthzError, target: Redirect) -> Response:
    params = {"error": exc.error}
    if exc.description:
        params["error_description"] = exc.description
    return RedirectResponse(target.url(params), status_code=303, headers=_NO_STORE)


async def handle(
    request: Request,
    server: OAuthServer,
    slug: str,
    endpoint: str,
    ip: str | None,
) -> Response:
    """Answer one request to ``/<slug>/oauth2/<endpoint>``."""
    if endpoint not in ENDPOINTS:
        return JSONResponse({"error": "not_found"}, status_code=404)
    method = request.method.upper()
    try:
        if endpoint in (".well-known/openid-configuration", "jwks"):
            if method != "GET":
                raise OAuthError("invalid_request", "use GET", 405)
            return await anyio.to_thread.run_sync(_discovery, server, slug, endpoint)
        if endpoint == "authorize":
            return await _authorize(request, server, slug, ip)
        if endpoint == "userinfo":
            if method not in ("GET", "POST"):
                raise OAuthError("invalid_request", "use GET or POST", 405)
            scheme, _, token = request.headers.get("authorization", "").partition(" ")
            if scheme.lower() != "bearer" or not token.strip():
                raise OAuthError("invalid_token", "a bearer token is required", 401)
            return await anyio.to_thread.run_sync(_userinfo, server, slug, token.strip())
        if method != "POST":
            raise OAuthError("invalid_request", "use POST", 405)
        form = await _form(request)
        authorization = request.headers.get("authorization")
        if not server.token_throttle.hit(ip or "unknown"):
            raise OAuthError("slow_down", "too many requests", 429)
        return await anyio.to_thread.run_sync(
            _post_endpoint, server, slug, endpoint, form, authorization, ip
        )
    except OAuthError as exc:
        return _error(exc)


def _with_tenant(server: OAuthServer, session: Session, slug: str) -> TenantRef:
    tenant = server.tenant(session, slug)
    if tenant is None:
        raise OAuthError("not_found", "unknown tenant", 404)
    return tenant


def _discovery(server: OAuthServer, slug: str, endpoint: str) -> Response:
    with server.factory() as session:
        tenant = _with_tenant(server, session, slug)
        if endpoint == "jwks":
            body: dict[str, Any] = {"keys": public_keys(session, tenant.id)}
        else:
            body = server.metadata(tenant)
    return JSONResponse(body, headers={"cache-control": "public, max-age=300"})


def _userinfo(server: OAuthServer, slug: str, token: str) -> Response:
    with server.factory() as session:
        tenant = _with_tenant(server, session, slug)
        return JSONResponse(server.userinfo(session, tenant, token), headers=_NO_STORE)


def _post_endpoint(
    server: OAuthServer,
    slug: str,
    endpoint: str,
    form: dict[str, str],
    authorization: str | None,
    ip: str | None,
) -> Response:
    with server.factory() as session:
        tenant = _with_tenant(server, session, slug)
        if endpoint == "token":
            body = server.token(session, tenant, form, authorization, ip)
            return JSONResponse(body, headers=_NO_STORE)
        if endpoint == "introspect":
            return JSONResponse(
                server.introspect(session, tenant, form, authorization), headers=_NO_STORE
            )
        server.revoke(session, tenant, form, authorization)
        return Response(status_code=200, headers=_NO_STORE)


async def _authorize(request: Request, server: OAuthServer, slug: str, ip: str | None) -> Response:
    method = request.method.upper()
    if method not in ("GET", "POST"):
        raise OAuthError("invalid_request", "use GET or POST", 405)
    secure = request.url.scheme == "https"
    params = _query(request) if method == "GET" else await _form(request)
    cookie = request.cookies.get(CSRF_COOKIE, "")
    throttled = method == "POST" and not server.throttle.hit(f"authorize:{ip or 'unknown'}")
    return await anyio.to_thread.run_sync(
        _authorize_sync, server, slug, method, params, cookie, throttled, secure, ip
    )


def _authorize_sync(
    server: OAuthServer,
    slug: str,
    method: str,
    params: dict[str, str],
    cookie: str,
    throttled: bool,
    secure: bool,
    ip: str | None,
) -> Response:
    with server.factory() as session:
        tenant = _with_tenant(server, session, slug)
        csrf = secrets.token_urlsafe(24)
        try:
            req = server.authorization_request(session, tenant, params)
        except AuthzError as exc:
            if exc.target is None:
                return _page(
                    tenant=tenant,
                    req=None,
                    params=params,
                    csrf=csrf,
                    message=exc.error,
                    status=400,
                    secure=secure,
                )
            return _redirect_error(exc, exc.target)

        def page(message: str = "", ask_totp: bool = False) -> HTMLResponse:
            shown = {k: v for k, v in params.items() if k in (*_PARAMS, "username")}
            return _page(
                tenant=tenant,
                req=req,
                params=shown,
                csrf=csrf,
                message=message,
                ask_totp=ask_totp,
                secure=secure,
            )

        if method == "GET":
            return page()
        if not cookie or not secrets.compare_digest(cookie, params.get("csrf", "")):
            return page(_MESSAGES["csrf"])
        if throttled:
            return page(_MESSAGES["throttled"])
        url, reason = server.sign_in(session, tenant, req, params, ip)
        if url is None:
            totp = reason in ("mfa_required", "invalid_mfa_code")
            return page(_MESSAGES.get(reason, _MESSAGES["invalid_credentials"]), ask_totp=totp)
        response = RedirectResponse(url, status_code=303, headers=_NO_STORE)
        response.delete_cookie(CSRF_COOKIE, path=f"/{tenant.slug}/oauth2/authorize")
        return response


def build_server(
    factory: sessionmaker[Session],
    box: SecretBox | None,
    public_url: str,
    *,
    max_failures: int,
    lockout_minutes: int,
    rate_per_minute: int,
) -> OAuthServer:
    return OAuthServer(
        factory,
        box,
        public_url,
        ConsoleUserRegistry(box, max_failures, lockout_minutes),
        LoginThrottle(rate_per_minute),
    )
