# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""OAuth 2.0 clients and token signing keys of a tenant's authorization server (T-023, ADR 0015).

| Route | Permission (tenant-wide) |
|---|---|
| ``GET .../oauth/server`` | ``oauth:read`` |
| ``GET .../oauth/clients[/{client_pk}]`` | ``oauth:read`` |
| ``POST .../oauth/clients``, ``PATCH``/``DELETE .../clients/{client_pk}`` | ``oauth:manage`` |
| ``POST .../oauth/clients/{client_pk}/secret`` | ``oauth:manage`` |
| ``GET .../oauth/keys`` | ``oauth:read`` |
| ``POST .../oauth/keys`` (rotate), ``DELETE .../oauth/keys/{signing_key_id}`` | ``oauth:manage`` |

Client secrets are shown once (on creation and rotation) and stored only as SHA-256 hashes.
Signing keys are stored encrypted with the secrets box and never returned; rotating makes a new
key active and keeps the previous ones in the JWKS ("retired") until they are deleted. Every
query runs on a tenant-bound session; another tenant's objects answer 404.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from datetime import datetime
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import Field, StringConstraints, field_validator
from sqlalchemy import func, select, update

from apiedge.admin.deps import TenantCaller, not_found, require
from apiedge.admin.schemas import In, Out
from apiedge.config import Settings
from apiedge.db.models import OAuthClient, OAuthRefreshToken, OAuthSigningKey, Tenant, utcnow
from apiedge.security import oauth
from apiedge.security.audit import audit
from apiedge.security.crypto import SecretBox

router = APIRouter(prefix="/tenants/{tenant_id}/oauth", tags=["oauth"])

MAX_CLIENTS = 500
MAX_KEYS = 10

Name = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9 _.@-]{0,99}$")]
Description = Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)]
Scope = Annotated[str, StringConstraints(pattern=r"^[\x21\x23-\x5B\x5D-\x7E]{1,100}$")]
Audience = Annotated[str, StringConstraints(min_length=1, max_length=200)]
GrantType = Literal["client_credentials", "authorization_code", "refresh_token"]
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}
_PRIVATE_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*\.[a-z0-9+.-]+$")


def _check_redirect(uri: str) -> str:
    if len(uri) > 2000 or any(c.isspace() for c in uri):
        raise ValueError("redirect URIs must be at most 2000 characters without spaces")
    parts = urlsplit(uri)
    if parts.fragment or "#" in uri:
        raise ValueError("redirect URIs must not contain a fragment")
    if parts.username or parts.password:
        raise ValueError("redirect URIs must not contain credentials")
    if parts.scheme == "https" and parts.hostname:
        return uri
    if parts.scheme == "http" and parts.hostname in _LOOPBACK:
        return uri  # native apps on the device (RFC 8252)
    if _PRIVATE_SCHEME.match(parts.scheme) and (parts.path or parts.netloc):
        return uri  # private-use URI scheme of a native app, e.g. com.example.app:/callback
    raise ValueError(
        "redirect URIs must use https, http on a loopback host, or a reverse-domain app scheme"
    )


class _ClientFields(In):
    @field_validator("redirect_uris", check_fields=False)
    @classmethod
    def _redirects(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        return list(dict.fromkeys(_check_redirect(u) for u in v))

    @field_validator("grant_types", "scopes", "audiences", check_fields=False)
    @classmethod
    def _unique(cls, v: list[str] | None) -> list[str] | None:
        return list(dict.fromkeys(v)) if v is not None else None


class ClientIn(_ClientFields):
    name: Name
    description: Description = ""
    client_type: Literal["confidential", "public"] = "confidential"
    grant_types: list[GrantType] = Field(min_length=1, max_length=3)
    redirect_uris: list[str] = Field(default_factory=list, max_length=20)
    scopes: list[Scope] = Field(default_factory=list, max_length=50)
    audiences: list[Audience] = Field(default_factory=list, max_length=10)
    access_token_ttl: int = Field(default=600, ge=60, le=86400)
    refresh_token_ttl: int = Field(default=86400, ge=300, le=90 * 86400)
    enabled: bool = True


class ClientUpdate(_ClientFields):
    description: Description | None = None
    grant_types: list[GrantType] | None = Field(default=None, min_length=1, max_length=3)
    redirect_uris: list[str] | None = Field(default=None, max_length=20)
    scopes: list[Scope] | None = Field(default=None, max_length=50)
    audiences: list[Audience] | None = Field(default=None, max_length=10)
    access_token_ttl: int | None = Field(default=None, ge=60, le=86400)
    refresh_token_ttl: int | None = Field(default=None, ge=300, le=90 * 86400)
    enabled: bool | None = None


class ClientOut(Out):
    id: int
    client_id: str
    name: str
    description: str
    client_type: str
    secret_prefix: str | None
    grant_types: list[str]
    redirect_uris: list[str]
    scopes: list[str]
    audiences: list[str]
    access_token_ttl: int
    refresh_token_ttl: int
    enabled: bool
    created_at: datetime
    updated_at: datetime


class ClientCreated(ClientOut):
    client_secret: str | None = None  # shown once


class SecretOut(Out):
    client_id: str
    client_secret: str
    secret_prefix: str


class KeyOut(Out):
    id: int
    kid: str
    algorithm: str
    status: str
    created_at: datetime
    retired_at: datetime | None
    public_jwk: dict[str, Any]


class ServerOut(Out):
    issuer: str
    discovery_url: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    introspection_endpoint: str
    revocation_endpoint: str
    userinfo_endpoint: str
    active_key_id: str | None
    user_registry: str


def _loads(text: str) -> list[str]:
    try:
        value = json.loads(text or "[]")
    except ValueError:
        return []
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _client_out(c: OAuthClient) -> ClientOut:
    return ClientOut(
        id=c.id,
        client_id=c.client_id,
        name=c.name,
        description=c.description,
        client_type=c.client_type,
        secret_prefix=c.secret_prefix,
        grant_types=_loads(c.grant_types),
        redirect_uris=_loads(c.redirect_uris),
        scopes=_loads(c.scopes),
        audiences=_loads(c.audiences),
        access_token_ttl=c.access_token_ttl,
        refresh_token_ttl=c.refresh_token_ttl,
        enabled=c.enabled,
        created_at=c.created_at,
        updated_at=c.updated_at,
    )


def _key_out(k: OAuthSigningKey) -> KeyOut:
    try:
        jwk = json.loads(k.public_jwk)
    except ValueError:
        jwk = {}
    return KeyOut(
        id=k.id,
        kid=k.kid,
        algorithm=k.algorithm,
        status=k.status,
        created_at=k.created_at,
        retired_at=k.retired_at,
        public_jwk=jwk if isinstance(jwk, dict) else {},
    )


def _audit(
    caller: TenantCaller, action: str, kind: str, obj_id: int, details: dict[str, Any]
) -> None:
    audit(
        caller.session,
        action,
        tenant_id=caller.tenant_id,
        actor_id=caller.id,
        actor_username=caller.username,
        resource_type=kind,
        resource_id=obj_id,
        client_ip=caller.ip,
        details=details,
    )


def _box(request: Request) -> SecretBox:
    box: SecretBox | None = request.app.state.secret_box
    if box is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="secrets encryption is not configured (APIEDGE_SECRET_KEY or the key file)",
        )
    return box


def _check_combination(
    client_type: str, grants: Sequence[str], redirects: Sequence[str], scopes: Sequence[str]
) -> None:
    if client_type == "public" and "client_credentials" in grants:
        raise HTTPException(422, detail="public clients cannot use client_credentials")
    if "refresh_token" in grants and "authorization_code" not in grants:
        raise HTTPException(422, detail="refresh_token needs the authorization_code grant")
    if "authorization_code" in grants and not redirects:
        raise HTTPException(422, detail="authorization_code needs at least one redirect URI")
    if client_type == "public" and "authorization_code" not in grants:
        raise HTTPException(422, detail="public clients must use the authorization_code grant")
    if "openid" in scopes and "authorization_code" not in grants:
        raise HTTPException(422, detail="the openid scope needs the authorization_code grant")


def _client(caller: TenantCaller, client_pk: int) -> OAuthClient:
    c = caller.session.get(OAuthClient, client_pk)
    if c is None or c.tenant_id != caller.tenant_id:
        raise not_found("OAuth client not found")
    return c


def _add_key(caller: TenantCaller, box: SecretBox) -> OAuthSigningKey:
    generated = oauth.generate_signing_key()
    key = OAuthSigningKey(
        tenant_id=caller.tenant_id,
        kid=generated.kid,
        algorithm=oauth.SIGNING_ALG,
        private_key=box.encrypt(
            generated.private_pem, oauth.signing_key_aad(caller.tenant_id, generated.kid)
        ),
        public_jwk=json.dumps(generated.public_jwk),
        status="active",
    )
    caller.session.add(key)
    return key


def _active_key(caller: TenantCaller) -> OAuthSigningKey | None:
    return caller.session.scalar(
        select(OAuthSigningKey).where(
            OAuthSigningKey.tenant_id == caller.tenant_id, OAuthSigningKey.status == "active"
        )
    )


# --------------------------------------------------------------------------- server


@router.get("/server", response_model=ServerOut, summary="The tenant's OAuth / OIDC endpoints")
def get_server(
    request: Request, caller: Annotated[TenantCaller, Depends(require("oauth:read"))]
) -> ServerOut:
    settings: Settings = request.app.state.settings
    tenant = caller.session.get(Tenant, caller.tenant_id)
    if tenant is None:  # pragma: no cover - the RBAC dependency checked the tenant
        raise not_found("Tenant not found")
    issuer = oauth.issuer_url(settings.effective_gateway_public_url, tenant.slug)
    active = _active_key(caller)
    return ServerOut(
        issuer=issuer,
        discovery_url=f"{issuer}/.well-known/openid-configuration",
        authorization_endpoint=f"{issuer}/authorize",
        token_endpoint=f"{issuer}/token",
        jwks_uri=f"{issuer}/jwks",
        introspection_endpoint=f"{issuer}/introspect",
        revocation_endpoint=f"{issuer}/revoke",
        userinfo_endpoint=f"{issuer}/userinfo",
        active_key_id=active.kid if active else None,
        user_registry="console",
    )


# --------------------------------------------------------------------------- clients


@router.get("/clients", response_model=list[ClientOut], summary="List OAuth clients")
def list_clients(
    caller: Annotated[TenantCaller, Depends(require("oauth:read"))],
) -> list[ClientOut]:
    stmt = (
        select(OAuthClient)
        .where(OAuthClient.tenant_id == caller.tenant_id)
        .order_by(OAuthClient.name)
    )
    return [_client_out(c) for c in caller.session.scalars(stmt)]


@router.post(
    "/clients",
    response_model=ClientCreated,
    status_code=201,
    summary="Register an OAuth client (the secret is shown once)",
)
def create_client(
    body: ClientIn,
    request: Request,
    caller: Annotated[TenantCaller, Depends(require("oauth:manage"))],
) -> ClientCreated:
    _check_combination(body.client_type, body.grant_types, body.redirect_uris, body.scopes)
    session = caller.session
    exists = session.scalar(
        select(OAuthClient.id).where(
            OAuthClient.tenant_id == caller.tenant_id, OAuthClient.name == body.name
        )
    )
    if exists is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="the name is already used")
    count = session.scalar(
        select(func.count(OAuthClient.id)).where(OAuthClient.tenant_id == caller.tenant_id)
    )
    if (count or 0) >= MAX_CLIENTS:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail=f"a tenant can have at most {MAX_CLIENTS} clients"
        )
    if _active_key(caller) is None:
        _add_key(caller, _box(request))  # the server needs a key before the first token
    secret = (
        oauth.new_secret(oauth.CLIENT_SECRET_PREFIX) if body.client_type == "confidential" else None
    )
    c = OAuthClient(
        tenant_id=caller.tenant_id,
        client_id=oauth.new_client_id(),
        name=body.name,
        description=body.description,
        client_type=body.client_type,
        secret_hash=oauth.token_hash(secret) if secret else None,
        secret_prefix=secret[:8] if secret else None,
        redirect_uris=json.dumps(body.redirect_uris),
        grant_types=json.dumps(body.grant_types),
        scopes=json.dumps(body.scopes),
        audiences=json.dumps(body.audiences),
        access_token_ttl=body.access_token_ttl,
        refresh_token_ttl=body.refresh_token_ttl,
        enabled=body.enabled,
    )
    session.add(c)
    session.flush()
    _audit(
        caller,
        "oauth_client.create",
        "oauth_client",
        c.id,
        {"name": c.name, "client_id": c.client_id, "grant_types": body.grant_types},
    )
    session.commit()
    session.refresh(c)
    return ClientCreated(**_client_out(c).model_dump(), client_secret=secret)


@router.get("/clients/{client_pk}", response_model=ClientOut, summary="Get an OAuth client")
def get_client(
    client_pk: int, caller: Annotated[TenantCaller, Depends(require("oauth:read"))]
) -> ClientOut:
    return _client_out(_client(caller, client_pk))


@router.patch("/clients/{client_pk}", response_model=ClientOut, summary="Change an OAuth client")
def update_client(
    client_pk: int,
    body: ClientUpdate,
    caller: Annotated[TenantCaller, Depends(require("oauth:manage"))],
) -> ClientOut:
    c = _client(caller, client_pk)
    grants = body.grant_types if body.grant_types is not None else _loads(c.grant_types)
    redirects = body.redirect_uris if body.redirect_uris is not None else _loads(c.redirect_uris)
    scopes = body.scopes if body.scopes is not None else _loads(c.scopes)
    _check_combination(c.client_type, grants, redirects, scopes)
    changed = body.model_dump(exclude_none=True)
    for name in ("grant_types", "redirect_uris", "scopes", "audiences"):
        if name in changed:
            setattr(c, name, json.dumps(changed.pop(name)))
    for name, value in changed.items():
        setattr(c, name, value)
    if body.enabled is False:  # a disabled client's sign-ins end
        caller.session.execute(
            update(OAuthRefreshToken)
            .where(
                OAuthRefreshToken.client_pk == c.id,
                OAuthRefreshToken.tenant_id == caller.tenant_id,
                OAuthRefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=utcnow())
        )
    _audit(
        caller,
        "oauth_client.update",
        "oauth_client",
        c.id,
        {"name": c.name, "fields": sorted(body.model_dump(exclude_none=True))},
    )
    caller.session.commit()
    caller.session.refresh(c)
    return _client_out(c)


@router.post(
    "/clients/{client_pk}/secret",
    response_model=SecretOut,
    summary="Rotate a confidential client's secret (shown once)",
)
def rotate_secret(
    client_pk: int, caller: Annotated[TenantCaller, Depends(require("oauth:manage"))]
) -> SecretOut:
    c = _client(caller, client_pk)
    if c.client_type != "confidential":
        raise HTTPException(status.HTTP_409_CONFLICT, detail="public clients have no secret")
    secret = oauth.new_secret(oauth.CLIENT_SECRET_PREFIX)
    c.secret_hash = oauth.token_hash(secret)
    c.secret_prefix = secret[:8]
    _audit(caller, "oauth_client.rotate_secret", "oauth_client", c.id, {"name": c.name})
    caller.session.commit()
    return SecretOut(client_id=c.client_id, client_secret=secret, secret_prefix=secret[:8])


@router.delete("/clients/{client_pk}", status_code=204, summary="Delete an OAuth client")
def delete_client(
    client_pk: int, caller: Annotated[TenantCaller, Depends(require("oauth:manage"))]
) -> Response:
    c = _client(caller, client_pk)
    _audit(caller, "oauth_client.delete", "oauth_client", c.id, {"name": c.name, "id": c.client_id})
    caller.session.delete(c)
    caller.session.commit()
    return Response(status_code=204)


# --------------------------------------------------------------------------- signing keys


@router.get("/keys", response_model=list[KeyOut], summary="List token signing keys")
def list_keys(
    caller: Annotated[TenantCaller, Depends(require("oauth:read"))],
) -> list[KeyOut]:
    stmt = (
        select(OAuthSigningKey)
        .where(OAuthSigningKey.tenant_id == caller.tenant_id)
        .order_by(OAuthSigningKey.id.desc())
    )
    return [_key_out(k) for k in caller.session.scalars(stmt)]


@router.post(
    "/keys",
    response_model=KeyOut,
    status_code=201,
    summary="Rotate the signing key (the previous key stays published until deleted)",
)
def rotate_key(
    request: Request, caller: Annotated[TenantCaller, Depends(require("oauth:manage"))]
) -> KeyOut:
    box = _box(request)
    session = caller.session
    count = session.scalar(
        select(func.count(OAuthSigningKey.id)).where(OAuthSigningKey.tenant_id == caller.tenant_id)
    )
    if (count or 0) >= MAX_KEYS:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"at most {MAX_KEYS} keys: delete retired keys first",
        )
    previous = _active_key(caller)
    if previous is not None:
        previous.status = "retired"
        previous.retired_at = utcnow()
        session.flush()
    key = _add_key(caller, box)
    session.flush()
    _audit(
        caller,
        "oauth_key.rotate",
        "oauth_key",
        key.id,
        {"kid": key.kid, "retired": previous.kid if previous else None},
    )
    session.commit()
    session.refresh(key)
    return _key_out(key)


@router.delete("/keys/{signing_key_id}", status_code=204, summary="Delete a retired signing key")
def delete_key(
    signing_key_id: int, caller: Annotated[TenantCaller, Depends(require("oauth:manage"))]
) -> Response:
    k = caller.session.get(OAuthSigningKey, signing_key_id)
    if k is None or k.tenant_id != caller.tenant_id:
        raise not_found("Signing key not found")
    if k.status == "active":
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="the active key cannot be deleted: rotate first"
        )
    _audit(caller, "oauth_key.delete", "oauth_key", k.id, {"kid": k.kid})
    caller.session.delete(k)
    caller.session.commit()
    return Response(status_code=204)
