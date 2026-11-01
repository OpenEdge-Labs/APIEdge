# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Policy chains and API keys (T-008, ADR 0009).

| Route | Permission (tenant-wide or scoped to the product) |
|---|---|
| ``GET .../products/{product_id}/apis/{api_id}/policies`` | ``policy:read`` |
| ``PUT .../products/{product_id}/apis/{api_id}/policies`` | ``policy:update`` |
| ``GET .../products/{product_id}/api-keys`` | ``apikey:read`` |
| ``POST .../products/{product_id}/api-keys`` | ``apikey:manage`` |
| ``POST .../products/{product_id}/api-keys/{key_id}/revoke`` | ``apikey:manage`` |

Products and APIs the caller cannot see answer 404 as in ``admin.apis``; every query runs on a
tenant-bound session.

The chain is replaced as a whole. Policies keep their ``id`` (new ones get one), which the
packet inspector's trace refers to. Secret fields (the JWT shared secret) are encrypted with the
secrets box and never returned: sending ``null`` keeps the stored value of the policy with the
same id. JWKS URLs pass the SSRF guard; route filters must name routes of the API.

API keys belong to a product and work for every API of it that has an ``api-key`` policy. Only
the SHA-256 of a key is stored; the key itself is in the create response only. Revoked keys stop
working as soon as the gateway reloads (immediately in the same process).
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, StringConstraints, field_validator
from sqlalchemy import func, select

from apiedge.admin.apis import SSRF_HINT, _api, _product, _writable
from apiedge.admin.deps import TenantCaller, deny, not_found, require_any
from apiedge.admin.schemas import In, Out
from apiedge.config import Settings
from apiedge.db.models import Api, ApiKey, Product
from apiedge.policies.builtin import hash_api_key, secret_aad
from apiedge.policies.config import HMAC_ALGS, SECRET_FIELDS, PolicyChain, PolicySpec
from apiedge.policies.jwt import load_pem_key
from apiedge.security.audit import audit
from apiedge.security.crypto import SecretBox
from apiedge.security.ssrf import SsrfError, check_url

router = APIRouter(prefix="/tenants/{tenant_id}/products/{product_id}", tags=["policies"])

MAX_CHAIN_BYTES = 512 * 1024
MAX_ACTIVE_KEYS = 1000
KEY_PREFIX = "ak_"


class PolicyChainOut(BaseModel):
    policies: list[PolicySpec]
    # policy id -> secret fields that hold a stored value (the values are never returned)
    secrets_set: dict[str, list[str]] = Field(default_factory=dict)


def _stored(api: Api) -> list[dict[str, Any]]:
    try:
        entries = json.loads(api.policies or "[]")
    except ValueError:
        return []
    return [e for e in entries if isinstance(e, dict)] if isinstance(entries, list) else []


def _chain_out(api: Api) -> PolicyChainOut:
    shown: list[dict[str, Any]] = []
    secrets_set: dict[str, list[str]] = {}
    for entry in _stored(api):
        fields = SECRET_FIELDS.get(str(entry.get("type")), ())
        config = dict(entry.get("config") or {})
        held = [f for f in fields if config.get(f)]
        for f in fields:
            config[f] = None
        if held:
            secrets_set[str(entry.get("id"))] = held
        shown.append({**entry, "config": config})
    chain = PolicyChain.model_validate({"policies": shown})
    return PolicyChainOut(policies=chain.policies, secrets_set=secrets_set)


def _policy_api(caller: TenantCaller, product_id: int, api_id: int, permission: str) -> Api:
    product = _product(caller, product_id, "api:read")
    api = _api(caller, product, api_id)
    if not caller.principal.has(permission, caller.tenant_id, product.id):
        raise deny(caller, permission, caller.tenant_id)
    if permission == "policy:update":
        _writable(product, api)
    return api


@router.get(
    "/apis/{api_id}/policies", response_model=PolicyChainOut, summary="Get an API's policy chain"
)
def get_policies(
    product_id: int,
    api_id: int,
    caller: Annotated[TenantCaller, Depends(require_any("policy:read"))],
) -> PolicyChainOut:
    return _chain_out(_policy_api(caller, product_id, api_id, "policy:read"))


def _secret(box: SecretBox | None, value: str, api_id: int, policy_id: str, field: str) -> str:
    if box is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="secrets encryption is not configured (APIEDGE_SECRET_KEY or the key file)",
        )
    return box.encrypt(value, secret_aad(api_id, policy_id, field))


@router.put(
    "/apis/{api_id}/policies",
    response_model=PolicyChainOut,
    summary="Replace an API's policy chain",
)
def put_policies(
    product_id: int,
    api_id: int,
    body: PolicyChain,
    request: Request,
    caller: Annotated[TenantCaller, Depends(require_any("policy:update"))],
) -> PolicyChainOut:
    api = _policy_api(caller, product_id, api_id, "policy:update")
    settings: Settings = request.app.state.settings
    box: SecretBox | None = request.app.state.secret_box
    existing = {str(e.get("id")): e for e in _stored(api)}
    route_paths = {r.path for r in api.routes}
    errors: list[str] = []
    stored: list[dict[str, Any]] = []
    for i, spec in enumerate(body.policies, start=1):
        pid = spec.id or secrets.token_hex(8)
        data = spec.model_dump(mode="json")
        data["id"] = pid
        unknown = [r for r in spec.routes if r not in route_paths]
        if unknown:
            errors.append(f"policy {i}: unknown route {unknown[0]}")
        previous = existing.get(pid)
        same_type = previous is not None and previous.get("type") == spec.type
        for field in SECRET_FIELDS.get(spec.type, ()):
            value = data["config"].get(field)
            if value is None:
                prior = (previous or {}).get("config") or {}
                data["config"][field] = prior.get(field) if same_type else None
            else:
                data["config"][field] = _secret(box, value, api.id, pid, field)
        if spec.type == "jwt":
            cfg = spec.config
            if set(cfg.algorithms) <= set(HMAC_ALGS) and not data["config"].get("secret"):
                errors.append(f"policy {i}: HS algorithms need a shared secret")
            if cfg.jwks_url:
                try:
                    check_url(cfg.jwks_url, settings.ssrf_policy())
                except SsrfError:
                    errors.append(f"policy {i}: JWKS {SSRF_HINT}")
            if cfg.public_key:
                try:
                    load_pem_key(cfg.public_key)
                except ValueError as exc:
                    errors.append(f"policy {i}: public key: {exc}")
        stored.append(data)
    if errors:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"policies": errors})
    document = json.dumps(stored, separators=(",", ":"))
    if len(document) > MAX_CHAIN_BYTES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="the policy chain is too large")
    api.policies = document
    audit(
        caller.session,
        "api.policies.update",
        tenant_id=caller.tenant_id,
        actor_id=caller.id,
        actor_username=caller.username,
        resource_type="api",
        resource_id=api.id,
        client_ip=caller.ip,
        details={
            "product_id": api.product_id,
            "policies": [f"{p['type']}:{p['id']}" for p in stored],
        },
    )
    caller.session.commit()
    caller.session.refresh(api)
    return _chain_out(api)


# --------------------------------------------------------------------------- API keys


class ApiKeyIn(In):
    name: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9 _.@-]{0,99}$")]
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def _future(cls, v: datetime | None) -> datetime | None:
        if v is None:
            return None
        if v.tzinfo is None:
            raise ValueError("include a time zone (for example 2027-01-01T00:00:00Z)")
        if v <= datetime.now(timezone.utc):
            raise ValueError("the expiry must be in the future")
        return v


class ApiKeyOut(Out):
    id: int
    product_id: int
    name: str
    prefix: str
    status: str  # active, expired or revoked
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None


class ApiKeyCreated(ApiKeyOut):
    key: str  # shown once


def _aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)  # SQLite drops the offset
    return value


def _key_out(k: ApiKey) -> ApiKeyOut:
    expires = _aware(k.expires_at)
    if k.revoked_at is not None:
        state = "revoked"
    elif expires is not None and expires <= datetime.now(timezone.utc):
        state = "expired"
    else:
        state = "active"
    return ApiKeyOut(
        id=k.id,
        product_id=k.product_id,
        name=k.name,
        prefix=k.prefix,
        status=state,
        created_at=_aware(k.created_at) or k.created_at,
        expires_at=expires,
        revoked_at=_aware(k.revoked_at),
    )


def _key_product(caller: TenantCaller, product_id: int, permission: str) -> Product:
    product = _product(caller, product_id, "api:read")
    if not caller.principal.has(permission, caller.tenant_id, product.id):
        raise deny(caller, permission, caller.tenant_id)
    return product


def _key_audit(caller: TenantCaller, action: str, key: ApiKey) -> None:
    audit(
        caller.session,
        action,
        tenant_id=caller.tenant_id,
        actor_id=caller.id,
        actor_username=caller.username,
        resource_type="api_key",
        resource_id=key.id,
        client_ip=caller.ip,
        details={"product_id": key.product_id, "name": key.name, "prefix": key.prefix},
    )


@router.get("/api-keys", response_model=list[ApiKeyOut], summary="List a product's API keys")
def list_keys(
    product_id: int, caller: Annotated[TenantCaller, Depends(require_any("apikey:read"))]
) -> list[ApiKeyOut]:
    product = _key_product(caller, product_id, "apikey:read")
    stmt = (
        select(ApiKey)
        .where(ApiKey.tenant_id == caller.tenant_id, ApiKey.product_id == product.id)
        .order_by(ApiKey.created_at.desc(), ApiKey.id.desc())
    )
    return [_key_out(k) for k in caller.session.scalars(stmt)]


@router.post(
    "/api-keys",
    response_model=ApiKeyCreated,
    status_code=201,
    summary="Create an API key (the key is shown only in this response)",
)
def create_key(
    product_id: int,
    body: ApiKeyIn,
    response: Response,
    caller: Annotated[TenantCaller, Depends(require_any("apikey:manage"))],
) -> ApiKeyCreated:
    product = _key_product(caller, product_id, "apikey:manage")
    if product.lifecycle == "retired":
        raise HTTPException(status.HTTP_409_CONFLICT, detail="the product is retired (read-only)")
    active = caller.session.scalar(
        select(func.count(ApiKey.id)).where(
            ApiKey.tenant_id == caller.tenant_id,
            ApiKey.product_id == product.id,
            ApiKey.revoked_at.is_(None),
        )
    )
    if (active or 0) >= MAX_ACTIVE_KEYS:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail=f"a product can have at most {MAX_ACTIVE_KEYS} keys"
        )
    plain = KEY_PREFIX + secrets.token_urlsafe(32)
    key = ApiKey(
        tenant_id=caller.tenant_id,
        product_id=product.id,
        name=body.name,
        prefix=plain[:11],
        key_hash=hash_api_key(plain),
        created_by=caller.id,
        expires_at=body.expires_at,
    )
    caller.session.add(key)
    caller.session.flush()
    _key_audit(caller, "apikey.create", key)
    caller.session.commit()
    caller.session.refresh(key)
    response.headers["cache-control"] = "no-store"
    return ApiKeyCreated(**_key_out(key).model_dump(), key=plain)


@router.post("/api-keys/{key_id}/revoke", response_model=ApiKeyOut, summary="Revoke an API key")
def revoke_key(
    product_id: int,
    key_id: int,
    caller: Annotated[TenantCaller, Depends(require_any("apikey:manage"))],
) -> ApiKeyOut:
    product = _key_product(caller, product_id, "apikey:manage")
    key = caller.session.get(ApiKey, key_id)
    if key is None or key.tenant_id != caller.tenant_id or key.product_id != product.id:
        raise not_found("API key not found")
    if key.revoked_at is None:
        key.revoked_at = datetime.now(timezone.utc)
        _key_audit(caller, "apikey.revoke", key)
        caller.session.commit()
        caller.session.refresh(key)
    return _key_out(key)
