# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Truststores and keystores (T-023, ADR 0013).

| Route | Permission (tenant-wide) |
|---|---|
| ``GET .../tls/truststores[/{truststore_id}]`` | ``tls:read`` |
| ``POST .../tls/truststores``, ``PATCH``/``DELETE .../{truststore_id}`` | ``tls:manage`` |
| ``GET .../tls/keystores[/{keystore_id}]`` | ``tls:read`` |
| ``POST .../tls/keystores``, ``DELETE .../tls/keystores/{keystore_id}`` | ``tls:manage`` |

Every query runs on a tenant-bound session; another tenant's objects answer 404. Uploaded
certificates are parsed and re-encoded (only certificates are kept from a PEM bundle). A
keystore's private key must match its certificate, is stored encrypted with the secrets box
(bound to tenant and keystore) and is never returned. Truststores used by an ``mtls`` policy
cannot be deleted.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import Field, StringConstraints
from sqlalchemy import select

from apiedge.admin.deps import TenantCaller, not_found, require
from apiedge.admin.schemas import In, Out
from apiedge.db.models import Api, Keystore, Truststore
from apiedge.security.audit import audit
from apiedge.security.crypto import SecretBox
from apiedge.security.x509 import (
    CertificateError,
    bundle_pem,
    describe,
    describe_key,
    key_matches,
    load_pem_certificates,
    load_private_key,
    private_key_pem,
)

router = APIRouter(prefix="/tenants/{tenant_id}/tls", tags=["tls"])

MAX_PER_TENANT = 200
MAX_CHAIN_CERTS = 10

Name = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9 _.@-]{0,99}$")]
Description = Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)]
Pem = Annotated[str, StringConstraints(min_length=1, max_length=512 * 1024)]


class CertificateOut(Out):
    subject: str
    issuer: str
    common_name: str
    serial: str
    not_before: datetime
    not_after: datetime
    fingerprint_sha256: str
    key_type: str
    is_ca: bool
    dns_names: list[str]
    status: str  # valid, expiring (within 30 days), expired, not_yet_valid


class TruststoreIn(In):
    name: Name
    description: Description = ""
    certificates: Pem


class TruststoreUpdate(In):
    description: Description | None = None
    certificates: Pem | None = None


class TruststoreOut(Out):
    id: int
    name: str
    description: str
    certificates: list[CertificateOut]
    pem: str
    created_at: datetime
    updated_at: datetime


class KeystoreIn(In):
    name: Name
    description: Description = ""
    certificate_chain: Pem  # leaf first, then intermediates
    private_key: Annotated[str, StringConstraints(min_length=1, max_length=64 * 1024)]
    passphrase: str | None = Field(default=None, max_length=1024)


class KeystoreOut(Out):
    id: int
    name: str
    description: str
    key_type: str
    certificate: CertificateOut
    chain: list[CertificateOut]
    created_at: datetime
    updated_at: datetime


def keystore_aad(tenant_id: int, keystore_id: int) -> str:
    return f"keystore:{tenant_id}:{keystore_id}"


def _bad(detail: str) -> HTTPException:
    return HTTPException(status.HTTP_400_BAD_REQUEST, detail=detail)


def _certs(text: str, *, limit: int = 100) -> list[Any]:
    try:
        return load_pem_certificates(text, limit=limit)
    except CertificateError as exc:
        raise _bad(str(exc)) from exc


def _truststore_out(t: Truststore) -> TruststoreOut:
    certs = load_pem_certificates(t.certificates) if t.certificates else []
    return TruststoreOut(
        id=t.id,
        name=t.name,
        description=t.description,
        certificates=[CertificateOut(**describe(c)) for c in certs],
        pem=t.certificates,
        created_at=t.created_at,
        updated_at=t.updated_at,
    )


def _keystore_out(k: Keystore) -> KeystoreOut:
    chain = [CertificateOut(**describe(c)) for c in load_pem_certificates(k.certificate_chain)]
    return KeystoreOut(
        id=k.id,
        name=k.name,
        description=k.description,
        key_type=k.key_type,
        certificate=chain[0],
        chain=chain[1:],
        created_at=k.created_at,
        updated_at=k.updated_at,
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


def _count(caller: TenantCaller, model: Any) -> int:
    return len(
        caller.session.scalars(select(model.id).where(model.tenant_id == caller.tenant_id)).all()
    )


def _unique(caller: TenantCaller, model: Any, name: str) -> None:
    exists = caller.session.scalar(
        select(model.id).where(model.tenant_id == caller.tenant_id, model.name == name)
    )
    if exists is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="the name is already used")
    if _count(caller, model) >= MAX_PER_TENANT:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail=f"a tenant can have at most {MAX_PER_TENANT}"
        )


def truststore_users(caller: TenantCaller, truststore_id: int) -> list[str]:
    """Names of the tenant's APIs whose policy chain refers to the truststore."""
    names = []
    for api in caller.session.scalars(select(Api).where(Api.tenant_id == caller.tenant_id)):
        try:
            entries = json.loads(api.policies or "[]")
        except ValueError:
            continue
        for e in entries if isinstance(entries, list) else []:
            cfg = e.get("config") if isinstance(e, dict) else None
            if isinstance(cfg, dict) and cfg.get("truststore_id") == truststore_id:
                names.append(api.name)
                break
    return names


# --------------------------------------------------------------------------- truststores


def _truststore(caller: TenantCaller, truststore_id: int) -> Truststore:
    t = caller.session.get(Truststore, truststore_id)
    if t is None or t.tenant_id != caller.tenant_id:
        raise not_found("Truststore not found")
    return t


@router.get("/truststores", response_model=list[TruststoreOut], summary="List truststores")
def list_truststores(
    caller: Annotated[TenantCaller, Depends(require("tls:read"))],
) -> list[TruststoreOut]:
    stmt = (
        select(Truststore).where(Truststore.tenant_id == caller.tenant_id).order_by(Truststore.name)
    )
    return [_truststore_out(t) for t in caller.session.scalars(stmt)]


@router.post(
    "/truststores", response_model=TruststoreOut, status_code=201, summary="Create a truststore"
)
def create_truststore(
    body: TruststoreIn, caller: Annotated[TenantCaller, Depends(require("tls:manage"))]
) -> TruststoreOut:
    certs = _certs(body.certificates)
    _unique(caller, Truststore, body.name)
    t = Truststore(
        tenant_id=caller.tenant_id,
        name=body.name,
        description=body.description,
        certificates=bundle_pem(certs),
    )
    caller.session.add(t)
    caller.session.flush()
    _audit(
        caller,
        "truststore.create",
        "truststore",
        t.id,
        {"name": t.name, "fingerprints": [c.fingerprint_sha256 for c in certs]},
    )
    caller.session.commit()
    caller.session.refresh(t)
    return _truststore_out(t)


@router.get(
    "/truststores/{truststore_id}", response_model=TruststoreOut, summary="Get a truststore"
)
def get_truststore(
    truststore_id: int, caller: Annotated[TenantCaller, Depends(require("tls:read"))]
) -> TruststoreOut:
    return _truststore_out(_truststore(caller, truststore_id))


@router.patch(
    "/truststores/{truststore_id}",
    response_model=TruststoreOut,
    summary="Change a truststore's description or certificates",
)
def update_truststore(
    truststore_id: int,
    body: TruststoreUpdate,
    caller: Annotated[TenantCaller, Depends(require("tls:manage"))],
) -> TruststoreOut:
    t = _truststore(caller, truststore_id)
    details: dict[str, Any] = {"name": t.name}
    if body.description is not None:
        t.description = body.description
    if body.certificates is not None:
        certs = _certs(body.certificates)
        t.certificates = bundle_pem(certs)
        details["fingerprints"] = [c.fingerprint_sha256 for c in certs]
    _audit(caller, "truststore.update", "truststore", t.id, details)
    caller.session.commit()
    caller.session.refresh(t)
    return _truststore_out(t)


@router.delete("/truststores/{truststore_id}", status_code=204, summary="Delete a truststore")
def delete_truststore(
    truststore_id: int, caller: Annotated[TenantCaller, Depends(require("tls:manage"))]
) -> Response:
    t = _truststore(caller, truststore_id)
    users = truststore_users(caller, t.id)
    if users:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"the truststore is used by the policies of: {', '.join(sorted(users)[:10])}",
        )
    _audit(caller, "truststore.delete", "truststore", t.id, {"name": t.name})
    caller.session.delete(t)
    caller.session.commit()
    return Response(status_code=204)


# --------------------------------------------------------------------------- keystores


def _keystore(caller: TenantCaller, keystore_id: int) -> Keystore:
    k = caller.session.get(Keystore, keystore_id)
    if k is None or k.tenant_id != caller.tenant_id:
        raise not_found("Keystore not found")
    return k


@router.get("/keystores", response_model=list[KeystoreOut], summary="List keystores")
def list_keystores(
    caller: Annotated[TenantCaller, Depends(require("tls:read"))],
) -> list[KeystoreOut]:
    stmt = select(Keystore).where(Keystore.tenant_id == caller.tenant_id).order_by(Keystore.name)
    return [_keystore_out(k) for k in caller.session.scalars(stmt)]


@router.post(
    "/keystores",
    response_model=KeystoreOut,
    status_code=201,
    summary="Create a keystore (certificate chain and private key)",
)
def create_keystore(
    body: KeystoreIn,
    request: Request,
    caller: Annotated[TenantCaller, Depends(require("tls:manage"))],
) -> KeystoreOut:
    box: SecretBox | None = request.app.state.secret_box
    if box is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="secrets encryption is not configured (APIEDGE_SECRET_KEY or the key file)",
        )
    chain = _certs(body.certificate_chain, limit=MAX_CHAIN_CERTS)
    try:
        key = load_private_key(body.private_key, body.passphrase or None)
    except CertificateError as exc:
        raise _bad(str(exc)) from exc
    if not key_matches(chain[0], key):
        raise _bad("the private key does not belong to the first certificate of the chain")
    _unique(caller, Keystore, body.name)
    k = Keystore(
        tenant_id=caller.tenant_id,
        name=body.name,
        description=body.description,
        certificate_chain=bundle_pem(chain),
        private_key="",
        key_type=describe_key(key)[:32],
        fingerprint_sha256=chain[0].fingerprint_sha256,
        not_after=chain[0].not_after,
    )
    caller.session.add(k)
    caller.session.flush()
    k.private_key = box.encrypt(private_key_pem(key), keystore_aad(caller.tenant_id, k.id))
    _audit(
        caller,
        "keystore.create",
        "keystore",
        k.id,
        {"name": k.name, "fingerprint": k.fingerprint_sha256},
    )
    caller.session.commit()
    caller.session.refresh(k)
    return _keystore_out(k)


@router.get("/keystores/{keystore_id}", response_model=KeystoreOut, summary="Get a keystore")
def get_keystore(
    keystore_id: int, caller: Annotated[TenantCaller, Depends(require("tls:read"))]
) -> KeystoreOut:
    return _keystore_out(_keystore(caller, keystore_id))


@router.delete("/keystores/{keystore_id}", status_code=204, summary="Delete a keystore")
def delete_keystore(
    keystore_id: int, caller: Annotated[TenantCaller, Depends(require("tls:manage"))]
) -> Response:
    k = _keystore(caller, keystore_id)
    _audit(
        caller,
        "keystore.delete",
        "keystore",
        k.id,
        {"name": k.name, "fingerprint": k.fingerprint_sha256},
    )
    caller.session.delete(k)
    caller.session.commit()
    return Response(status_code=204)
