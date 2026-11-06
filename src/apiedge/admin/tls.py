# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Truststores and keystores (T-023, ADR 0013).

| Route | Permission (tenant-wide) |
|---|---|
| ``GET .../tls/truststores[/{truststore_id}]`` | ``tls:read`` |
| ``POST .../tls/truststores``, ``PATCH``/``DELETE .../{truststore_id}`` | ``tls:manage`` |
| ``GET .../tls/keystores[/{keystore_id}]`` | ``tls:read`` |
| ``POST .../tls/keystores``, ``DELETE .../tls/keystores/{keystore_id}`` | ``tls:manage`` |
| ``GET .../tls/profiles[/{profile_id}]`` | ``tls:read`` |
| ``POST .../tls/profiles``, ``PATCH``/``DELETE .../tls/profiles/{profile_id}`` | ``tls:manage`` |

Every query runs on a tenant-bound session; another tenant's objects answer 404. Uploaded
certificates are parsed and re-encoded (only certificates are kept from a PEM bundle). A
keystore's private key must match its certificate, is stored encrypted with the secrets box
(bound to tenant and keystore) and is never returned. Truststores used by an ``mtls`` policy
cannot be deleted. TLS profiles tell the gateway how to connect to an API's HTTPS upstreams:
lowest TLS version, TLS 1.2 ciphers, the truststore verifying the upstream and the keystore
presented as client certificate. Profiles, truststores and keystores in use cannot be deleted.
"""

from __future__ import annotations

import json
import ssl
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import Field, StringConstraints
from sqlalchemy import select

from apiedge.admin.deps import TenantCaller, not_found, require
from apiedge.admin.schemas import In, Out
from apiedge.db.models import Api, Keystore, LdapDirectory, TlsProfile, Truststore
from apiedge.security.audit import audit
from apiedge.security.crypto import SecretBox
from apiedge.security.tls import keystore_aad
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


def _profile_users(caller: TenantCaller, column: str, obj_id: int) -> list[str]:
    stmt = select(TlsProfile.name).where(
        TlsProfile.tenant_id == caller.tenant_id, getattr(TlsProfile, column) == obj_id
    )
    return [f"TLS profile {n}" for n in caller.session.scalars(stmt)]


def _directory_users(caller: TenantCaller, truststore_id: int) -> list[str]:
    stmt = select(LdapDirectory.name).where(
        LdapDirectory.tenant_id == caller.tenant_id, LdapDirectory.truststore_id == truststore_id
    )
    return [f"LDAP directory {n}" for n in caller.session.scalars(stmt)]


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
    users = (
        truststore_users(caller, t.id)
        + _profile_users(caller, "truststore_id", t.id)
        + _directory_users(caller, t.id)
    )
    if users:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"the truststore is in use by: {', '.join(sorted(users)[:10])}",
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
    users = _profile_users(caller, "keystore_id", k.id)
    if users:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"the keystore is in use by: {', '.join(sorted(users)[:10])}",
        )
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


# --------------------------------------------------------------------------- TLS profiles

Ciphers = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9+:!@=_-]{1,2000}$")]


class TlsProfileIn(In):
    name: Name
    description: Description = ""
    min_version: Literal["1.2", "1.3"] = "1.2"
    ciphers: Ciphers | None = None
    truststore_id: int | None = Field(default=None, ge=1)
    keystore_id: int | None = Field(default=None, ge=1)


class TlsProfilePatch(In):
    description: Description | None = None
    min_version: Literal["1.2", "1.3"] | None = None
    ciphers: Ciphers | None = None
    truststore_id: int | None = Field(default=None, ge=1)
    keystore_id: int | None = Field(default=None, ge=1)


class TlsProfileOut(Out):
    id: int
    name: str
    description: str
    min_version: str
    ciphers: str | None
    truststore_id: int | None
    keystore_id: int | None
    apis: list[str]
    created_at: datetime
    updated_at: datetime


def _profile(caller: TenantCaller, profile_id: int) -> TlsProfile:
    p = caller.session.get(TlsProfile, profile_id)
    if p is None or p.tenant_id != caller.tenant_id:
        raise not_found("TLS profile not found")
    return p


def _profile_apis(caller: TenantCaller, profile_id: int) -> list[str]:
    stmt = select(Api.name).where(
        Api.tenant_id == caller.tenant_id, Api.tls_profile_id == profile_id
    )
    return sorted(caller.session.scalars(stmt))


def _profile_out(caller: TenantCaller, p: TlsProfile) -> TlsProfileOut:
    return TlsProfileOut(
        id=p.id,
        name=p.name,
        description=p.description,
        min_version=p.min_version,
        ciphers=p.ciphers,
        truststore_id=p.truststore_id,
        keystore_id=p.keystore_id,
        apis=_profile_apis(caller, p.id),
        created_at=p.created_at,
        updated_at=p.updated_at,
    )


def _check_refs(caller: TenantCaller, truststore_id: int | None, keystore_id: int | None) -> None:
    """Referenced stores must exist in the caller's tenant (400, no existence disclosure)."""
    if truststore_id is not None:
        t = caller.session.get(Truststore, truststore_id)
        if t is None or t.tenant_id != caller.tenant_id:
            raise _bad(f"truststore {truststore_id} not found")
    if keystore_id is not None:
        k = caller.session.get(Keystore, keystore_id)
        if k is None or k.tenant_id != caller.tenant_id:
            raise _bad(f"keystore {keystore_id} not found")


def _check_ciphers(ciphers: str | None) -> None:
    if ciphers is None:
        return
    try:
        ssl.create_default_context().set_ciphers(ciphers)
    except ssl.SSLError as exc:
        raise _bad("the cipher list selects no usable cipher") from exc


@router.get("/profiles", response_model=list[TlsProfileOut], summary="List TLS profiles")
def list_profiles(
    caller: Annotated[TenantCaller, Depends(require("tls:read"))],
) -> list[TlsProfileOut]:
    stmt = (
        select(TlsProfile).where(TlsProfile.tenant_id == caller.tenant_id).order_by(TlsProfile.name)
    )
    return [_profile_out(caller, p) for p in caller.session.scalars(stmt)]


@router.post(
    "/profiles", response_model=TlsProfileOut, status_code=201, summary="Create a TLS profile"
)
def create_profile(
    body: TlsProfileIn, caller: Annotated[TenantCaller, Depends(require("tls:manage"))]
) -> TlsProfileOut:
    _check_refs(caller, body.truststore_id, body.keystore_id)
    _check_ciphers(body.ciphers)
    _unique(caller, TlsProfile, body.name)
    p = TlsProfile(tenant_id=caller.tenant_id, **body.model_dump())
    caller.session.add(p)
    caller.session.flush()
    _audit(caller, "tls_profile.create", "tls_profile", p.id, body.model_dump())
    caller.session.commit()
    caller.session.refresh(p)
    return _profile_out(caller, p)


@router.get("/profiles/{profile_id}", response_model=TlsProfileOut, summary="Get a TLS profile")
def get_profile(
    profile_id: int, caller: Annotated[TenantCaller, Depends(require("tls:read"))]
) -> TlsProfileOut:
    return _profile_out(caller, _profile(caller, profile_id))


@router.patch(
    "/profiles/{profile_id}",
    response_model=TlsProfileOut,
    summary="Change a TLS profile (null clears the truststore, keystore or cipher list)",
)
def update_profile(
    profile_id: int,
    body: TlsProfilePatch,
    caller: Annotated[TenantCaller, Depends(require("tls:manage"))],
) -> TlsProfileOut:
    p = _profile(caller, profile_id)
    changes = body.model_dump(exclude_unset=True)
    for required in ("description", "min_version"):
        if changes.get(required) is None:
            changes.pop(required, None)
    _check_refs(caller, changes.get("truststore_id"), changes.get("keystore_id"))
    _check_ciphers(changes.get("ciphers"))
    for field, value in changes.items():
        setattr(p, field, value)
    _audit(caller, "tls_profile.update", "tls_profile", p.id, {"name": p.name, **changes})
    caller.session.commit()
    caller.session.refresh(p)
    return _profile_out(caller, p)


@router.delete("/profiles/{profile_id}", status_code=204, summary="Delete a TLS profile")
def delete_profile(
    profile_id: int, caller: Annotated[TenantCaller, Depends(require("tls:manage"))]
) -> Response:
    p = _profile(caller, profile_id)
    apis = _profile_apis(caller, p.id)
    if apis:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"the TLS profile is used by the APIs: {', '.join(apis[:10])}",
        )
    _audit(caller, "tls_profile.delete", "tls_profile", p.id, {"name": p.name})
    caller.session.delete(p)
    caller.session.commit()
    return Response(status_code=204)
