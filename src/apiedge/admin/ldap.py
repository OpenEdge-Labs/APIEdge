# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""LDAP and Active Directory directories of a tenant (T-023, ADR 0016).

| Route | Permission (tenant-wide) |
|---|---|
| ``GET .../ldap/directories[/{directory_id}]`` | ``ldap:read`` |
| ``POST .../ldap/directories`` | ``ldap:manage`` |
| ``PATCH``/``DELETE .../ldap/directories/{directory_id}`` | ``ldap:manage`` |
| ``POST .../ldap/directories/{directory_id}/test`` | ``ldap:manage`` |

Every query runs on a tenant-bound session; another tenant's directories answer 404. The host
passes the SSRF guard when saved and again on every connection. The service account's password is
stored encrypted with the secrets box (bound to tenant and directory), is never returned and must
be entered again when the host, port, security mode or truststore changes, so it cannot be
redirected to another server. Directories used by a ``basic-ldap`` policy cannot be deleted.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import Field, StringConstraints, field_validator
from sqlalchemy import select

from apiedge.admin.deps import TenantCaller, not_found, require
from apiedge.admin.schemas import In, Out
from apiedge.config import Settings
from apiedge.db.models import Api, LdapDirectory, Truststore
from apiedge.gateway.snapshot import runtime_directory
from apiedge.security import ldap
from apiedge.security.audit import audit
from apiedge.security.crypto import CryptoError, SecretBox

router = APIRouter(prefix="/tenants/{tenant_id}/ldap", tags=["ldap"])

MAX_PER_TENANT = 50

Name = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9 _.@-]{0,99}$")]
Description = Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)]
Host = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9:][A-Za-z0-9:.-]{0,254}$")]
Port = Annotated[int, Field(ge=1, le=65535)]
Security = Literal["ldaps", "starttls", "plain"]
Timeout = Annotated[int, Field(ge=1, le=60)]
Dn = Annotated[str, StringConstraints(max_length=1024, pattern=r"^[^\x00-\x1f\x7f]*$")]
Password = Annotated[str, StringConstraints(max_length=ldap.MAX_INPUT)]
Attribute = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9.;-]{0,127}$")]
OptionalAttribute = Annotated[
    str, StringConstraints(pattern=r"^([A-Za-z0-9][A-Za-z0-9.;-]{0,127})?$")
]


def _valid_filter(value: str | None) -> str | None:
    if value is None:
        return None
    if "{username}" not in value:
        raise ValueError("the filter must contain {username}")
    try:
        ldap.parse_filter(ldap.fill_template(value, username="user"))
    except ldap.LdapError as exc:
        raise ValueError(str(exc)) from exc
    return value


def _valid_template(value: str | None) -> str | None:
    if value and "{username}" not in value:
        raise ValueError("the template must contain {username}")
    return value


class DirectoryIn(In):
    name: Name
    description: Description = ""
    host: Host
    port: Port = 636
    security: Security = "ldaps"
    truststore_id: int | None = Field(default=None, ge=1)
    timeout_seconds: Timeout = 5
    bind_dn: Dn = ""
    bind_password: Password = ""  # write-only
    user_base_dn: Dn = ""
    user_filter: Annotated[str, StringConstraints(max_length=1024)] = "(uid={username})"
    user_dn_template: Dn = ""
    username_attribute: Attribute = "uid"
    email_attribute: OptionalAttribute = "mail"
    name_attribute: OptionalAttribute = "cn"

    _f = field_validator("user_filter")(_valid_filter)
    _t = field_validator("user_dn_template")(_valid_template)


class DirectoryUpdate(In):
    """Omitted fields keep their value. ``bind_password``: omitted keeps it, empty clears it."""

    description: Description | None = None
    host: Host | None = None
    port: Port | None = None
    security: Security | None = None
    truststore_id: int | None = Field(default=None, ge=1)
    timeout_seconds: Timeout | None = None
    bind_dn: Dn | None = None
    bind_password: Password | None = None
    user_base_dn: Dn | None = None
    user_filter: Annotated[str, StringConstraints(max_length=1024)] | None = None
    user_dn_template: Dn | None = None
    username_attribute: Attribute | None = None
    email_attribute: OptionalAttribute | None = None
    name_attribute: OptionalAttribute | None = None

    _f = field_validator("user_filter")(_valid_filter)
    _t = field_validator("user_dn_template")(_valid_template)


class DirectoryOut(Out):
    id: int
    name: str
    description: str
    host: str
    port: int
    security: str
    truststore_id: int | None
    timeout_seconds: int
    bind_dn: str
    bind_password_set: bool
    user_base_dn: str
    user_filter: str
    user_dn_template: str
    username_attribute: str
    email_attribute: str
    name_attribute: str
    apis: list[str]  # APIs whose basic-ldap policy uses this directory
    created_at: datetime
    updated_at: datetime


class DirectoryTestOut(Out):
    ok: bool
    message: str


def directory_users(caller: TenantCaller, directory_id: int) -> list[str]:
    """Names of the tenant's APIs whose policy chain refers to the directory."""
    names = []
    for api in caller.session.scalars(select(Api).where(Api.tenant_id == caller.tenant_id)):
        try:
            entries = json.loads(api.policies or "[]")
        except ValueError:
            continue
        for e in entries if isinstance(entries, list) else []:
            cfg = e.get("config") if isinstance(e, dict) else None
            if (
                isinstance(cfg, dict)
                and e.get("type") == "basic-ldap"
                and cfg.get("directory_id") == directory_id
            ):
                names.append(api.name)
                break
    return names


def _out(caller: TenantCaller, d: LdapDirectory) -> DirectoryOut:
    return DirectoryOut(
        id=d.id,
        name=d.name,
        description=d.description,
        host=d.host,
        port=d.port,
        security=d.security,
        truststore_id=d.truststore_id,
        timeout_seconds=d.timeout_seconds,
        bind_dn=d.bind_dn,
        bind_password_set=bool(d.bind_password),
        user_base_dn=d.user_base_dn,
        user_filter=d.user_filter,
        user_dn_template=d.user_dn_template,
        username_attribute=d.username_attribute,
        email_attribute=d.email_attribute,
        name_attribute=d.name_attribute,
        apis=sorted(directory_users(caller, d.id)),
        created_at=d.created_at,
        updated_at=d.updated_at,
    )


def _audit(caller: TenantCaller, action: str, d: LdapDirectory, **details: Any) -> None:
    audit(
        caller.session,
        action,
        tenant_id=caller.tenant_id,
        actor_id=caller.id,
        actor_username=caller.username,
        resource_type="ldap_directory",
        resource_id=d.id,
        client_ip=caller.ip,
        details={"name": d.name, **details},
    )


def _bad(detail: str) -> HTTPException:
    return HTTPException(status.HTTP_400_BAD_REQUEST, detail=detail)


def _directory(caller: TenantCaller, directory_id: int) -> LdapDirectory:
    d = caller.session.get(LdapDirectory, directory_id)
    if d is None or d.tenant_id != caller.tenant_id:
        raise not_found("Directory not found")
    return d


def _store_password(request: Request, d: LdapDirectory, password: str, tenant_id: int) -> None:
    if not password:
        d.bind_password = None
        return
    box: SecretBox | None = request.app.state.secret_box
    if box is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="secrets encryption is not configured (APIEDGE_SECRET_KEY or the key file)",
        )
    d.bind_password = box.encrypt(password, ldap.bind_password_aad(tenant_id, d.id))


def _validate(request: Request, caller: TenantCaller, d: LdapDirectory) -> None:
    """Checks across fields, the truststore's owner and the SSRF guard."""
    if bool(d.bind_dn) != bool(d.bind_password):
        raise _bad("a service account needs both a bind DN and a password")
    if not d.user_dn_template and not d.user_base_dn:
        raise _bad("set a user base DN (to search for users) or a user DN template")
    if d.truststore_id is not None:
        store = caller.session.get(Truststore, d.truststore_id)
        if store is None or store.tenant_id != caller.tenant_id:
            raise _bad(f"truststore {d.truststore_id} not found")
    settings: Settings = request.app.state.settings
    try:
        ldap.resolve_checked(d.host, d.port, settings.ssrf_policy())
    except ldap.LdapError as exc:
        raise _bad(
            f"{exc} (private, loopback, link-local and cloud metadata addresses are blocked "
            "unless an administrator allows them)"
        ) from exc


@router.get("/directories", response_model=list[DirectoryOut], summary="List LDAP directories")
def list_directories(
    caller: Annotated[TenantCaller, Depends(require("ldap:read"))],
) -> list[DirectoryOut]:
    stmt = (
        select(LdapDirectory)
        .where(LdapDirectory.tenant_id == caller.tenant_id)
        .order_by(LdapDirectory.name)
    )
    return [_out(caller, d) for d in caller.session.scalars(stmt)]


@router.post(
    "/directories", response_model=DirectoryOut, status_code=201, summary="Create an LDAP directory"
)
def create_directory(
    body: DirectoryIn,
    request: Request,
    caller: Annotated[TenantCaller, Depends(require("ldap:manage"))],
) -> DirectoryOut:
    existing = caller.session.scalars(
        select(LdapDirectory.name).where(LdapDirectory.tenant_id == caller.tenant_id)
    ).all()
    if body.name in existing:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="the name is already used")
    if len(existing) >= MAX_PER_TENANT:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail=f"a tenant can have at most {MAX_PER_TENANT}"
        )
    d = LdapDirectory(
        tenant_id=caller.tenant_id,
        **body.model_dump(exclude={"bind_password"}),
    )
    # The password's associated data contains the row id, so it is encrypted after the flush.
    d.bind_password = "pending" if body.bind_password else None
    _validate(request, caller, d)
    caller.session.add(d)
    caller.session.flush()
    _store_password(request, d, body.bind_password, caller.tenant_id)
    _audit(caller, "ldap.directory.create", d, host=d.host, port=d.port, security=d.security)
    caller.session.commit()
    caller.session.refresh(d)
    return _out(caller, d)


@router.get(
    "/directories/{directory_id}", response_model=DirectoryOut, summary="Get an LDAP directory"
)
def get_directory(
    directory_id: int, caller: Annotated[TenantCaller, Depends(require("ldap:read"))]
) -> DirectoryOut:
    return _out(caller, _directory(caller, directory_id))


@router.patch(
    "/directories/{directory_id}", response_model=DirectoryOut, summary="Change an LDAP directory"
)
def update_directory(
    directory_id: int,
    body: DirectoryUpdate,
    request: Request,
    caller: Annotated[TenantCaller, Depends(require("ldap:manage"))],
) -> DirectoryOut:
    d = _directory(caller, directory_id)
    changes = {
        field: value
        for field, value in body.model_dump(exclude_unset=True).items()
        if value is not None or field == "truststore_id"  # null keeps a value, except here
    }
    password = changes.pop("bind_password", None)
    # Where the password goes and how it is protected: changing this must not send the stored
    # password to a server chosen by whoever can edit the directory, so it has to be re-entered.
    moved = any(
        field in changes and changes[field] != getattr(d, field)
        for field in ("host", "port", "security", "truststore_id")
    )
    for field, value in changes.items():
        setattr(d, field, value)
    if password is not None:
        _store_password(request, d, password, caller.tenant_id)
    if not d.bind_dn:
        d.bind_password = None  # no service account any more: do not keep its password
    if moved and d.bind_password and password is None:
        raise _bad(
            "enter the service account's password again when the host, port, security or "
            "truststore changes"
        )
    with caller.session.no_autoflush:
        _validate(request, caller, d)
    _audit(
        caller,
        "ldap.directory.update",
        d,
        fields=sorted(changes) + (["bind_password"] if password is not None else []),
    )
    caller.session.commit()
    caller.session.refresh(d)
    return _out(caller, d)


@router.delete("/directories/{directory_id}", status_code=204, summary="Delete an LDAP directory")
def delete_directory(
    directory_id: int, caller: Annotated[TenantCaller, Depends(require("ldap:manage"))]
) -> Response:
    d = _directory(caller, directory_id)
    users = directory_users(caller, d.id)
    if users:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"the directory is in use by: {', '.join(sorted(users)[:10])}",
        )
    _audit(caller, "ldap.directory.delete", d)
    caller.session.delete(d)
    caller.session.commit()
    return Response(status_code=204)


@router.post(
    "/directories/{directory_id}/test",
    response_model=DirectoryTestOut,
    summary="Connect to an LDAP directory and bind as its service account",
)
def test_directory(
    directory_id: int,
    request: Request,
    caller: Annotated[TenantCaller, Depends(require("ldap:manage"))],
) -> DirectoryTestOut:
    d = _directory(caller, directory_id)
    settings: Settings = request.app.state.settings
    try:
        runtime = runtime_directory(caller.session, d, request.app.state.secret_box)
        ldap.check_directory(runtime, ssrf_policy=settings.ssrf_policy())
        result = DirectoryTestOut(ok=True, message="Connected.")
    except (ldap.LdapError, ValueError, CryptoError) as exc:
        message = str(exc) if isinstance(exc, ldap.LdapError) else "the configuration is unusable"
        result = DirectoryTestOut(ok=False, message=message[:300])
    _audit(caller, "ldap.directory.test", d, ok=result.ok)
    caller.session.commit()
    return result
