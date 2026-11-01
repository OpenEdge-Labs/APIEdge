# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""Tenant-filtered data access (T-003, OWASP A01 / API1).

A session bound to a tenant with :func:`bind_tenant` automatically

* adds ``tenant_id = :tenant`` to every ORM SELECT of a :class:`TenantOwned` model, and
  ``tenant_id = :tenant OR tenant_id IS NULL`` for :class:`TenantOrGlobal` models
  (including joins, relationship loads and ``session.get``), and
* refuses to flush a tenant-owned row that belongs to another tenant.

So tenant isolation does not depend on every route handler remembering a WHERE clause.
Unbound sessions (platform scope: SuperAdmin platform routes, the CLI) are unfiltered.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import event, or_
from sqlalchemy.orm import ORMExecuteState, Session, with_loader_criteria

from apiedge.db.base import Base
from apiedge.db.models import TenantOrGlobal, TenantOwned

TENANT_KEY = "apiedge_tenant_id"


class CrossTenantWriteError(Exception):
    """A tenant-bound session tried to write another tenant's row."""


def bind_tenant(session: Session, tenant_id: int) -> None:
    session.info[TENANT_KEY] = tenant_id


def bound_tenant(session: Session) -> int | None:
    value = session.info.get(TENANT_KEY)
    return int(value) if value is not None else None


def _filter(state: ORMExecuteState) -> None:
    tid = bound_tenant(state.session)
    if tid is None or not state.is_select:
        return
    # Plain (non-lambda) criteria per mapped class: the tenant id is a bound parameter.
    options = []
    for cls in _scoped_classes():
        col = cls.tenant_id
        crit = or_(col == tid, col.is_(None)) if issubclass(cls, TenantOrGlobal) else col == tid
        options.append(with_loader_criteria(cls, crit, include_aliases=True))
    state.statement = state.statement.options(*options)


def _scoped_classes() -> list[Any]:
    return [
        m.class_
        for m in Base.registry.mappers
        if issubclass(m.class_, (TenantOwned, TenantOrGlobal))
    ]


def _guard_writes(session: Session, _ctx: Any, _instances: Any) -> None:
    tid = bound_tenant(session)
    if tid is None:
        return
    for obj in list(session.new) + list(session.dirty) + list(session.deleted):
        # Global rows (tenant_id NULL) are read-only for tenant-bound sessions.
        if isinstance(obj, (TenantOwned, TenantOrGlobal)) and getattr(obj, "tenant_id") != tid:  # noqa: B009
            raise CrossTenantWriteError(type(obj).__name__)


_INSTALLED = "_apiedge_tenant_filter"


def install_tenant_filter(target: Any) -> None:
    """Register the filter on a ``sessionmaker`` (or ``Session`` class). Idempotent.

    The guard is a marker stored on the target itself. ``event.contains`` must not be used:
    SQLAlchemy's event registry is keyed by ``id(target)``, so a new factory allocated at the
    address of a garbage-collected one would be reported as filtered and left unfiltered.
    """
    if vars(target).get(_INSTALLED):
        return
    event.listen(target, "do_orm_execute", _filter)
    event.listen(target, "before_flush", _guard_writes)
    setattr(target, _INSTALLED, True)
