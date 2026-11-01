# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""Tenant filter in the data-access layer, and RBAC catalog vs. migration drift (T-003)."""

from __future__ import annotations

import gc
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import inspect, select
from sqlalchemy.orm import Session, sessionmaker

from apiedge.db.base import alembic_config, make_engine, make_session_factory, run_migrations
from apiedge.db.models import AuditEvent, Role, RoleAssignment, Tenant, User
from apiedge.db.tenancy import CrossTenantWriteError, bind_tenant
from apiedge.security.rbac import BUILTIN_ROLES, PERMISSIONS


@pytest.fixture
def factory(tmp_path: Path) -> sessionmaker[Session]:
    url = f"sqlite:///{(tmp_path / 't.db').as_posix()}"
    run_migrations(url)
    f = make_session_factory(make_engine(url))
    with f() as s:
        a, b = Tenant(slug="a", name="A"), Tenant(slug="b", name="B")
        s.add_all([a, b])
        s.flush()
        s.add_all(
            [
                User(username="root", password_hash="x", is_superadmin=True),
                User(username="ua", tenant_id=a.id, password_hash="x"),
                User(username="ub", tenant_id=b.id, password_hash="x"),
                Role(tenant_id=b.id, name="Custom-B"),
                AuditEvent(tenant_id=a.id, action="x"),
                AuditEvent(tenant_id=b.id, action="x"),
                AuditEvent(tenant_id=None, action="x"),
            ]
        )
        s.commit()
    return f


def test_unbound_session_sees_everything(factory: sessionmaker[Session]) -> None:
    with factory() as s:
        assert len(s.scalars(select(User)).all()) == 3
        assert len(s.scalars(select(AuditEvent)).all()) == 3


def test_bound_session_is_filtered(factory: sessionmaker[Session]) -> None:
    with factory() as s:
        bind_tenant(s, 1)
        assert [u.username for u in s.scalars(select(User))] == ["ua"]
        assert len(s.scalars(select(AuditEvent)).all()) == 1
        roles = {r.name for r in s.scalars(select(Role))}
        assert set(BUILTIN_ROLES) <= roles and "Custom-B" not in roles
        ub_id = s.scalar(select(User.id).where(User.username == "ub"))
        assert ub_id is None


def test_session_get_is_filtered(factory: sessionmaker[Session]) -> None:
    with factory() as s:
        bind_tenant(s, 1)
        assert s.get(User, 3) is None  # 'ub' (tenant 2)
        assert s.get(User, 1) is None  # platform user


def test_cross_tenant_write_refused(factory: sessionmaker[Session]) -> None:
    with factory() as s:
        bind_tenant(s, 1)
        s.add(User(username="intruder", tenant_id=2, password_hash="x"))
        with pytest.raises(CrossTenantWriteError):
            s.flush()
    with factory() as s:
        bind_tenant(s, 1)
        builtin = s.scalars(select(Role).where(Role.name == "Viewer")).one()
        builtin.description = "changed"
        with pytest.raises(CrossTenantWriteError):
            s.flush()
    with factory() as s:
        bind_tenant(s, 1)
        s.add(RoleAssignment(tenant_id=2, user_id=3, role_id=1))
        with pytest.raises(CrossTenantWriteError):
            s.flush()


def test_migrated_catalog_matches_code(factory: sessionmaker[Session]) -> None:
    with factory() as s:
        from apiedge.db.models import Permission

        db_perms = {p.name: p.description for p in s.scalars(select(Permission))}
        assert db_perms == PERMISSIONS
        builtin = {r.name: set(r.permissions) for r in s.scalars(select(Role)) if r.is_builtin}
        assert builtin == {n: set(p) for n, (_, p) in BUILTIN_ROLES.items()}


def test_migration_downgrade_to_0001_and_back(tmp_path: Path) -> None:
    url = f"sqlite:///{(tmp_path / 'd.db').as_posix()}"
    run_migrations(url)
    command.downgrade(alembic_config(url), "0001")
    engine = make_engine(url)
    tables = inspect(engine).get_table_names()
    assert "users" in tables and "tenants" not in tables
    assert "tenant_id" not in {c["name"] for c in inspect(engine).get_columns("users")}
    engine.dispose()
    run_migrations(url)


def test_filter_installed_on_every_new_factory(factory: sessionmaker[Session]) -> None:
    """Regression: the install guard used ``event.contains``, whose registry is keyed by
    ``id(target)``. A new session factory allocated at the address of a garbage-collected one
    was reported as already filtered, so its sessions were not tenant-filtered at all."""
    engine = factory.kw["bind"]
    for _ in range(50):
        f = make_session_factory(engine)
        with f() as s:
            bind_tenant(s, 1)
            assert len(s.scalars(select(AuditEvent)).all()) == 1
            assert [u.username for u in s.scalars(select(User))] == ["ua"]
        del f, s
        gc.collect()
    # CPython usually hands the freed addresses straight back, but that depends on the allocator
    # (CI run 41312919574 saw no reuse on ubuntu / Python 3.10), so the next test forces the
    # failing condition deterministically.


def test_filter_installed_even_if_the_event_registry_claims_it(
    factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deterministic form of the regression above: the event registry reports every target as
    already listened to (what an address reuse looks like); the filter must still be installed."""
    from sqlalchemy import event

    monkeypatch.setattr(event, "contains", lambda *_a, **_k: True)
    f = make_session_factory(factory.kw["bind"])
    with f() as s:
        bind_tenant(s, 1)
        assert len(s.scalars(select(AuditEvent)).all()) == 1
        assert [u.username for u in s.scalars(select(User))] == ["ua"]
