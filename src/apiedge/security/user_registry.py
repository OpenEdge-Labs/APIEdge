# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""User registries for the OAuth authorization endpoint (T-023, ADR 0015).

The people who sign in at a tenant's ``/oauth2/authorize`` page are looked up in a
:class:`UserRegistry`. The only registry today is :class:`ConsoleUserRegistry`: the tenant's own
console users, with the same password check, account lockout and TOTP as the console sign-in.
Other registries (LDAP / Active Directory) implement the same protocol.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from apiedge.db.models import Tenant, User
from apiedge.security import auth
from apiedge.security.crypto import CryptoError, SecretBox
from apiedge.security.passwords import hash_password, verify_password


@dataclass(frozen=True)
class RegistryUser:
    """A signed-in end user, as the authorization server sees them."""

    user_id: int
    username: str
    email: str | None


@dataclass(frozen=True)
class AuthOutcome:
    user: RegistryUser | None
    # "ok", "invalid_credentials", "mfa_required", "invalid_mfa_code", "locked"
    reason: str


class UserRegistry(Protocol):
    name: str

    def authenticate(
        self,
        session: Session,
        tenant_id: int,
        username: str,
        password: str,
        totp_code: str | None,
    ) -> AuthOutcome: ...

    def lookup(self, session: Session, tenant_id: int, user_id: int) -> RegistryUser | None: ...


@functools.lru_cache(maxsize=1)
def _dummy_hash() -> str:
    return hash_password("apiedge-timing-equalizer")


class ConsoleUserRegistry:
    """The tenant's console users (platform users and other tenants' users never match)."""

    name = "console"

    def __init__(
        self, box: SecretBox | None, max_failures: int = 5, lockout_minutes: int = 15
    ) -> None:
        self.box = box
        self.max_failures = max_failures
        self.lockout_minutes = lockout_minutes

    @staticmethod
    def _usable(session: Session, user: User, tenant_id: int) -> bool:
        if user.tenant_id != tenant_id or not user.is_active:
            return False
        tenant = session.get(Tenant, tenant_id)
        return tenant is not None and tenant.is_active

    def authenticate(
        self,
        session: Session,
        tenant_id: int,
        username: str,
        password: str,
        totp_code: str | None,
    ) -> AuthOutcome:
        user = session.scalar(
            select(User).where(User.username == username, User.tenant_id == tenant_id)
        )
        if user is None:
            verify_password(_dummy_hash(), password)
            return AuthOutcome(None, "invalid_credentials")
        password_ok = verify_password(user.password_hash, password)
        if auth.is_locked(user):
            return AuthOutcome(None, "locked" if password_ok else "invalid_credentials")
        if not password_ok:
            auth.record_failure(user, self.max_failures, self.lockout_minutes)
            return AuthOutcome(None, "invalid_credentials")
        if not self._usable(session, user, tenant_id):
            return AuthOutcome(None, "invalid_credentials")
        if user.mfa_enabled:
            if not totp_code:
                return AuthOutcome(None, "mfa_required")
            step = self._totp_step(user, totp_code)
            if step is None:
                auth.record_failure(user, self.max_failures, self.lockout_minutes)
                return AuthOutcome(None, "invalid_mfa_code")
            user.mfa_last_step = step
        auth.record_success(user)
        return AuthOutcome(RegistryUser(user.id, user.username, user.email), "ok")

    def _totp_step(self, user: User, code: str) -> int | None:
        if not user.mfa_secret_enc or self.box is None:
            return None
        try:
            secret = self.box.decrypt_str(user.mfa_secret_enc, f"user:{user.id}:mfa")
        except CryptoError:
            return None
        return auth.verify_totp(secret, code, user.mfa_last_step)

    def lookup(self, session: Session, tenant_id: int, user_id: int) -> RegistryUser | None:
        user = session.get(User, user_id)
        if user is None or not self._usable(session, user, tenant_id):
            return None
        return RegistryUser(user.id, user.username, user.email)
