# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Console authentication core (T-003, OWASP A07 / API2).

* Access tokens: short-lived HS256 JWTs (``iss``/``aud``/``typ`` pinned, algorithm pinned).
  They carry ``ver`` = ``users.token_version``; bumping it (password, role, MFA or status
  change) invalidates every access token issued before.
* Refresh tokens: opaque random values, stored as SHA-256 only, rotated on every use. Each login
  starts a family with an absolute lifetime; presenting an already-used token revokes the whole
  family (theft detection).
* Login throttling (per client IP, in-process sliding window) and account lockout.
* TOTP MFA (RFC 6238) with a per-user replay guard; secrets are encrypted at rest.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import pyotp
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from apiedge.db.models import RefreshToken, User, utcnow
from apiedge.security.rbac import Grant, Principal

JWT_ALG = "HS256"
JWT_ISSUER = "apiedge"
JWT_AUDIENCE = "apiedge-admin"
MFA_ISSUER = "APIEdge"


class AuthError(Exception):
    """Authentication failed. ``code`` is safe to return to the client."""

    def __init__(self, code: str = "invalid_credentials") -> None:
        super().__init__(code)
        self.code = code


def _aware(dt: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; treat them as UTC."""
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# --------------------------------------------------------------------------- access tokens


@dataclass(frozen=True)
class AccessClaims:
    user_id: int
    token_version: int
    must_change_password: bool


class TokenSigner:
    def __init__(self, key: bytes, ttl_seconds: int) -> None:
        if len(key) < 32:
            raise ValueError("JWT signing key must be at least 32 bytes")
        self._key = key
        self.ttl_seconds = ttl_seconds

    def issue(self, user: User) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "typ": "access",
            "sub": str(user.id),
            "ver": user.token_version,
            "pwc": bool(user.must_change_password),
            "iat": now,
            "nbf": now,
            "exp": now + self.ttl_seconds,
            "jti": uuid.uuid4().hex,
        }
        return jwt.encode(claims, self._key, algorithm=JWT_ALG)

    def verify(self, token: str) -> AccessClaims:
        try:
            claims = jwt.decode(
                token,
                self._key,
                algorithms=[JWT_ALG],
                audience=JWT_AUDIENCE,
                issuer=JWT_ISSUER,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
                leeway=5,
            )
            if claims.get("typ") != "access":
                raise AuthError("invalid_token")
            return AccessClaims(
                user_id=int(claims["sub"]),
                token_version=int(claims["ver"]),
                must_change_password=bool(claims.get("pwc", False)),
            )
        except (jwt.PyJWTError, KeyError, TypeError, ValueError) as exc:
            raise AuthError("invalid_token") from exc


# --------------------------------------------------------------------------- refresh tokens


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def issue_refresh(
    session: Session, user: User, *, family_id: str | None = None, expires_at: datetime
) -> str:
    raw = secrets.token_urlsafe(32)
    session.add(
        RefreshToken(
            user_id=user.id,
            token_hash=_hash_token(raw),
            family_id=family_id or uuid.uuid4().hex,
            expires_at=expires_at,
        )
    )
    return raw


def rotate_refresh(session: Session, raw: str) -> tuple[User, str]:
    """Consume ``raw`` and return its user and a new token of the same family."""
    row = session.scalar(select(RefreshToken).where(RefreshToken.token_hash == _hash_token(raw)))
    if row is None:
        raise AuthError("invalid_token")
    now = utcnow()
    if row.used_at is not None or row.revoked_at is not None:
        # Reuse of a rotated token: assume theft and end the whole session family.
        revoke_family(session, row.family_id)
        raise AuthError("token_reused")
    expires_at = _aware(row.expires_at)
    if expires_at is None or expires_at <= now:
        raise AuthError("invalid_token")
    user = session.get(User, row.user_id)
    if user is None or not user.is_active:
        raise AuthError("invalid_token")
    # Conditional update: of two concurrent uses only one can win; the loser counts as reuse.
    claimed = session.execute(
        update(RefreshToken)
        .where(RefreshToken.id == row.id, RefreshToken.used_at.is_(None))
        .values(used_at=now)
        .execution_options(synchronize_session=False)
    )
    if getattr(claimed, "rowcount", 0) != 1:
        revoke_family(session, row.family_id)
        raise AuthError("token_reused")
    return user, issue_refresh(session, user, family_id=row.family_id, expires_at=expires_at)


def revoke_family(session: Session, family_id: str) -> None:
    session.execute(
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )


def revoke_refresh(session: Session, raw: str) -> None:
    row = session.scalar(select(RefreshToken).where(RefreshToken.token_hash == _hash_token(raw)))
    if row is not None:
        revoke_family(session, row.family_id)


def invalidate_sessions(session: Session, user: User) -> None:
    """End every session of ``user``: old access tokens fail, refresh tokens are revoked."""
    user.token_version += 1
    session.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )


# --------------------------------------------------------------------------- throttling


class LoginThrottle:
    """Sliding-window limit of login attempts per client key (in-process)."""

    def __init__(self, limit: int, window_seconds: float = 60.0) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str) -> bool:
        """Record an attempt; False if the client is over the limit."""
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > 10_000:  # bound memory under address-spraying
                self._hits = {
                    k: v for k, v in self._hits.items() if v and v[-1] > now - self.window
                }
            q = self._hits.setdefault(key, deque())
            while q and q[0] <= now - self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True


def is_locked(user: User) -> bool:
    locked = _aware(user.locked_until)
    return locked is not None and locked > utcnow()


def record_failure(user: User, max_failures: int, lockout_minutes: int) -> bool:
    """Count a failed login; returns True if this failure locked the account."""
    user.failed_login_count += 1
    if user.failed_login_count >= max_failures:
        user.locked_until = utcnow() + timedelta(minutes=lockout_minutes)
        user.failed_login_count = 0
        return True
    return False


def record_success(user: User) -> None:
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = utcnow()


# --------------------------------------------------------------------------- TOTP


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=MFA_ISSUER)


def verify_totp(secret: str, code: str, last_step: int | None) -> int | None:
    """The matched time step if ``code`` is valid (+-1 step) and newer than ``last_step``."""
    code = code.strip()
    if not (code.isdigit() and len(code) == 6):
        return None
    totp = pyotp.TOTP(secret)
    now_step = int(time.time()) // totp.interval
    for step in (now_step - 1, now_step, now_step + 1):
        if last_step is not None and step <= last_step:
            continue
        if secrets.compare_digest(totp.generate_otp(step), code):
            return step
    return None


# --------------------------------------------------------------------------- principals


def load_principal(user: User) -> Principal:
    grants = tuple(
        Grant(
            tenant_id=a.tenant_id,
            product_id=a.product_id,
            permissions=frozenset(a.role.permissions),
        )
        for a in user.assignments
        if a.tenant_id == user.tenant_id  # assignments never cross the user's tenant
    )
    return Principal(
        user_id=user.id,
        username=user.username,
        tenant_id=user.tenant_id,
        is_superadmin=user.is_superadmin,
        must_change_password=user.must_change_password,
        grants=grants,
    )
