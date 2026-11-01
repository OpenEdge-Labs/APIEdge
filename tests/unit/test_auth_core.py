# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import time
from datetime import timedelta

import jwt
import pyotp
import pytest

from apiedge.db.models import User, utcnow
from apiedge.security import auth
from apiedge.security.crypto import SecretBox
from apiedge.security.passwords import password_problems

KEY = b"k" * 32


def _user(**kw: object) -> User:
    u = User(id=7, username="alice", password_hash="x", token_version=3, must_change_password=False)
    for k, v in kw.items():
        setattr(u, k, v)
    return u


def test_access_token_roundtrip() -> None:
    signer = auth.TokenSigner(KEY, 60)
    claims = signer.verify(signer.issue(_user()))
    assert (claims.user_id, claims.token_version, claims.must_change_password) == (7, 3, False)


def test_short_key_rejected() -> None:
    with pytest.raises(ValueError):
        auth.TokenSigner(b"short", 60)


@pytest.mark.parametrize(
    "mutate",
    [
        {"aud": "other"},
        {"iss": "other"},
        {"typ": "refresh"},
        {"exp": int(time.time()) - 60},
    ],
)
def test_access_token_claims_enforced(mutate: dict[str, object]) -> None:
    now = int(time.time())
    claims = {
        "iss": auth.JWT_ISSUER,
        "aud": auth.JWT_AUDIENCE,
        "typ": "access",
        "sub": "7",
        "ver": 0,
        "iat": now,
        "exp": now + 60,
        **mutate,
    }
    token = jwt.encode(claims, KEY, algorithm="HS256")
    with pytest.raises(auth.AuthError):
        auth.TokenSigner(KEY, 60).verify(token)


def test_other_key_and_algorithm_rejected() -> None:
    token = auth.TokenSigner(b"o" * 32, 60).issue(_user())
    with pytest.raises(auth.AuthError):
        auth.TokenSigner(KEY, 60).verify(token)
    hs512 = jwt.encode({"sub": "7"}, KEY + KEY, algorithm="HS512")
    with pytest.raises(auth.AuthError):
        auth.TokenSigner(KEY, 60).verify(hs512)


def test_throttle_window() -> None:
    t = auth.LoginThrottle(2, window_seconds=0.2)
    assert t.hit("ip") and t.hit("ip") and not t.hit("ip")
    assert t.hit("other")
    time.sleep(0.25)
    assert t.hit("ip")


def test_lockout_counter() -> None:
    u = _user(failed_login_count=0, locked_until=None)
    assert not auth.record_failure(u, 2, 5)
    assert auth.record_failure(u, 2, 5)
    assert auth.is_locked(u)
    auth.record_success(u)
    assert not auth.is_locked(u) and u.failed_login_count == 0


def test_lock_expires() -> None:
    assert not auth.is_locked(_user(locked_until=utcnow() - timedelta(seconds=1)))
    naive = (utcnow() + timedelta(minutes=1)).replace(tzinfo=None)  # as SQLite returns it
    assert auth.is_locked(_user(locked_until=naive))


def test_totp_verify_and_replay_guard() -> None:
    secret = auth.new_totp_secret()
    totp = pyotp.TOTP(secret)
    step = auth.verify_totp(secret, totp.now(), None)
    assert step is not None
    assert auth.verify_totp(secret, totp.now(), step) is None  # replay
    assert auth.verify_totp(secret, "12345", None) is None
    assert auth.verify_totp(secret, "abcdef", None) is None
    assert "issuer=APIEdge" in auth.totp_uri(secret, "alice")


def test_derive_key_is_stable_and_separated() -> None:
    box = SecretBox([b"m" * 32])
    assert box.derive_key("a") == box.derive_key("a") != box.derive_key("b")
    assert len(box.derive_key("a")) == 32


@pytest.mark.parametrize(
    ("pw", "user"),
    [("x" * 129, None), ("alice-and-more-1", "alice"), ("password1234", None), ("ab" * 8, None)],
)
def test_password_policy(pw: str, user: str | None) -> None:
    assert password_problems(pw, user)


def test_password_policy_accepts_passphrase() -> None:
    assert password_problems("correct horse battery staple", "alice") == []
