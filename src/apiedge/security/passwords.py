# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""Argon2id password hashing and generation."""

from __future__ import annotations

import secrets
import string

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

# argon2-cffi defaults follow RFC 9106 (Argon2id, t=3, m=64 MiB, p=4).
_hasher = PasswordHasher()

MIN_PASSWORD_LENGTH = 12


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def generate_password(length: int = 20) -> str:
    """Random password with at least one lower, upper, digit and symbol."""
    if length < MIN_PASSWORD_LENGTH:
        raise ValueError(f"length must be >= {MIN_PASSWORD_LENGTH}")
    alphabet = string.ascii_letters + string.digits + "-_.!@#%"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in pw)
            and any(c.isupper() for c in pw)
            and any(c.isdigit() for c in pw)
            and any(not c.isalnum() for c in pw)
        ):
            return pw


def password_problems(password: str) -> list[str]:
    """Minimal policy for the bootstrap admin; T-003 introduces the full policy."""
    problems = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"must be at least {MIN_PASSWORD_LENGTH} characters")
    if password.strip() != password:
        problems.append("must not start or end with whitespace")
    return problems
