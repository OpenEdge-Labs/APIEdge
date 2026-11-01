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

POLICY_MIN_LENGTH = 12
POLICY_MAX_LENGTH = 128  # bounds hashing cost (ASVS 2.1.2 allows >= 64)
POLICY_TEXT = (
    f"password must be {POLICY_MIN_LENGTH}-{POLICY_MAX_LENGTH} characters, must not start or "
    "end with whitespace, must not contain the username and must not be a common password"
)

# Small built-in deny list of the most common passwords of policy length (ASVS 2.1.7).
_COMMON = frozenset(
    {
        "123456789012", "1234567890123", "12345678910111", "password1234", "password12345",
        "password123!", "passw0rd1234", "qwertyuiop12", "qwerty123456", "qwertyuiopas",
        "administrator", "admin1234567", "adminadmin12", "letmein12345", "welcome12345",
        "iloveyou1234", "changeme1234", "abcdefghijkl", "abc123abc123", "111111111111",
        "000000000000", "aaaaaaaaaaaa", "trustno1trustno1", "football1234", "baseball1234",
        "superman1234", "monkey123456", "dragon123456", "sunshine1234", "princess1234",
        "p@ssw0rd1234", "p@ssword1234", "1q2w3e4r5t6y", "1qaz2wsx3edc", "zaq12wsxcde3",
    }
)  # fmt: skip


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def generate_password(length: int = 20) -> str:
    """Random password with at least one lower, upper, digit and symbol."""
    if length < POLICY_MIN_LENGTH:
        raise ValueError(f"length must be >= {POLICY_MIN_LENGTH}")
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


def password_problems(password: str, username: str | None = None) -> list[str]:
    """Password policy (ASVS 2.1): length 12-128, no composition rules, no common passwords.

    Returns human-readable problems; never includes the password itself.
    """
    problems = []
    if len(password) < POLICY_MIN_LENGTH:
        problems.append(f"must be at least {POLICY_MIN_LENGTH} characters")
    if len(password) > POLICY_MAX_LENGTH:
        problems.append(f"must be at most {POLICY_MAX_LENGTH} characters")
    if password.strip() != password:
        problems.append("must not start or end with whitespace")
    lowered = password.lower()
    if username and len(username) >= 3 and username.lower() in lowered:
        problems.append("must not contain the username")
    if lowered in _COMMON or len(set(password)) < 4:
        problems.append("is too common or too simple")
    return problems
