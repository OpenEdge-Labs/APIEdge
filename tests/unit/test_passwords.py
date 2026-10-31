# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest

from apiedge.security.passwords import (
    generate_password,
    hash_password,
    password_problems,
    verify_password,
)


def test_hash_is_argon2id_and_verifies() -> None:
    h = hash_password("correct horse battery")
    assert h.startswith("$argon2id$")
    assert verify_password(h, "correct horse battery")
    assert not verify_password(h, "wrong password!!")


def test_verify_garbage_hash_is_false() -> None:
    assert not verify_password("not-a-hash", "whatever")


def test_generated_password_meets_policy() -> None:
    pw = generate_password()
    assert len(pw) == 20
    assert password_problems(pw) == []
    assert generate_password() != pw


def test_generate_too_short_rejected() -> None:
    with pytest.raises(ValueError, match="length"):
        generate_password(8)


@pytest.mark.parametrize("pw", ["short", " leadingspace123", ""])
def test_weak_passwords_rejected(pw: str) -> None:
    assert password_problems(pw)
