# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from apiedge.security.crypto import (
    DecryptionError,
    KeyConfigError,
    SecretBox,
    build_secret_box,
    ensure_key_file,
    generate_key,
    parse_key,
)


def _box(*keys: str) -> SecretBox:
    return SecretBox([parse_key(k) for k in keys])


def test_roundtrip_and_randomised_nonce() -> None:
    box = _box(generate_key())
    a, b = box.encrypt("s3cr3t"), box.encrypt("s3cr3t")
    assert a != b  # fresh nonce per encryption
    assert "s3cr3t" not in a
    assert a.startswith(f"v1.{box.primary_key_id}.")
    assert box.decrypt_str(a) == box.decrypt_str(b) == "s3cr3t"


def test_aad_binds_token_to_its_context() -> None:
    box = _box(generate_key())
    token = box.encrypt("pw", aad="tenant:1/upstream:7")
    assert box.decrypt_str(token, aad="tenant:1/upstream:7") == "pw"
    with pytest.raises(DecryptionError):
        box.decrypt(token, aad="tenant:2/upstream:7")  # copied to another tenant
    with pytest.raises(DecryptionError):
        box.decrypt(token)


def test_tampering_is_detected() -> None:
    box = _box(generate_key())
    token = box.encrypt("value")
    head, body = token.rsplit(".", 1)
    flipped = body[:-2] + ("A" if body[-2] != "A" else "B") + body[-1]
    with pytest.raises(DecryptionError):
        box.decrypt(f"{head}.{flipped}")
    for bad in ("", "v1.x", "v2.abc.def", "v1.00000000.AAAA", f"{head}.!!!"):
        with pytest.raises(DecryptionError):
            box.decrypt(bad)


def test_wrong_key_cannot_decrypt() -> None:
    token = _box(generate_key()).encrypt("value")
    with pytest.raises(DecryptionError):
        _box(generate_key()).decrypt(token)


def test_rotation_previous_key_still_decrypts() -> None:
    old, new = generate_key(), generate_key()
    old_token = _box(old).encrypt("value")
    rotated = _box(new, old)
    assert rotated.decrypt_str(old_token) == "value"
    assert rotated.needs_rotation(old_token)
    assert not rotated.needs_rotation(rotated.encrypt("value"))


@pytest.mark.parametrize("bad", ["", "not base64 !!", generate_key()[:-4]])
def test_bad_keys_rejected(bad: str) -> None:
    with pytest.raises(KeyConfigError):
        parse_key(bad)
    with pytest.raises(KeyConfigError):
        SecretBox([])


def test_key_file_created_once_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "sub" / "secret.key"
    assert ensure_key_file(path) is True
    first = path.read_text()
    assert ensure_key_file(path) is False  # never overwritten
    assert path.read_text() == first
    if sys.platform != "win32":
        assert (path.stat().st_mode & 0o777) == 0o600
    box = build_secret_box(None, path)
    assert box.decrypt_str(box.encrypt("x")) == "x"


def test_explicit_key_wins_and_missing_file_errors(tmp_path: Path) -> None:
    key = generate_key()
    box = build_secret_box(key, tmp_path / "missing.key")
    assert box.primary_key_id == _box(key).primary_key_id
    with pytest.raises(KeyConfigError, match="apiedge init"):
        build_secret_box(None, tmp_path / "missing.key")
