# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Secrets encryption at rest (T-002, OWASP A02, ADR 0003).

Secrets such as upstream credentials, client secrets and private keys are stored as
**AES-256-GCM** tokens::

    v1.<key id>.<base64url(nonce || ciphertext || tag)>

* ``key id`` is the first 8 hex chars of SHA-256(key), so tokens survive key rotation: the primary
  key encrypts, the primary *and* the previous keys decrypt (``needs_rotation`` flags old tokens).
* An optional **associated data** string (for example ``"tenant:42/upstream:7/password"``) binds a
  token to its row and field, so a ciphertext copied to another row or tenant does not decrypt.
* The master key comes from ``APIEDGE_SECRET_KEY`` or the key file ``<data dir>/secret.key``
  (created by ``apiedge init`` with owner-only permissions). It is never stored in the database.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import logging
import os
import secrets
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

# pycryptodome (maintained) reuses the legacy `Crypto` namespace; B413 targets abandoned pyCrypto.
from Crypto.Cipher import AES  # nosec B413

if TYPE_CHECKING:
    from apiedge.config import Settings

log = logging.getLogger("apiedge")

TOKEN_VERSION = "v1"  # noqa: S105  # nosec B105 - format tag, not a secret
KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
KEY_FILE_NAME = "secret.key"


class CryptoError(Exception):
    """Base class; messages never contain key material or plaintext."""


class KeyConfigError(CryptoError):
    """The master key is missing or malformed."""


class DecryptionError(CryptoError):
    """Token is malformed, was tampered with, or was encrypted with an unknown key."""


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def generate_key() -> str:
    """A new random 256-bit master key, base64url encoded (store it like a password)."""
    return _b64e(secrets.token_bytes(KEY_BYTES))


def parse_key(text: str) -> bytes:
    try:
        raw = _b64d(text.strip())
    except (binascii.Error, ValueError) as exc:
        raise KeyConfigError("secret key is not valid base64url") from exc
    if len(raw) != KEY_BYTES:
        raise KeyConfigError(f"secret key must decode to {KEY_BYTES} bytes")
    return raw


def key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:8]


class SecretBox:
    """Encrypt/decrypt secrets with a primary key and optional previous keys (rotation)."""

    def __init__(self, keys: Sequence[bytes]) -> None:
        if not keys:
            raise KeyConfigError("at least one secret key is required")
        for k in keys:
            if len(k) != KEY_BYTES:
                raise KeyConfigError(f"secret keys must be {KEY_BYTES} bytes")
        self._primary_id = key_id(keys[0])
        self._keys = {key_id(k): bytes(k) for k in reversed(keys)}  # primary wins on collision
        self._keys[self._primary_id] = bytes(keys[0])

    @property
    def primary_key_id(self) -> str:
        return self._primary_id

    def derive_key(self, purpose: str) -> bytes:
        """A 32-byte subkey of the primary key for ``purpose`` (HMAC-SHA256 key separation)."""
        return hmac.new(
            self._keys[self._primary_id], b"apiedge-subkey:" + purpose.encode("utf-8"), "sha256"
        ).digest()

    def encrypt(self, plaintext: str | bytes, aad: str = "") -> str:
        data = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext
        nonce = secrets.token_bytes(NONCE_BYTES)
        cipher = AES.new(self._keys[self._primary_id], AES.MODE_GCM, nonce=nonce, mac_len=TAG_BYTES)
        cipher.update(aad.encode("utf-8"))
        ct, tag = cipher.encrypt_and_digest(data)
        return f"{TOKEN_VERSION}.{self._primary_id}.{_b64e(nonce + ct + tag)}"

    def decrypt(self, token: str, aad: str = "") -> bytes:
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != TOKEN_VERSION:
            raise DecryptionError("unsupported or malformed secret token")
        key = self._keys.get(parts[1])
        if key is None:
            raise DecryptionError("secret token was encrypted with an unknown key")
        try:
            blob = _b64d(parts[2])
        except (binascii.Error, ValueError) as exc:
            raise DecryptionError("malformed secret token") from exc
        if len(blob) < NONCE_BYTES + TAG_BYTES:
            raise DecryptionError("malformed secret token")
        nonce, ct, tag = blob[:NONCE_BYTES], blob[NONCE_BYTES:-TAG_BYTES], blob[-TAG_BYTES:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_BYTES)
        cipher.update(aad.encode("utf-8"))
        try:
            return bytes(cipher.decrypt_and_verify(ct, tag))
        except ValueError as exc:  # MAC check failed
            raise DecryptionError("secret token failed authentication") from exc

    def decrypt_str(self, token: str, aad: str = "") -> str:
        return self.decrypt(token, aad).decode("utf-8")

    def needs_rotation(self, token: str) -> bool:
        """True if ``token`` was not encrypted with the current primary key."""
        parts = token.split(".")
        return len(parts) != 3 or parts[1] != self._primary_id


def ensure_key_file(path: Path) -> bool:
    """Create ``path`` with a new key (owner-only permissions) if missing; True if created."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(generate_key() + "\n")
    return True


def read_key_file(path: Path) -> bytes:
    try:
        text = path.read_text(encoding="ascii")
    except FileNotFoundError as exc:
        raise KeyConfigError(
            f"no secret key: set APIEDGE_SECRET_KEY or run `apiedge init` to create {path}"
        ) from exc
    return parse_key(text)


def build_secret_box(
    primary: str | None, key_file: Path, previous: Sequence[str] = ()
) -> SecretBox:
    """Build the box from config: an explicit key wins over the key file."""
    keys = [parse_key(primary) if primary else read_key_file(key_file)]
    keys.extend(parse_key(p) for p in previous if p.strip())
    return SecretBox(keys)


def load_secret_box(settings: Settings) -> SecretBox | None:
    """The secrets-encryption box, or None (with a warning) if no master key is configured."""
    try:
        return build_secret_box(
            settings.secret_key.get_secret_value() if settings.secret_key else None,
            settings.effective_secret_key_file,
            [k.get_secret_value() for k in settings.secret_key_previous],
        )
    except KeyConfigError as exc:
        log.warning("secrets encryption unavailable: %s", exc)
        return None
