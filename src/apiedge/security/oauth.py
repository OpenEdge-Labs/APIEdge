# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Building blocks of the built-in OAuth 2.0 / OpenID Connect server (T-023, ADR 0015).

* Per-tenant RSA signing keys (RS256): generated here, stored encrypted with the secrets box
  (bound to tenant and key id) and published as a JWKS.
* JWT signing for access tokens (``typ: at+jwt``, RFC 9068) and OIDC ID tokens.
* Client secrets, authorization codes and refresh tokens are random, shown once and stored
  only as SHA-256 hashes (they carry 256 bits of entropy, so a slow hash adds nothing).
* PKCE (RFC 7636): only the ``S256`` method is accepted.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

# pycryptodome (maintained) reuses the legacy `Crypto` namespace; B413 targets abandoned pyCrypto.
from Crypto.Hash import SHA256  # nosec B413
from Crypto.PublicKey import RSA  # nosec B413
from Crypto.Signature import pkcs1_15  # nosec B413

RSA_BITS = 2048
SIGNING_ALG = "RS256"
CLIENT_ID_PREFIX = "cl_"
CLIENT_SECRET_PREFIX = "cs_"  # noqa: S105  # nosec B105 - a prefix, not a secret
CODE_PREFIX = "ac_"
REFRESH_PREFIX = "rt_"

# Scopes with a meaning in OpenID Connect; any other scope is the tenant's own.
OIDC_SCOPES = frozenset({"openid", "profile", "email"})
GRANT_TYPES = ("client_credentials", "authorization_code", "refresh_token")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_b64(value: int) -> str:
    return b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def token_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def new_client_id() -> str:
    return CLIENT_ID_PREFIX + secrets.token_urlsafe(18)


def new_secret(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


def secret_matches(raw: str, stored_hash: str | None) -> bool:
    if not stored_hash:
        return False
    return hmac.compare_digest(token_hash(raw), stored_hash)


def signing_key_aad(tenant_id: int, kid: str) -> str:
    return f"tenant:{tenant_id}:oauth-key:{kid}"


def issuer_url(public_url: str, tenant_slug: str) -> str:
    return f"{public_url.rstrip('/')}/{tenant_slug}/oauth2"


# --------------------------------------------------------------------------- keys


@dataclass(frozen=True)
class GeneratedKey:
    kid: str
    private_pem: str
    public_jwk: dict[str, str]


def public_jwk(key: Any, kid: str) -> dict[str, str]:
    pub = key.public_key() if key.has_private() else key
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": SIGNING_ALG,
        "kid": kid,
        "n": _int_b64(pub.n),
        "e": _int_b64(pub.e),
    }


def generate_signing_key() -> GeneratedKey:
    key = RSA.generate(RSA_BITS)
    kid = uuid.uuid4().hex
    pem = key.export_key(format="PEM", pkcs=8).decode("ascii")
    return GeneratedKey(kid, pem, public_jwk(key, kid))


@dataclass(frozen=True)
class SigningKey:
    """An active private key, ready to sign."""

    kid: str
    key: Any  # pycryptodome RSA private key

    @classmethod
    def from_pem(cls, kid: str, pem: str) -> SigningKey:
        return cls(kid, RSA.import_key(pem))


def sign_jwt(claims: Mapping[str, Any], key: SigningKey, typ: str = "JWT") -> str:
    header = {"alg": SIGNING_ALG, "typ": typ, "kid": key.kid}
    signing_input = (
        b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64url(json.dumps(dict(claims), separators=(",", ":")).encode())
    )
    signature = pkcs1_15.new(key.key).sign(SHA256.new(signing_input.encode("ascii")))
    return signing_input + "." + b64url(signature)


def access_token_claims(
    *,
    issuer: str,
    subject: str,
    client_id: str,
    scope: str,
    ttl: int,
    audience: Iterable[str] = (),
    extra: Mapping[str, Any] | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    iat = int(time.time()) if now is None else now
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": subject,
        "client_id": client_id,
        "iat": iat,
        "nbf": iat,
        "exp": iat + ttl,
        "jti": uuid.uuid4().hex,
    }
    aud = list(audience)
    if aud:
        claims["aud"] = aud[0] if len(aud) == 1 else aud
    if scope:
        claims["scope"] = scope
    if extra:
        claims.update(extra)
    return claims


# --------------------------------------------------------------------------- scopes / PKCE


def parse_scope(text: str | None) -> list[str] | None:
    """Scope tokens in order (duplicates removed), or None if malformed."""
    if text is None:
        return []
    tokens = text.split(" ")
    if any(not t for t in tokens) and text != "":
        return None
    out: list[str] = []
    for t in tokens:
        if not t:
            continue
        if len(t) > 100 or any(ord(c) < 0x21 or ord(c) > 0x7E or c in '"\\' for c in t):
            return None
        if t not in out:
            out.append(t)
    return out


def grant_scope(requested: list[str], allowed: Iterable[str]) -> list[str] | None:
    """The scopes to grant: the request if allowed (None if not); no request: all allowed."""
    allowed_list = list(allowed)
    if not requested:
        return [s for s in allowed_list if s not in OIDC_SCOPES]
    if not set(requested) <= set(allowed_list):
        return None
    return requested


def pkce_matches(verifier: str, challenge: str) -> bool:
    if not (43 <= len(verifier) <= 128) or not all(
        c.isascii() and (c.isalnum() or c in "-._~") for c in verifier
    ):
        return False
    computed = b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return hmac.compare_digest(computed, challenge)


def valid_challenge(challenge: str) -> bool:
    return len(challenge) == 43 and all(c.isalnum() or c in "-_" for c in challenge)
