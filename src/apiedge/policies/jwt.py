# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""JWT validation for the ``jwt`` policy (T-008, ADR 0009).

Verification is done here rather than with a general-purpose JWT library so that the rules are
explicit and the RSA/ECDSA primitives come from pycryptodome (already a runtime dependency):

* the header's ``alg`` must be in the policy's allow-list (``none`` never is); HS* and
  asymmetric algorithms cannot be mixed in one policy (algorithm confusion);
* tokens with a ``crit`` header are refused (no extensions are supported);
* RSA keys must be at least 2048 bits; ECDSA keys must be on the curve the algorithm names;
* JWKS ``oct`` (symmetric) keys are ignored; a key's ``alg``/``use`` must fit when present;
* ``exp`` (required unless switched off), ``nbf``, ``iss`` and ``aud`` are checked with a
  bounded clock leeway.

JWKS documents are fetched through the gateway's SSRF-guarded HTTP client, size-limited, cached
per URL and refreshed at most every :data:`MIN_REFRESH_SECONDS` when an unknown ``kid`` shows up.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx

# pycryptodome (maintained) reuses the legacy `Crypto` namespace; B413 targets abandoned pyCrypto.
from Crypto.Hash import SHA256, SHA384, SHA512  # nosec B413
from Crypto.PublicKey import ECC, RSA  # nosec B413
from Crypto.Signature import DSS, pkcs1_15, pss  # nosec B413

log = logging.getLogger("apiedge.gateway.policies")

MAX_TOKEN_BYTES = 8192
MAX_JWKS_BYTES = 64 * 1024
MIN_REFRESH_SECONDS = 30
JWKS_TIMEOUT_SECONDS = 5.0
MIN_RSA_BITS = 2048

_HASHES: dict[str, Any] = {"256": SHA256, "384": SHA384, "512": SHA512}
_HMAC: dict[str, Callable[[], Any]] = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}
_CURVES = {"ES256": ("NIST P-256", 32), "ES384": ("NIST P-384", 48), "ES512": ("NIST P-521", 66)}
_JWK_CURVES = {"P-256": "NIST P-256", "P-384": "NIST P-384", "P-521": "NIST P-521"}


class JwtError(Exception):
    """The token is not acceptable. ``str(exc)`` is a short reason for the trace (no token)."""


class KeysUnavailableError(Exception):
    """No verification keys could be obtained (JWKS unreachable or invalid)."""


def b64url_decode(part: str) -> bytes:
    if not part or len(part) % 4 == 1 or any(c in part for c in "+/="):
        raise JwtError("malformed token")
    try:
        return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    except (binascii.Error, ValueError) as exc:
        raise JwtError("malformed token") from exc


def _b64int(value: object) -> int:
    if not isinstance(value, str):
        raise ValueError("not a base64url string")
    return int.from_bytes(b64url_decode(value), "big")


@dataclass(frozen=True)
class VerifyKey:
    kty: str  # "RSA" or "EC"
    key: Any  # pycryptodome public key
    kid: str | None = None
    alg: str | None = None

    def fits(self, alg: str) -> bool:
        if self.alg is not None and self.alg != alg:
            return False
        if alg[:2] in ("RS", "PS"):
            return self.kty == "RSA"
        return self.kty == "EC" and self.key.curve == _CURVES[alg][0]


def _check_rsa(key: Any) -> Any:
    if key.has_private():
        key = key.public_key()
    if key.size_in_bits() < MIN_RSA_BITS:
        raise ValueError(f"RSA keys must have at least {MIN_RSA_BITS} bits")
    return key


def load_pem_key(pem: str) -> VerifyKey:
    """A public key from PEM (RSA or EC). Raises ``ValueError`` if unusable."""
    text = pem.strip()
    try:
        rsa_key = RSA.import_key(text)
    except (ValueError, IndexError, TypeError):
        rsa_key = None
    if rsa_key is not None:
        return VerifyKey("RSA", _check_rsa(rsa_key))
    try:
        key = ECC.import_key(text)
    except (ValueError, IndexError, TypeError) as exc:
        raise ValueError("not an RSA or EC public key in PEM format") from exc
    if key.curve not in _JWK_CURVES.values():
        raise ValueError("unsupported EC curve")
    return VerifyKey("EC", key.public_key() if key.has_private() else key)


def parse_jwks(document: object) -> list[VerifyKey]:
    """The usable signature keys of a JWKS document (others are skipped)."""
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise ValueError("not a JWKS document")
    keys: list[VerifyKey] = []
    for jwk in document["keys"][:100]:
        if not isinstance(jwk, dict) or jwk.get("use", "sig") != "sig":
            continue
        kid = jwk.get("kid") if isinstance(jwk.get("kid"), str) else None
        alg = jwk.get("alg") if isinstance(jwk.get("alg"), str) else None
        try:
            if jwk.get("kty") == "RSA":
                key = _check_rsa(RSA.construct((_b64int(jwk.get("n")), _b64int(jwk.get("e")))))
                keys.append(VerifyKey("RSA", key, kid, alg))
            elif jwk.get("kty") == "EC" and jwk.get("crv") in _JWK_CURVES:
                ec = ECC.construct(
                    curve=_JWK_CURVES[jwk["crv"]],
                    point_x=_b64int(jwk.get("x")),
                    point_y=_b64int(jwk.get("y")),
                )
                keys.append(VerifyKey("EC", ec, kid, alg))
            # "oct" and unknown key types are never used.
        except (ValueError, TypeError, JwtError):
            log.warning("skipping an invalid key in a JWKS document")
    return keys


def _verify_signature(alg: str, signing_input: bytes, sig: bytes, key: VerifyKey) -> bool:
    digest = _HASHES[alg[2:]].new(signing_input)
    try:
        if alg.startswith("RS"):
            pkcs1_15.new(key.key).verify(digest, sig)
        elif alg.startswith("PS"):
            pss.new(key.key).verify(digest, sig)
        else:
            if len(sig) != 2 * _CURVES[alg][1]:
                return False
            DSS.new(key.key, "fips-186-3").verify(digest, sig)
    except (ValueError, TypeError):
        return False
    return True


@dataclass(frozen=True)
class Token:
    header: dict[str, Any]
    claims: dict[str, Any]
    signing_input: bytes
    signature: bytes

    @property
    def alg(self) -> str:
        return str(self.header.get("alg", ""))

    @property
    def kid(self) -> str | None:
        kid = self.header.get("kid")
        return kid if isinstance(kid, str) else None


def parse_token(token: str, algorithms: frozenset[str]) -> Token:
    if len(token) > MAX_TOKEN_BYTES:
        raise JwtError("token too large")
    parts = token.split(".")
    if len(parts) != 3:
        raise JwtError("malformed token")
    try:
        header = json.loads(b64url_decode(parts[0]))
        claims = json.loads(b64url_decode(parts[1]))
    except (ValueError, UnicodeDecodeError) as exc:
        raise JwtError("malformed token") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise JwtError("malformed token")
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in algorithms:
        raise JwtError("algorithm not allowed")
    if "crit" in header:
        raise JwtError("unsupported critical header")
    signature = b64url_decode(parts[2])
    return Token(header, claims, f"{parts[0]}.{parts[1]}".encode("ascii"), signature)


def _number(claims: Mapping[str, Any], name: str) -> float | None:
    value = claims.get(name)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise JwtError(f"invalid {name} claim")
    return float(value)


def check_claims(
    claims: Mapping[str, Any],
    *,
    issuer: str | None,
    audiences: frozenset[str],
    require_exp: bool,
    leeway: int,
    now: float | None = None,
) -> None:
    now = time.time() if now is None else now
    exp = _number(claims, "exp")
    if exp is None and require_exp:
        raise JwtError("missing exp claim")
    if exp is not None and now > exp + leeway:
        raise JwtError("token expired")
    nbf = _number(claims, "nbf")
    if nbf is not None and now + leeway < nbf:
        raise JwtError("token not yet valid")
    if issuer is not None and claims.get("iss") != issuer:
        raise JwtError("issuer mismatch")
    if audiences:
        aud = claims.get("aud")
        values = [aud] if isinstance(aud, str) else aud if isinstance(aud, list) else []
        if not any(isinstance(a, str) and a in audiences for a in values):
            raise JwtError("audience mismatch")


@dataclass
class _JwksEntry:
    keys: list[VerifyKey] = field(default_factory=list)
    fetched_at: float = 0.0
    attempted_at: float = 0.0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class JwksCache:
    """Per-URL JWKS cache shared by every ``jwt`` policy of the gateway (survives reloads)."""

    def __init__(self, client_getter: Callable[[], httpx.AsyncClient | None]) -> None:
        self._client_getter = client_getter
        self._entries: dict[str, _JwksEntry] = {}

    async def _fetch(self, url: str) -> list[VerifyKey]:
        client = self._client_getter()
        if client is None:
            raise KeysUnavailableError("no HTTP client")
        request = client.build_request(
            "GET",
            url,
            headers={"accept": "application/json"},
            extensions={"timeout": httpx.Timeout(JWKS_TIMEOUT_SECONDS).as_dict()},
        )
        response = await client.send(request, stream=True)
        try:
            if response.status_code != 200:
                raise KeysUnavailableError(f"JWKS answered {response.status_code}")
            data = bytearray()
            async for chunk in response.aiter_bytes():
                data += chunk
                if len(data) > MAX_JWKS_BYTES:
                    raise KeysUnavailableError("JWKS document too large")
        finally:
            await response.aclose()
        try:
            return parse_jwks(json.loads(bytes(data)))
        except (ValueError, UnicodeDecodeError) as exc:
            raise KeysUnavailableError("invalid JWKS document") from exc

    async def keys(self, url: str, ttl: int, *, refresh: bool = False) -> list[VerifyKey]:
        entry = self._entries.setdefault(url, _JwksEntry())
        now = time.monotonic()
        fresh = entry.fetched_at and now - entry.fetched_at < ttl
        if fresh and not refresh:
            return entry.keys
        if entry.attempted_at and now - entry.attempted_at < MIN_REFRESH_SECONDS:
            if entry.fetched_at:
                return entry.keys  # throttled: keep what we have
            raise KeysUnavailableError("JWKS fetch failed recently")
        async with entry.lock:
            if entry.attempted_at > now:  # another request refreshed while we waited
                return entry.keys
            entry.attempted_at = time.monotonic()
            try:
                entry.keys = await self._fetch(url)
                entry.fetched_at = time.monotonic()
            except (httpx.HTTPError, KeysUnavailableError) as exc:
                log.warning("JWKS fetch failed: %s", type(exc).__name__)
                if not entry.fetched_at:
                    raise KeysUnavailableError("JWKS unavailable") from exc
            return entry.keys


class JwtVerifier:
    """Verifies tokens for one ``jwt`` policy."""

    def __init__(
        self,
        *,
        algorithms: frozenset[str],
        secret: bytes | None,
        public_key: VerifyKey | None,
        jwks_url: str | None,
        jwks_ttl: int,
        jwks: JwksCache | None,
        issuer: str | None,
        audiences: frozenset[str],
        require_exp: bool,
        leeway: int,
    ) -> None:
        self.algorithms = algorithms
        self.secret = secret
        self.public_key = public_key
        self.jwks_url = jwks_url
        self.jwks_ttl = jwks_ttl
        self.jwks = jwks
        self.issuer = issuer
        self.audiences = audiences
        self.require_exp = require_exp
        self.leeway = leeway

    def _pick(self, keys: list[VerifyKey], token: Token) -> VerifyKey | None:
        usable = [k for k in keys if k.fits(token.alg)]
        if token.kid is not None:
            usable = [k for k in usable if k.kid == token.kid]
        elif len(usable) != 1:
            return None  # without a kid only an unambiguous key is used
        return usable[0] if usable else None

    async def _asym_key(self, token: Token) -> VerifyKey:
        if self.public_key is not None:
            if not self.public_key.fits(token.alg):
                raise JwtError("key does not fit the algorithm")
            return self.public_key
        if self.jwks is None or self.jwks_url is None:
            raise KeysUnavailableError("no key configured")
        key = self._pick(await self.jwks.keys(self.jwks_url, self.jwks_ttl), token)
        if key is None:  # perhaps the issuer rotated its keys
            key = self._pick(
                await self.jwks.keys(self.jwks_url, self.jwks_ttl, refresh=True), token
            )
        if key is None:
            raise JwtError("no matching key")
        return key

    async def verify(self, raw: str, now: float | None = None) -> dict[str, Any]:
        token = parse_token(raw, self.algorithms)
        if token.alg in _HMAC:
            if not self.secret:
                raise KeysUnavailableError("no secret configured")
            expected = hmac.new(self.secret, token.signing_input, _HMAC[token.alg]).digest()
            if not hmac.compare_digest(expected, token.signature):
                raise JwtError("invalid signature")
        else:
            key = await self._asym_key(token)
            if not _verify_signature(token.alg, token.signing_input, token.signature, key):
                raise JwtError("invalid signature")
        check_claims(
            token.claims,
            issuer=self.issuer,
            audiences=self.audiences,
            require_exp=self.require_exp,
            leeway=self.leeway,
            now=now,
        )
        return token.claims
