# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the OAuth server building blocks (T-023): scopes, PKCE, redirect URI rules,
signing and verification with the built-in issuer, and the jwt policy's built-in issuer option.
"""

from __future__ import annotations

import base64
import hashlib
import time

import pytest
from pydantic import ValidationError

from apiedge.admin.oauth import _check_redirect
from apiedge.policies.config import JwtConfig
from apiedge.policies.jwt import IssuerKeys, JwtError, JwtVerifier, parse_jwks
from apiedge.security import oauth

KEY = oauth.generate_signing_key()
SIGNER = oauth.SigningKey.from_pem(KEY.kid, KEY.private_pem)
ISSUER = "https://gw.example.com/acme/oauth2"


def _verifier(issuer: str = ISSUER) -> JwtVerifier:
    source = IssuerKeys(issuer, tuple(parse_jwks({"keys": [KEY.public_jwk]})))
    return JwtVerifier(
        algorithms=frozenset({"RS256"}),
        secret=None,
        public_key=None,
        jwks_url=None,
        jwks_ttl=300,
        jwks=None,
        issuer=None,
        audiences=frozenset(),
        require_exp=True,
        leeway=0,
        issuer_source=lambda: source,
    )


def test_scope_parsing_and_granting() -> None:
    assert oauth.parse_scope(None) == []
    assert oauth.parse_scope("") == []
    assert oauth.parse_scope("a b a") == ["a", "b"]
    for bad in ("a  b", " a", 'a"', "a\\b", "x" * 101, "é"):
        assert oauth.parse_scope(bad) is None, bad
    assert oauth.grant_scope([], ["openid", "orders"]) == ["orders"]
    assert oauth.grant_scope(["orders"], ["orders"]) == ["orders"]
    assert oauth.grant_scope(["admin"], ["orders"]) is None


def test_pkce_s256() -> None:
    verifier = "v" * 43
    challenge = oauth.b64url(hashlib.sha256(verifier.encode()).digest())
    assert oauth.valid_challenge(challenge)
    assert oauth.pkce_matches(verifier, challenge)
    assert not oauth.pkce_matches("w" * 43, challenge)
    assert not oauth.pkce_matches("short", challenge)
    assert not oauth.pkce_matches("v" * 42 + "!", challenge)
    assert not oauth.valid_challenge("x" * 42)


def test_redirect_uri_rules() -> None:
    for ok in (
        "https://app.example.com/cb",
        "https://app.example.com/cb?x=1",
        "http://127.0.0.1:8000/cb",
        "http://localhost/cb",
        "com.example.app:/callback",
    ):
        assert _check_redirect(ok) == ok
    for bad in (
        "http://app.example.com/cb",
        "https://app.example.com/cb#frag",
        "https://user:pw@app.example.com/cb",
        "javascript:alert(1)",
        "myapp:/cb",
        "https:///nohost",
        "https://a.example.com/c b",
    ):
        with pytest.raises(ValueError):
            _check_redirect(bad)


def test_signed_tokens_verify_with_the_builtin_issuer() -> None:
    claims = oauth.access_token_claims(
        issuer=ISSUER, subject="cl_x", client_id="cl_x", scope="a", ttl=60
    )
    token = oauth.sign_jwt(claims, SIGNER, typ="at+jwt")
    header = base64.urlsafe_b64decode(token.split(".")[0] + "==")
    assert b'"typ":"at+jwt"' in header and KEY.kid.encode() in header
    assert _verifier().verify_builtin(token)["sub"] == "cl_x"
    with pytest.raises(JwtError):
        _verifier("https://gw.example.com/other/oauth2").verify_builtin(token)
    expired = oauth.access_token_claims(
        issuer=ISSUER, subject="s", client_id="c", scope="", ttl=60, now=int(time.time()) - 600
    )
    with pytest.raises(JwtError):
        _verifier().verify_builtin(oauth.sign_jwt(expired, SIGNER))
    other = oauth.generate_signing_key()
    forged = oauth.sign_jwt(claims, oauth.SigningKey.from_pem(KEY.kid, other.private_pem))
    with pytest.raises(JwtError):
        _verifier().verify_builtin(forged)
    assert "d" not in KEY.public_jwk and KEY.public_jwk["alg"] == "RS256"


def test_secrets_are_hashed_and_compared() -> None:
    raw = oauth.new_secret(oauth.CLIENT_SECRET_PREFIX)
    assert raw.startswith("cs_") and len(raw) > 40
    assert oauth.secret_matches(raw, oauth.token_hash(raw))
    assert not oauth.secret_matches(raw + "x", oauth.token_hash(raw))
    assert not oauth.secret_matches(raw, None)
    assert oauth.issuer_url("https://gw.example.com/", "acme") == ISSUER


def test_jwt_policy_builtin_issuer_validation() -> None:
    cfg = JwtConfig(algorithms=["RS256"], builtin_issuer=True)
    assert cfg.builtin_issuer
    for bad in (
        {"algorithms": ["HS256"], "builtin_issuer": True},
        {"algorithms": ["RS256", "ES256"], "builtin_issuer": True},
        {"algorithms": ["RS256"], "builtin_issuer": True, "issuer": "x"},
        {"algorithms": ["RS256"], "builtin_issuer": True, "jwks_url": "https://x/jwks"},
    ):
        with pytest.raises(ValidationError):
            JwtConfig.model_validate(bad)
