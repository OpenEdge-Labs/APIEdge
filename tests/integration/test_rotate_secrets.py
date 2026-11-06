# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""`apiedge rotate-secrets` (T-034): every stored secret moves to the current key."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from apiedge.cli import main
from apiedge.db.base import make_engine, make_session_factory, run_migrations
from apiedge.db.models import (
    Api,
    CapturedExchange,
    CaptureSession,
    Keystore,
    OAuthSigningKey,
    Product,
    Tenant,
    User,
)
from apiedge.inspector.store import exchange_aad
from apiedge.policies.builtin import secret_aad
from apiedge.security.crypto import SecretBox, generate_key, parse_key
from apiedge.security.oauth import signing_key_aad
from apiedge.security.rotation import rotate_secrets
from apiedge.security.tls import keystore_aad

OLD, NEW, STRANGER = generate_key(), generate_key(), generate_key()


def _db(data_dir: Path) -> str:
    return f"sqlite:///{(data_dir.resolve() / 'apiedge.db').as_posix()}"


def _seed(url: str, box: SecretBox) -> dict[str, int]:
    """One row of every encrypted kind, all encrypted with ``box``'s primary key."""
    run_migrations(url)
    engine = make_engine(url)
    now = datetime.now(UTC)
    with make_session_factory(engine)() as s:
        t = Tenant(slug="acme", name="Acme")
        s.add(t)
        s.flush()
        u = User(tenant_id=t.id, username="alice", password_hash="x")
        s.add(u)
        p = Product(tenant_id=t.id, name="P")
        s.add(p)
        s.flush()
        u.mfa_secret_enc = box.encrypt("JBSWY3DPEHPK3PXP", f"user:{u.id}:mfa")
        a = Api(tenant_id=t.id, product_id=p.id, name="A", version="1", base_path="/a")
        s.add(a)
        s.flush()
        jwt_secret = box.encrypt("s1", secret_aad(a.id, "p1", "secret"))
        a.policies = json.dumps(
            [
                {"id": "p1", "type": "jwt", "config": {"secret": jwt_secret}},
                {"id": "p2", "type": "rate-limit", "config": {"limit": 5}},
            ]
        )
        cs = CaptureSession(
            tenant_id=t.id,
            product_id=p.id,
            api_id=a.id,
            max_exchanges=10,
            max_body_bytes=100,
            expires_at=now + timedelta(hours=1),
        )
        ks = Keystore(
            tenant_id=t.id,
            name="k",
            certificate_chain="-",
            private_key="",
            key_type="rsa",
            fingerprint_sha256="0" * 64,
            not_after=now,
        )
        sk = OAuthSigningKey(tenant_id=t.id, kid="kid1", private_key="", public_jwk="{}")
        s.add_all([cs, ks, sk])
        s.flush()
        ks.private_key = box.encrypt("PEM-KS", keystore_aad(t.id, ks.id))
        sk.private_key = box.encrypt("PEM-SK", signing_key_aad(t.id, "kid1"))
        ex = CapturedExchange(
            tenant_id=t.id,
            session_id=cs.id,
            product_id=p.id,
            api_id=a.id,
            request_id="r",
            started_at=now,
            method="GET",
            path="/",
            status=200,
            duration_ms=1.0,
            size=1,
            data=box.encrypt('{"k":1}', exchange_aad(t.id, cs.id)),
        )
        s.add(ex)
        s.commit()
        ids = {"tenant": t.id, "user": u.id, "api": a.id, "session": cs.id, "ks": ks.id}
    engine.dispose()
    return ids


def _tokens(url: str) -> list[str]:
    engine = make_engine(url)
    with make_session_factory(engine)() as s:
        out = [s.scalars(select(User.mfa_secret_enc)).one() or ""]
        out.append(json.loads(s.scalars(select(Api.policies)).one())[0]["config"]["secret"])
        out.append(s.scalars(select(Keystore.private_key)).one())
        out.append(s.scalars(select(OAuthSigningKey.private_key)).one())
        out.append(s.scalars(select(CapturedExchange.data)).one())
    engine.dispose()
    return out


def test_rotate_secrets_reencrypts_everything_and_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    url = _db(tmp_path)
    ids = _seed(url, SecretBox([parse_key(OLD)]))
    monkeypatch.setenv("APIEDGE_SECRET_KEY", NEW)
    monkeypatch.setenv("APIEDGE_SECRET_KEY_PREVIOUS", OLD)
    new_only = SecretBox([parse_key(NEW)])

    # Dry run reports but writes nothing.
    assert main(["rotate-secrets", "--data-dir", str(tmp_path), "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "5 secret(s) still use an old key" in out
    assert all(new_only.needs_rotation(t) for t in _tokens(url))

    assert main(["rotate-secrets", "--data-dir", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "APIEDGE_SECRET_KEY_PREVIOUS can be removed" in out
    assert "JBSWY3DPEHPK3PXP" not in out and "PEM" not in out
    tokens = _tokens(url)
    assert not any(new_only.needs_rotation(t) for t in tokens)
    # The plaintext and the row binding (associated data) are unchanged.
    tid, sid = ids["tenant"], ids["session"]
    assert new_only.decrypt_str(tokens[0], f"user:{ids['user']}:mfa") == "JBSWY3DPEHPK3PXP"
    assert new_only.decrypt_str(tokens[1], secret_aad(ids["api"], "p1", "secret")) == "s1"
    assert new_only.decrypt_str(tokens[2], keystore_aad(tid, ids["ks"])) == "PEM-KS"
    assert new_only.decrypt_str(tokens[3], signing_key_aad(tid, "kid1")) == "PEM-SK"
    assert new_only.decrypt_str(tokens[4], exchange_aad(tid, sid)) == '{"k":1}'

    # Second run: nothing left to do, nothing rewritten.
    assert main(["rotate-secrets", "--data-dir", str(tmp_path)]) == 0
    assert "re-encrypted      0" in capsys.readouterr().out
    assert _tokens(url) == tokens

    # The old key is no longer needed.
    monkeypatch.delenv("APIEDGE_SECRET_KEY_PREVIOUS")
    assert main(["rotate-secrets", "--data-dir", str(tmp_path), "--dry-run"]) == 0


def test_rotate_secrets_reports_undecryptable_and_keeps_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    url = _db(tmp_path)
    _seed(url, SecretBox([parse_key(STRANGER)]))  # a key that is not configured
    before = _tokens(url)
    monkeypatch.setenv("APIEDGE_SECRET_KEY", NEW)
    monkeypatch.setenv("APIEDGE_SECRET_KEY_PREVIOUS", OLD)
    assert main(["rotate-secrets", "--data-dir", str(tmp_path)]) == 1
    captured = capsys.readouterr()
    assert "keep APIEDGE_SECRET_KEY_PREVIOUS" in captured.err
    assert "cannot decrypt: user MFA secrets id=" in captured.err
    assert _tokens(url) == before  # never destroyed


def test_rotate_secrets_rejects_tokens_moved_between_rows(tmp_path: Path) -> None:
    """A token copied to another row fails its associated data and is not 'repaired'."""
    url = _db(tmp_path)
    old = SecretBox([parse_key(OLD)])
    _seed(url, old)
    engine = make_engine(url)
    with make_session_factory(engine)() as s:
        ks = s.scalars(select(Keystore)).one()
        ks.private_key = s.scalars(select(OAuthSigningKey.private_key)).one()
        s.commit()
        report = rotate_secrets(s, SecretBox([parse_key(NEW), parse_key(OLD)]))
    engine.dispose()
    assert report.counts("keystore private keys").failed == 1
    assert report.counts("OAuth signing keys").rotated == 1
    assert not report.ok


def test_rotate_secrets_skips_rows_changed_concurrently(tmp_path: Path) -> None:
    url = _db(tmp_path)
    _seed(url, SecretBox([parse_key(OLD)]))
    box = SecretBox([parse_key(NEW), parse_key(OLD)])
    engine = make_engine(url)
    factory = make_session_factory(engine)
    with factory() as s:
        original = s.execute
        changed = False

        def racing_execute(stmt, *args, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal changed
            if not changed and getattr(stmt, "is_update", False) and stmt.table.name == "keystores":
                changed = True
                with factory() as other:  # the console changes the keystore meanwhile
                    k = other.scalars(select(Keystore)).one()
                    k.private_key = box.encrypt("NEWER", keystore_aad(k.tenant_id, k.id))
                    other.commit()
            return original(stmt, *args, **kwargs)

        s.execute = racing_execute  # type: ignore[assignment]
        report = rotate_secrets(s, box)
    with factory() as s:
        k = s.scalars(select(Keystore)).one()
        assert box.decrypt_str(k.private_key, keystore_aad(k.tenant_id, k.id)) == "NEWER"
    engine.dispose()
    assert sum(c.conflicts for c in report.categories.values()) == 1
    assert not report.ok


def test_rotate_secrets_needs_a_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("APIEDGE_SECRET_KEY", raising=False)
    assert main(["rotate-secrets", "--data-dir", str(tmp_path)]) == 1
    assert "no secrets master key" in capsys.readouterr().err
