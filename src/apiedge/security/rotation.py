# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Re-encrypt every secret stored at rest with the current master key (T-034).

After a key rotation (new key in ``APIEDGE_SECRET_KEY``, old key in
``APIEDGE_SECRET_KEY_PREVIOUS``) the old key must stay configured as long as data encrypted with
it exists. :func:`rotate_secrets` finds every secrets-box token that was not encrypted with the
primary key, decrypts it with the previous key and re-encrypts it with the primary key, keeping
the same associated data. The old key can then be removed.

Covered columns: user TOTP secrets, secret fields of API policy chains, captured exchanges of
the packet inspector, keystore private keys and OAuth signing keys.

Properties:

* **Idempotent** - tokens already under the primary key are left alone, so re-running is safe
  and a re-run after an interruption continues where the last run stopped.
* **Race-safe** - every row is written with a conditional ``UPDATE ... WHERE column = <old
  token>``; a row changed concurrently (by the console or the gateway) is skipped and reported,
  never overwritten.
* **No data loss** - a token that cannot be decrypted (unknown key, tampered, wrong row) is left
  unchanged and reported; nothing is ever deleted. Output never contains plaintext or keys.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Column, select, update
from sqlalchemy.orm import Session

from apiedge.db.models import Api, CapturedExchange, Keystore, OAuthSigningKey, User
from apiedge.inspector.store import exchange_aad
from apiedge.policies.builtin import secret_aad
from apiedge.policies.config import SECRET_FIELDS
from apiedge.security.crypto import DecryptionError, SecretBox
from apiedge.security.oauth import signing_key_aad
from apiedge.security.tls import keystore_aad

BATCH = 200


@dataclass
class Counts:
    """Per-category result: tokens checked, re-encrypted, failed to decrypt, changed meanwhile."""

    checked: int = 0
    rotated: int = 0
    failed: int = 0
    conflicts: int = 0


@dataclass
class RotationReport:
    dry_run: bool
    key_id: str
    categories: dict[str, Counts] = field(default_factory=dict)
    # Row references (category, id) of tokens that could not be decrypted - never values.
    failures: list[str] = field(default_factory=list)

    def counts(self, name: str) -> Counts:
        return self.categories.setdefault(name, Counts())

    @property
    def ok(self) -> bool:
        return all(c.failed == 0 and c.conflicts == 0 for c in self.categories.values())

    @property
    def remaining(self) -> int:
        """Tokens still not under the primary key after this run."""
        if self.dry_run:
            return sum(c.rotated + c.failed for c in self.categories.values())
        return sum(c.failed + c.conflicts for c in self.categories.values())


def _reencrypt(box: SecretBox, token: str, aad: str) -> str:
    return box.encrypt(box.decrypt(token, aad), aad)


def _batches(session: Session, stmt: Any) -> Iterator[Any]:
    """Rows of ``stmt`` (ordered by primary key) in id-keyed batches, so a long table is never
    loaded at once and the read does not hold a cursor open across our writes."""
    last = 0
    while True:
        rows = session.execute(stmt(last).limit(BATCH)).all()
        if not rows:
            return
        yield from rows
        last = rows[-1][0]


def _rotate_column(
    session: Session,
    box: SecretBox,
    report: RotationReport,
    name: str,
    model: Any,
    column: Column[Any] | Any,
    aad_of: Callable[[Any], str],
    extra: tuple[Any, ...] = (),
) -> None:
    counts = report.counts(name)

    def stmt(last: int) -> Any:
        return (
            select(model.id, column, *extra)
            .where(model.id > last, column.is_not(None))
            .order_by(model.id)
        )

    for row in _batches(session, stmt):
        token = row[1]
        counts.checked += 1
        if not box.needs_rotation(token):
            continue
        try:
            new = _reencrypt(box, token, aad_of(row))
        except DecryptionError:
            counts.failed += 1
            report.failures.append(f"{name} id={row[0]}")
            continue
        if report.dry_run:
            counts.rotated += 1
            continue
        result = session.execute(
            update(model).where(model.id == row[0], column == token).values({column.key: new})
        )
        session.commit()
        if result.rowcount == 1:  # type: ignore[attr-defined]
            counts.rotated += 1
        else:
            counts.conflicts += 1


def _rotate_policy_chains(session: Session, box: SecretBox, report: RotationReport) -> None:
    counts = report.counts("policy secrets")

    def stmt(last: int) -> Any:
        return select(Api.id, Api.policies).where(Api.id > last).order_by(Api.id)

    for api_id, document in _batches(session, stmt):
        try:
            entries = json.loads(document or "[]")
        except ValueError:
            continue  # not ours to repair; the gateway reports invalid chains itself
        if not isinstance(entries, list):
            continue
        changed = failed = 0
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("config"), dict):
                continue
            config: dict[str, Any] = entry["config"]
            for name in SECRET_FIELDS.get(str(entry.get("type")), ()):
                token = config.get(name)
                if not isinstance(token, str):
                    continue
                counts.checked += 1
                if not box.needs_rotation(token):
                    continue
                try:
                    config[name] = _reencrypt(
                        box, token, secret_aad(api_id, str(entry.get("id")), name)
                    )
                except DecryptionError:
                    failed += 1
                    report.failures.append(f"policy secrets api={api_id} policy={entry.get('id')}")
                    continue
                changed += 1
        counts.failed += failed
        if not changed:
            continue
        if report.dry_run:
            counts.rotated += changed
            continue
        new_document = json.dumps(entries, separators=(",", ":"))
        result = session.execute(
            update(Api)
            .where(Api.id == api_id, Api.policies == document)
            .values(policies=new_document)
        )
        session.commit()
        if result.rowcount == 1:  # type: ignore[attr-defined]
            counts.rotated += changed
        else:
            counts.conflicts += changed


def rotate_secrets(session: Session, box: SecretBox, *, dry_run: bool = False) -> RotationReport:
    """Re-encrypt every stored secret with ``box``'s primary key (see the module docstring).

    ``session`` must be unbound (platform scope) so every tenant's rows are visited.
    """
    report = RotationReport(dry_run=dry_run, key_id=box.primary_key_id)
    _rotate_column(
        session,
        box,
        report,
        "user MFA secrets",
        User,
        User.mfa_secret_enc,
        lambda r: f"user:{r[0]}:mfa",
    )
    _rotate_policy_chains(session, box, report)
    _rotate_column(
        session,
        box,
        report,
        "keystore private keys",
        Keystore,
        Keystore.private_key,
        lambda r: keystore_aad(r[2], r[0]),
        (Keystore.tenant_id,),
    )
    _rotate_column(
        session,
        box,
        report,
        "OAuth signing keys",
        OAuthSigningKey,
        OAuthSigningKey.private_key,
        lambda r: signing_key_aad(r[2], r[3]),
        (OAuthSigningKey.tenant_id, OAuthSigningKey.kid),
    )
    _rotate_column(
        session,
        box,
        report,
        "captured exchanges",
        CapturedExchange,
        CapturedExchange.data,
        lambda r: exchange_aad(r[2], r[3]),
        (CapturedExchange.tenant_id, CapturedExchange.session_id),
    )
    return report
