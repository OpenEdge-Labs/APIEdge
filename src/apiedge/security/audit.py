# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Audit log writer (T-003, OWASP A09). Details are masked before they are stored."""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.orm import Session

from apiedge.db.models import AuditEvent
from apiedge.logs import request_id_var
from apiedge.security.masking import mask_value

log = logging.getLogger("apiedge.audit")


def audit(
    session: Session,
    action: str,
    *,
    tenant_id: int | None,
    actor_id: int | None = None,
    actor_username: str | None = None,
    resource_type: str | None = None,
    resource_id: object = None,
    outcome: str = "success",
    client_ip: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Add an audit event to ``session`` (committed with the action it records)."""
    session.add(
        AuditEvent(
            tenant_id=tenant_id,
            actor_user_id=actor_id,
            actor_username=actor_username,
            action=action,
            resource_type=resource_type,
            resource_id=None if resource_id is None else str(resource_id)[:64],
            outcome=outcome,
            client_ip=client_ip,
            request_id=request_id_var.get(),
            details=json.dumps(mask_value(details), default=str) if details else None,
        )
    )
    # Only code-defined values reach the log. User-influenced fields (names, ids, details) are
    # stored in the audit table only; the formatter adds the request id for correlation.
    log.info("audit %s %s", action, outcome)
