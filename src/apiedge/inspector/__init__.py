# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Packet inspector (T-012, ADR 0010).

* :mod:`apiedge.inspector.recorder` - gateway side: matches requests against the active capture
  sessions (a gateway trace listener), copies the exchange with bounded bodies into a bounded
  in-memory queue and writes it, encrypted, to the database; enforces the per-session ring
  buffer and the retention period.
* :mod:`apiedge.inspector.store` - the stored exchange format and its encryption.
* :mod:`apiedge.inspector.masking` - masking of credentials and configured fields for display.
* :mod:`apiedge.inspector.har` - HAR 1.2 export.
"""
