# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Allow ``python -m apiedge``."""

import sys

from apiedge.cli import main

sys.exit(main())
