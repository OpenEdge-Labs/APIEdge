#!/bin/sh
# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
# APIEdge installer bootstrap for Linux and macOS: finds Python 3.10-3.12,
# then runs scripts/install.py with all arguments.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

PY=""
for c in python3.12 python3.11 python3.10 python3 python; do
    if command -v "$c" >/dev/null 2>&1; then
        v=$("$c" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || true)
        case "$v" in 3.10|3.11|3.12) PY=$c; break ;; esac
    fi
done

if [ -z "$PY" ]; then
    echo ""
    echo "APIEdge needs Python 3.10, 3.11 or 3.12 (with the venv module), and none was found."
    case "$(uname -s)" in
        Darwin) echo "Install it from https://www.python.org/downloads/macos/ or run: brew install python@3.12" ;;
        *)      echo "Install it with your package manager, for example:"
                echo "  Debian/Ubuntu: sudo apt install python3 python3-venv"
                echo "  Fedora/RHEL:   sudo dnf install python3.12"
                echo "or download it from https://www.python.org/downloads/" ;;
    esac
    exit 3
fi

exec "$PY" "$ROOT/scripts/install.py" "$@"
