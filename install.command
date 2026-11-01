#!/bin/sh
# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
# APIEdge one-click installer for macOS. Double-click it in Finder, or run:
#   ./install.command [--yes] [--smoke-test] [--uninstall] [--help]
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$DIR" || exit 1
sh "$DIR/scripts/install.sh" "$@"
RC=$?
# Keep the Terminal window readable when started by double-click (no arguments).
if [ $# -eq 0 ]; then printf '\nPress Return to close this window...'; read -r _; fi
exit $RC
