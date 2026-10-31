#!/bin/sh
# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
# APIEdge one-click installer for Linux:  ./install.sh [--yes] [--smoke-test] [--uninstall] [--help]
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec sh "$DIR/scripts/install.sh" "$@"
