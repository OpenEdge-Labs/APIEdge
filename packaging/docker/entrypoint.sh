#!/bin/sh
# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
#
# APIEdge container entry point.
#   serve [run options]   (default) migrate, ensure the first SuperAdmin, start console + gateway
#   <apiedge command>     any other `apiedge` sub-command, e.g. `version` or `migrate`
#
# First SuperAdmin: APIEDGE_ADMIN_USER (default admin). The password is read from the file named
# by APIEDGE_ADMIN_PASSWORD_FILE (a Docker / Kubernetes secret) or, when unset, generated and
# printed ONCE to the container log. Either way it must be changed at the first sign-in.
set -eu

if [ "$#" -eq 0 ] || [ "$1" = "serve" ]; then
    [ "$#" -gt 0 ] && shift
    apiedge init
    user="${APIEDGE_ADMIN_USER:-admin}"
    if [ -n "${APIEDGE_ADMIN_PASSWORD_FILE:-}" ]; then
        apiedge create-admin --username "$user" --if-missing --password-stdin \
            < "$APIEDGE_ADMIN_PASSWORD_FILE"
    else
        apiedge create-admin --username "$user" --if-missing --generate-password
    fi
    exec apiedge run --no-migrate "$@"
fi

exec apiedge "$@"
