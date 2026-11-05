<!-- Copyright 2026 OpenEdge Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Upgrade notes

## General procedure

1. **Read the notes** for every version between yours and the target, below and in the
   CHANGELOG (`CHANGELOG.md` in the repository and in every installer bundle).
2. **Back up** the database and the secrets key (see
   [backup and restore](admin-guide/operations.md#backup-and-restore)).
3. **Upgrade** with the method you installed with (below). The database schema is upgraded by
   Alembic migrations, which `apiedge run` applies automatically at start (and `apiedge migrate`
   applies on demand). Migrations are forward-only: to go back to an older version, restore the
   backup taken before the upgrade.
4. **Check** `GET /healthz` and `GET /readyz`, sign in, and look at **System settings**.

Settings are read from `APIEDGE_*` environment variables and `.env`; an upgrade never rewrites
them. New settings always come with safe defaults.

| Installed with | Upgrade |
|---|---|
| One-click installer | Unzip the new bundle (or `git pull` in the checkout) and run the installer again. It reuses or repairs the environment, installs the locked versions, applies migrations and keeps your users and data |
| pip wheel | `pip install --require-hashes -r requirements/runtime.lock` from the new version, then `pip install --no-deps apiedge-<version>-py3-none-any.whl`, then restart (`apiedge migrate` runs at start) |
| Docker / Docker Compose | Rebuild the image from the new source (`docker compose up -d --build`); the volumes keep the data, and the entry point migrates on start |
| Helm | Push the new image and `helm upgrade apiedge packaging/helm/apiedge --set image.tag=<version>`. The chart uses the `Recreate` strategy, so expect a short interruption |

With several APIEdge processes on one database, stop all of them, upgrade, and start them again:
rolling upgrades are planned with clustering (T-026).

## Version notes

### Unreleased (0.1 pre-releases)

The first release has not been tagged yet. Notes for pre-release builds:

* **No upgrade path is promised between pre-release builds** before 0.1.0, although every schema
  change so far is a forward migration (0001 to 0007) and data has been preserved.
* **Python 3.11 or newer is required** (T-032). Python 3.10 is no longer supported; supported
  versions are 3.11, 3.12 and 3.13. On a host with only 3.10, install a newer Python first and
  run the installer again: it recreates the virtual environment with the new interpreter.
* **PostgreSQL driver** (T-033): APIEdge now ships pg8000 (pure Python, BSD-3-Clause) in every
  installation and image instead of psycopg in a special image build; the build argument
  `APIEDGE_WITH_POSTGRES` is gone. Existing `postgresql+psycopg://`, `postgresql://` and
  `postgres://` URLs keep working: they select pg8000. Rebuild compose stacks
  (`docker compose up -d --build`).
* Forwarded headers (T-018): the gateway now honours `X-Forwarded-For` / `X-Forwarded-Proto`
  only from `APIEDGE_GATEWAY_TRUSTED_PROXIES`; before, 127.0.0.1 was trusted implicitly. If a
  reverse proxy on the same host fronts the gateway, add `127.0.0.1` to that setting. The console
  keeps trusting 127.0.0.1 by default, now through the new `APIEDGE_TRUSTED_PROXIES` setting.
* Admin API operations now carry their required permission as `x-apiedge-access` in the OpenAPI
  document. This is an addition; existing clients are unaffected.
