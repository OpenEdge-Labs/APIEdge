# ADR 0001: Python/FastAPI single process, SQLite by default

Date: 2026-10-31 · Status: Accepted · Task: T-001

## Context
`docs/PROJECT_GUIDE.md` mandates Python 3.10+, FastAPI/Uvicorn, SQLAlchemy 2 + Alembic, SQLite by default with
PostgreSQL optional, and a console shipped as static files inside the Python package.

## Decision
* One ASGI app (`apiedge.app.create_app`) serves health probes, the admin API under `/api/v1`, and the
  console at `/`. The gateway data plane will be mounted in the same process (T-007) and may be split
  into a separate listener later.
* setuptools is the build backend (already needed by the installer, no extra build dependency).
* The CLI uses `argparse` (stdlib) to avoid adding a CLI framework.
* Alembic migrations ship inside the package and run programmatically (`apiedge migrate`); no
  `alembic.ini` is needed at runtime.
* The console is built with Vite using esbuild's JSX transform (no `@vitejs/plugin-react`/Babel), to
  keep the npm tree small (24 packages).
* T-001 creates a minimal `users` table so `apiedge create-admin` works from day one; T-003 extends it.

## Consequences
Small dependency surface; SQLite-specific behaviour is isolated in `apiedge.db.base`.
PostgreSQL needs the optional `psycopg` driver (`pip install apiedge[postgres]`), which is not in the
default lock yet.
