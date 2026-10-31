# Changelog

All notable changes to APIEdge are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- T-001: `apiedge` Python package (FastAPI, pydantic-settings, SQLAlchemy 2 + Alembic, SQLite default / PostgreSQL optional), CLI `init | migrate | run | create-admin | version`, `/healthz` and `/readyz` probes, Argon2id-hashed bootstrap SuperAdmin, React + Vite + TypeScript console shell prebuilt into `src/apiedge/static`, ruff / mypy --strict / bandit / pytest / pre-commit config, `.env.example`, GitHub Actions CI (Windows, Linux, macOS x Python 3.10-3.12), architecture docs and ADRs.
- T-019: one-click installers `install.bat` (Windows), `install.command` (macOS) and `install.sh` (Linux) on top of the shared `scripts/install.py`: Python check with guidance, venv, hash-locked install from PyPI (`requirements/*.lock`), migrations, first admin, shortcuts, start at logon, `--unattended`, `--proxy`, `--index-url`, `--uninstall`, install log. Lock tooling (`scripts/update-locks.py`), license gate and `THIRD_PARTY_LICENSES.md` (`scripts/check-licenses.py`), CI installer smoke test on all three OSs.
- Project guide (`docs/PROJECT_GUIDE.md`) and task list (`APIProjectTask.md`).
