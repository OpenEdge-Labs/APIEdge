# Contributing to APIEdge

Thank you for helping improve APIEdge. It's in early development (0.1 pre-releases), so bug reports, documentation fixes, tests and code are especially welcome.

## Before you start

- **Security problems:** don't open a public issue or pull request. Report them privately through the repository's Security tab → *Report a vulnerability*.
- **Bugs:** open an [issue](https://github.com/OpenEdge-Labs/APIEdge/issues). Include:
  - the APIEdge version and your OS;
  - your Python version (3.11, 3.12 or 3.13) and how you installed APIEdge;
  - the steps to reproduce the problem;
  - the log lines around it, with secrets removed.
- **Larger changes:** open an issue first to agree on the approach. The plan and the feature status are in [docs/FEATURE_MATRIX.md](docs/FEATURE_MATRIX.md) and [CHANGELOG.md](CHANGELOG.md).

## Development setup

You need Python 3.11, 3.12 or 3.13 and Git. The developer install builds a virtual environment in `.venv` from the hash-locked requirements:

```sh
git clone https://github.com/OpenEdge-Labs/APIEdge.git
cd APIEdge
python scripts/install.py --local --dev --no-start
.venv/bin/pre-commit install          # Windows: .venv\Scripts\pre-commit install
```

On Windows, replace `.venv/bin/` with `.venv\Scripts\` in the commands below.

## Checks your change must pass

CI runs these on every pull request. The pre-commit hooks run the first four for you:

```sh
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy
.venv/bin/bandit -c pyproject.toml -r src scripts
.venv/bin/python -m pytest
```

CI also runs CodeQL, `pip-audit` on the locked requirements, a licence check and the LDAP integration tests. A new dependency has to be added to the locked, hashed requirements in [requirements/](requirements/), with a compatible licence.

## Guidelines

- **Source file header:** every new source file starts with these two lines, in the file type's comment syntax:
  ```
  # Copyright 2026 OpenEdge Labs
  # SPDX-License-Identifier: Apache-2.0
  ```
- **Tests:** add tests for new behaviour and for every bug you fix.
- **Security:** follow the security model in [docs/SECURITY.md](docs/SECURITY.md):
  - check permissions on every admin route;
  - keep each tenant's data separate;
  - encrypt secrets at rest, and never log them;
  - fail closed on errors.
- **Documentation:** update the guides in [docs/](docs/) when you change behaviour or settings.
- **Commits:** keep each commit to one logical change, and use [Conventional Commits](https://www.conventionalcommits.org/) messages (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
- **Pull requests:** say what the change does, why, and how you tested it.

## Licence

APIEdge is licensed under the [Apache License 2.0](LICENSE). Contributions are accepted under the same licence, as set out in section 5 of the licence.

## Community

Everyone taking part is expected to be respectful and constructive. Project news and other OpenEdge Labs projects are at <https://openelabs.com>.
