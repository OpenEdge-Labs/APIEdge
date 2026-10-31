# ADR 0002: Online, hash-locked one-click installer (supersedes vendored wheelhouse)

Date: 2026-10-31 · Status: Accepted · Tasks: T-019, T-001

## Context
The original T-019 asked for every third-party wheel and npm tarball to be committed (`vendor/`) so
installs work offline. Before any wheel was committed, the customer changed direction: dependencies are
**not** committed; instead each OS gets a one-click installer that downloads from PyPI.

## Decision
* `requirements/{runtime,dev,build}.in` hold exact top-level pins.
* `scripts/update-locks.py` (maintainers, needs internet) resolves them with pip's resolver and writes
  `requirements/*.lock` containing **every** sha256 PyPI publishes for each pinned version, so one
  lock works on Windows, Linux and macOS (x86_64/arm64) for Python 3.10–3.12. It fails if a compiled
  package lacks a wheel for any of those 15 platform/Python combinations (this is why
  `argon2-cffi-bindings` is held at 25.1.0: 26.1.0 has no macOS x86_64 wheel).
* Locks carry PEP 508 environment markers. `update-locks.py` resolves once with pip, then walks the
  dependency graph separately for each of the 15 targets (5 platforms x Python 3.10-3.12),
  evaluating every `Requires-Dist` marker and extra for that target. A package needed on only some
  targets gets a marker (for example `tomli ; python_version < "3.11"` or
  `colorama ; sys_platform == "win32"`). If dev tools need a runtime-locked package on more targets,
  `dev.lock` gets a complementary entry with a disjoint marker. Before writing, the script checks
  Requires-Python and wheel availability per target, and runs `pip install --dry-run --require-hashes`
  for every target with the markers applied.
  *Amended 2026-10-31:* the first version emitted marker-less union locks, and
  `backports-asyncio-runner` (Requires-Python <3.11) broke installs on Python 3.11 and 3.12 in CI.
* `scripts/install.py` (stdlib only) is the single installer implementation. Thin wrappers locate a
  suitable Python: `install.bat` → `scripts/install.ps1` (Windows), `install.command` (macOS) and
  `install.sh` (Linux) → `scripts/install.sh`.
* Install order: `build.lock` (pip, setuptools, wheel) → `runtime.lock` (+ `dev.lock` with `--dev`) →
  APIEdge itself with `--no-deps --no-build-isolation`, so **every** downloaded artifact is
  hash-verified (build isolation would otherwise fetch unpinned setuptools).
* The prebuilt console (our own code) stays committed in `src/apiedge/static`.
* CI replaces the planned network-disabled job with an installer smoke test on all three OSs.

## Consequences
* Installing needs internet access to PyPI (or a PyPI mirror via standard `PIP_INDEX_URL`).
* Supply-chain integrity comes from hashes; a compromised PyPI file is rejected.
* Offline bundles (wheelhouse per OS) remain possible later as release artifacts (T-016).
* `THIRD_PARTY_LICENSES.md` is generated from installed metadata by `scripts/check-licenses.py`, which
  also fails CI on GPL/AGPL/SSPL.
