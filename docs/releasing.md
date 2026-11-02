# Releasing APIEdge (maintainers)

Release artifacts are built by `.github/workflows/release.yml` with `scripts/build-release.py`
(design: [ADR 0011](adr/0011-release-packaging.md)).

## What a release build produces

| File | What it is |
|---|---|
| `apiedge-<version>-py3-none-any.whl` | the wheel, with the prebuilt console |
| `apiedge-<version>-installer-windows.zip` / `-macos.zip` / `-linux.zip` | one-click installer bundles |
| `apiedge-<version>.cdx.json` | CycloneDX 1.5 SBOM |
| `apiedge-<chart version>.tgz` | Helm chart (SemVer form of the version, e.g. `0.1.0-dev.0`) |
| `SHA256SUMS`, `SHA256SUMS.asc` | checksums, and their GPG signature when a key is configured |

The multi-arch container image is built and tested but not exported or pushed.

## Build locally

```
python scripts/install.py --local --dev --no-start --no-shortcut    # once
.venv/bin/python scripts/build-release.py build --out dist/release  # add --helm if helm is installed
.venv/bin/python scripts/build-release.py verify dist/release
docker build -f packaging/docker/Dockerfile -t apiedge:local .
```

`build` refuses a non-empty output directory and, for a tag, a tag that is not `v<version>`.

## Cut a release

1. Set `version` in `pyproject.toml`, and `version` / `appVersion` in
   `packaging/helm/apiedge/Chart.yaml` (a unit test checks they agree), and move the CHANGELOG
   entries from `Unreleased` to the new version.
2. Commit, then tag and push: `git tag v<version> && git push origin v<version>`.
3. The workflow builds and tests every artifact. Download them from the run's `apiedge-release`
   artifact.

## Signing and publishing (off until the customer enables them)

| Setting | Kind | Effect |
|---|---|---|
| `APIEDGE_RELEASE_GPG_KEY` | repository secret | ASCII-armored private key; when set, `SHA256SUMS.asc` is created and verified |
| `APIEDGE_RELEASE_GPG_PASSPHRASE` | repository secret | its passphrase |
| `APIEDGE_PUBLISH_RELEASE` | repository variable | `true`: a `v*` tag also creates a **draft** GitHub release with all artifacts |

Without them the steps are skipped and the run stays green. Publishing to PyPI and to a container
registry is not configured; that is part of T-031.
