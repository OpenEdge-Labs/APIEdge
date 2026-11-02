# syntax=docker/dockerfile:1
# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
#
# APIEdge container image (linux/amd64 and linux/arm64).
#   docker build -f packaging/docker/Dockerfile -t apiedge:dev .
# Dependencies come from PyPI with --require-hashes (requirements/runtime.lock); nothing
# third-party is copied from the source tree.

# Multi-arch index digest of python:3.12.16-slim-trixie.
ARG PYTHON_IMAGE=python:3.12.16-slim-trixie@sha256:8523d6abeb48ceae0b7240d30c5808fc26cb79c1a635bacdf19cf3baecfbec07

# ---------------------------------------------------------------- build the wheel
FROM ${PYTHON_IMAGE} AS build
WORKDIR /src
COPY requirements/build.lock requirements/build.lock
RUN python -m pip install --no-cache-dir --disable-pip-version-check --no-input \
        --require-hashes -r requirements/build.lock
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src/ src/
RUN python -m pip wheel --no-cache-dir --disable-pip-version-check --no-input \
        --no-deps --no-build-isolation --wheel-dir /wheels .

# ---------------------------------------------------------------- runtime
FROM ${PYTHON_IMAGE}
ARG VERSION=dev
# 1 = also install the hash-pinned PostgreSQL driver (packaging/docker/postgres-driver.txt).
ARG APIEDGE_WITH_POSTGRES=0

LABEL org.opencontainers.image.title="APIEdge" \
      org.opencontainers.image.description="On-premise, multi-tenant API Gateway with a no-code / low-code web console" \
      org.opencontainers.image.vendor="OpenEdge Labs" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/OpenEdge-Labs/APIEdge" \
      org.opencontainers.image.version="${VERSION}"

RUN groupadd --system --gid 10001 apiedge \
 && useradd --system --uid 10001 --gid apiedge --home-dir /var/lib/apiedge \
        --shell /usr/sbin/nologin apiedge \
 && install -d -o apiedge -g apiedge -m 0700 /var/lib/apiedge

COPY requirements/build.lock requirements/runtime.lock /tmp/req/
COPY packaging/docker/postgres-driver.txt /tmp/req/
RUN python -m venv /opt/apiedge \
 && /opt/apiedge/bin/pip install --no-cache-dir --disable-pip-version-check --no-input \
        --require-hashes -r /tmp/req/build.lock \
 && /opt/apiedge/bin/pip install --no-cache-dir --disable-pip-version-check --no-input \
        --require-hashes -r /tmp/req/runtime.lock \
 && if [ "$APIEDGE_WITH_POSTGRES" = "1" ]; then \
        /opt/apiedge/bin/pip install --no-cache-dir --disable-pip-version-check --no-input \
            --require-hashes --no-deps -r /tmp/req/postgres-driver.txt; \
    fi \
 && rm -rf /tmp/req

COPY --from=build /wheels/ /tmp/wheels/
RUN /opt/apiedge/bin/pip install --no-cache-dir --disable-pip-version-check --no-input \
        --no-deps /tmp/wheels/*.whl \
 && rm -rf /tmp/wheels

COPY --chmod=0755 packaging/docker/entrypoint.sh /usr/local/bin/apiedge-entrypoint

ENV PATH=/opt/apiedge/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APIEDGE_DATA_DIR=/var/lib/apiedge \
    APIEDGE_HOST=0.0.0.0 \
    APIEDGE_PORT=8080 \
    APIEDGE_GATEWAY_HOST=0.0.0.0 \
    APIEDGE_GATEWAY_PORT=8081

USER 10001:10001
WORKDIR /var/lib/apiedge
VOLUME ["/var/lib/apiedge"]
EXPOSE 8080 8081

HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=3 \
    CMD ["python", "-c", "import os, sys, urllib.request; port = os.environ.get('APIEDGE_PORT', '8080'); sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:' + port + '/healthz', timeout=3).status == 200 else 1)"]

ENTRYPOINT ["apiedge-entrypoint"]
CMD ["serve"]
