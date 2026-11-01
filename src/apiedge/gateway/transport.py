# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Outbound HTTP for the gateway with the SSRF guard applied at connect time (T-007).

Upstream URLs were checked when they were saved, but DNS can change afterwards (DNS rebinding).
:class:`GuardedNetworkBackend` sits below httpx's connection pool: every new TCP connection
resolves the host, checks **all** resolved addresses against the SSRF policy and connects to a
validated address. The request URL keeps the host name, so the ``Host`` header, TLS SNI and
certificate verification all use the real name, and pooled connections are keyed by that name.
"""

from __future__ import annotations

import logging
import ssl
from collections.abc import Iterable
from pathlib import Path

import anyio
import httpcore
import httpx

from apiedge.security.ssrf import AsyncResolver, SsrfError, SsrfPolicy, resolve_checked_async

log = logging.getLogger("apiedge.gateway")


class UpstreamRefused(httpcore.ConnectError):
    """The upstream address is not allowed by the SSRF policy (nothing was sent)."""


class GuardedNetworkBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, policy: SsrfPolicy, resolver: AsyncResolver | None = None) -> None:
        self._policy = policy
        self._resolver = resolver
        self._inner = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        try:
            with anyio.fail_after(timeout):
                addresses = await resolve_checked_async(host, port, self._policy, self._resolver)
        except TimeoutError as exc:
            raise httpcore.ConnectTimeout("upstream name resolution timed out") from exc
        except SsrfError as exc:
            log.warning("upstream %s:%s refused by the SSRF guard: %s", host, port, exc)
            raise UpstreamRefused("upstream address refused") from None
        last: Exception | None = None
        for address in addresses:
            try:
                return await self._inner.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last = exc
        assert last is not None  # noqa: S101  # nosec B101 - addresses is never empty
        raise last

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise UpstreamRefused("unix sockets are not allowed")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def build_ssl_context(ca_bundle: Path | None) -> ssl.SSLContext:
    """Verifying TLS client context (TLS 1.2+); verification cannot be switched off here."""
    if ca_bundle is not None:
        ctx = ssl.create_default_context(cafile=str(ca_bundle))
    else:
        ctx = httpx.create_ssl_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class GuardedTransport(httpx.AsyncHTTPTransport):
    """httpx transport whose connection pool uses :class:`GuardedNetworkBackend`."""

    def __init__(
        self,
        policy: SsrfPolicy,
        *,
        ssl_context: ssl.SSLContext,
        limits: httpx.Limits | None = None,
        resolver: AsyncResolver | None = None,
    ) -> None:
        limits = limits or httpx.Limits(max_connections=500, max_keepalive_connections=100)
        super().__init__(verify=ssl_context, trust_env=False, limits=limits)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            max_connections=limits.max_connections,
            max_keepalive_connections=limits.max_keepalive_connections,
            keepalive_expiry=limits.keepalive_expiry,
            network_backend=GuardedNetworkBackend(policy, resolver),
        )


def build_client(
    policy: SsrfPolicy, ca_bundle: Path | None, resolver: AsyncResolver | None = None
) -> httpx.AsyncClient:
    """Client for upstream calls: no redirects followed, no proxy settings from the environment."""
    ssl_context = build_ssl_context(ca_bundle)
    transport = GuardedTransport(policy, ssl_context=ssl_context, resolver=resolver)
    return httpx.AsyncClient(transport=transport, follow_redirects=False, trust_env=False)
