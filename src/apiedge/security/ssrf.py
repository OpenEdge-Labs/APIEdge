# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""SSRF guard for upstream URLs (T-002, OWASP A10 / API7).

:func:`check_url` validates a URL and **every** address its host resolves to against an
:class:`SsrfPolicy`:

* only ``http``/``https``; no user-info (``user:pass@host``); a host is required;
* non-canonical numeric hosts (``2130706433``, ``0x7f.1``, ``127.1``) are rejected outright;
* loopback, private (RFC 1918, ULA), link-local, CGNAT, multicast, reserved and unspecified
  addresses are blocked by default (``allow_private=True`` lifts this for on-prem upstreams);
* cloud metadata endpoints stay blocked even with ``allow_private`` unless an ``allow_cidrs``
  entry covers them explicitly;
* ``deny_cidrs`` always wins; ``allow_cidrs`` overrides the default blocks.

The result carries the vetted IP addresses. Callers that open a connection (gateway proxy, script
HTTP, inspector replay) must connect to one of those addresses, not re-resolve the name, otherwise
DNS rebinding can swap in a forbidden address between check and use.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
Resolver = Callable[[str, int], Sequence[str]]

ALLOWED_SCHEMES = frozenset({"http", "https"})

METADATA_NETWORKS: tuple[IPNetwork, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "169.254.169.254/32",  # AWS, GCP, Azure, OpenStack, DigitalOcean ...
        "169.254.170.2/32",  # AWS ECS task metadata
        "100.100.100.200/32",  # Alibaba Cloud
        "fd00:ec2::254/128",  # AWS IMDS over IPv6
    )
)

# Blocked by default (on top of ipaddress' is_private / is_loopback / ... flags).
DEFAULT_BLOCKED_NETWORKS: tuple[IPNetwork, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "100.64.0.0/10",  # carrier-grade NAT
        "192.0.0.0/24",
        "198.18.0.0/15",  # benchmarking
        "255.255.255.255/32",
        "64:ff9b::/96",  # NAT64 can reach any IPv4, incl. private
        "64:ff9b:1::/48",
        "2002::/16",  # 6to4 embeds IPv4
    )
)

_NUMERIC_HOST = re.compile(r"^(0x[0-9a-f]*|[0-9]+)(\.(0x[0-9a-f]*|[0-9]*))*$", re.IGNORECASE)


class SsrfError(ValueError):
    """The URL or one of its resolved addresses is not allowed."""


@dataclass(frozen=True)
class SsrfPolicy:
    allow_private: bool = False
    allow_cidrs: tuple[IPNetwork, ...] = ()
    deny_cidrs: tuple[IPNetwork, ...] = ()
    allowed_ports: frozenset[int] | None = None  # None = any port

    @classmethod
    def from_strings(
        cls,
        *,
        allow_private: bool = False,
        allow_cidrs: Iterable[str] = (),
        deny_cidrs: Iterable[str] = (),
        allowed_ports: Iterable[int] | None = None,
    ) -> SsrfPolicy:
        return cls(
            allow_private=allow_private,
            allow_cidrs=tuple(ipaddress.ip_network(c.strip(), strict=False) for c in allow_cidrs),
            deny_cidrs=tuple(ipaddress.ip_network(c.strip(), strict=False) for c in deny_cidrs),
            allowed_ports=frozenset(allowed_ports) if allowed_ports is not None else None,
        )


@dataclass(frozen=True)
class CheckedUrl:
    url: str
    scheme: str
    host: str
    port: int
    addresses: tuple[str, ...] = field(default_factory=tuple)


def _in_any(ip: IPAddress, nets: Iterable[IPNetwork]) -> bool:
    return any(ip.version == n.version and ip in n for n in nets)


def _is_special(ip: IPAddress) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or (isinstance(ip, ipaddress.IPv6Address) and ip.is_site_local)
        or _in_any(ip, DEFAULT_BLOCKED_NETWORKS)
    )


def check_ip(ip_text: str, policy: SsrfPolicy) -> None:
    """Raise :class:`SsrfError` if the address is not allowed by ``policy``."""
    ip: IPAddress = ipaddress.ip_address(ip_text.split("%", 1)[0])  # strip IPv6 zone id
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 is 127.0.0.1
    if _in_any(ip, policy.deny_cidrs):
        raise SsrfError(f"address {ip} is denied by policy")
    if _in_any(ip, policy.allow_cidrs):
        return
    if _in_any(ip, METADATA_NETWORKS):
        raise SsrfError(f"address {ip} is a cloud metadata endpoint")
    if _is_special(ip) and not policy.allow_private:
        raise SsrfError(f"address {ip} is private, loopback, link-local or reserved")


def system_resolver(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise SsrfError(f"cannot resolve host {host!r}") from exc
    return sorted({str(info[4][0]) for info in infos})


def _parse(url: str, policy: SsrfPolicy) -> tuple[str, str, int, IPAddress | None]:
    if len(url) > 2048:
        raise SsrfError("URL is too long")
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError as exc:
        raise SsrfError("malformed URL") from exc
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SsrfError("only http and https URLs are allowed")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise SsrfError("credentials in the URL are not allowed")
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise SsrfError("URL has no host")
    if port is None:
        port = 443 if scheme == "https" else 80
    if policy.allowed_ports is not None and port not in policy.allowed_ports:
        raise SsrfError(f"port {port} is not allowed")
    try:
        literal: IPAddress | None = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        literal = None
        if _NUMERIC_HOST.match(host):
            raise SsrfError("non-canonical numeric host is not allowed") from None
    return scheme, host, port, literal


def check_url(url: str, policy: SsrfPolicy, resolver: Resolver = system_resolver) -> CheckedUrl:
    """Validate ``url`` and all addresses its host resolves to. Blocking (does DNS)."""
    scheme, host, port, literal = _parse(url, policy)
    addresses = [str(literal)] if literal is not None else list(resolver(host, port))
    if not addresses:
        raise SsrfError(f"host {host!r} resolved to no addresses")
    for addr in addresses:
        check_ip(addr, policy)
    return CheckedUrl(url=url, scheme=scheme, host=host, port=port, addresses=tuple(addresses))


AsyncResolver = Callable[[str, int], Awaitable[Sequence[str]]]


async def system_resolver_async(host: str, port: int) -> list[str]:
    """Resolve with the event loop's resolver (does not block the loop)."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise SsrfError(f"cannot resolve host {host!r}") from exc
    return sorted({str(info[4][0]) for info in infos})


async def resolve_checked_async(
    host: str, port: int, policy: SsrfPolicy, resolver: AsyncResolver | None = None
) -> tuple[str, ...]:
    """Resolve ``host`` and return its addresses only if **every** one passes ``policy``.

    Used at connect time (gateway proxy): the caller connects to one of the returned addresses,
    so a DNS answer that changed since the URL was saved (DNS rebinding) is checked again.
    """
    host = host.strip("[]").rstrip(".")
    if not host:
        raise SsrfError("URL has no host")
    if policy.allowed_ports is not None and port not in policy.allowed_ports:
        raise SsrfError(f"port {port} is not allowed")
    try:
        literal: IPAddress | None = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        literal = None
        if _NUMERIC_HOST.match(host):
            raise SsrfError("non-canonical numeric host is not allowed") from None
    if literal is not None:
        addresses: Sequence[str] = [str(literal)]
    else:
        addresses = await (resolver or system_resolver_async)(host, port)
    if not addresses:
        raise SsrfError(f"host {host!r} resolved to no addresses")
    for addr in addresses:
        check_ip(addr, policy)
    return tuple(addresses)


async def check_url_async(url: str, policy: SsrfPolicy) -> CheckedUrl:
    """Async variant of :func:`check_url` using the event loop's resolver."""
    scheme, host, port, _literal = _parse(url, policy)
    addresses = await resolve_checked_async(host, port, policy)
    return CheckedUrl(url=url, scheme=scheme, host=host, port=port, addresses=addresses)
