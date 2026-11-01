# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections.abc import Sequence

import pytest

from apiedge.security.ssrf import Resolver, SsrfError, SsrfPolicy, check_url, check_url_async

DEFAULT = SsrfPolicy()


def fake_dns(mapping: dict[str, list[str]]) -> Resolver:
    def resolve(host: str, _port: int) -> Sequence[str]:
        if host not in mapping:
            raise SsrfError(f"cannot resolve host {host!r}")
        return mapping[host]

    return resolve


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://10.1.2.3/",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://100.64.0.1/",
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://[fe80::1]/",
        "http://[fc00::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[::ffff:169.254.169.254]/",
        "http://[fd00:ec2::254]/",
        "http://224.0.0.1/",
        "http://2130706433/",  # decimal 127.0.0.1
        "http://0x7f000001/",
        "http://0x7f.1/",
        "http://127.1/",
        "http://017700000001/",
    ],
)
def test_blocked_addresses(url: str) -> None:
    with pytest.raises(SsrfError):
        check_url(url, DEFAULT, resolver=fake_dns({}))


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://example.com/",
        "ftp://example.com/",
        "http://user:pass@example.com/",
        "http://@example.com/",
        "http:///nohost",
        "http://example.com:99999/",
        "//example.com/",
        "http://" + "a" * 2100 + ".com/",
    ],
)
def test_malformed_or_forbidden_urls(url: str) -> None:
    with pytest.raises(SsrfError):
        check_url(url, DEFAULT, resolver=fake_dns({"example.com": ["93.184.216.34"]}))


def test_public_host_allowed_and_addresses_returned() -> None:
    res = check_url(
        "https://api.example.com/v1", DEFAULT, resolver=fake_dns({"api.example.com": ["8.8.8.8"]})
    )
    assert res.host == "api.example.com"
    assert res.port == 443
    assert res.addresses == ("8.8.8.8",)


def test_any_private_resolution_blocks_hostname() -> None:
    dns = fake_dns({"rebind.example": ["8.8.8.8", "10.0.0.5"], "lh.example.": ["127.0.0.1"]})
    with pytest.raises(SsrfError, match=r"10.0.0.5"):
        check_url("http://rebind.example/", DEFAULT, resolver=dns)
    with pytest.raises(SsrfError):
        check_url("http://localhost./", DEFAULT, resolver=fake_dns({"localhost": ["127.0.0.1"]}))


def test_allow_private_for_on_prem_but_metadata_stays_blocked() -> None:
    policy = SsrfPolicy(allow_private=True)
    assert check_url("http://10.0.0.5:8080/", policy).port == 8080
    with pytest.raises(SsrfError, match="metadata"):
        check_url("http://169.254.169.254/", policy)


def test_allow_and_deny_cidrs() -> None:
    allow = SsrfPolicy.from_strings(allow_cidrs=["10.20.0.0/16"])
    assert check_url("http://10.20.1.1/", allow)
    with pytest.raises(SsrfError):
        check_url("http://10.21.1.1/", allow)
    deny = SsrfPolicy.from_strings(allow_private=True, deny_cidrs=["8.8.8.0/24", "10.9.0.0/16"])
    with pytest.raises(SsrfError, match="denied"):
        check_url("http://8.8.8.8/", deny)
    with pytest.raises(SsrfError, match="denied"):
        check_url("http://10.9.0.1/", deny)


def test_port_allow_list() -> None:
    policy = SsrfPolicy.from_strings(allowed_ports=[443])
    assert check_url("https://8.8.8.8/", policy)
    with pytest.raises(SsrfError, match="port"):
        check_url("http://8.8.8.8:22/", policy)


async def test_async_variant_blocks_literals() -> None:
    with pytest.raises(SsrfError):
        await check_url_async("http://127.0.0.1/", DEFAULT)
    assert (await check_url_async("http://8.8.4.4/", DEFAULT)).addresses == ("8.8.4.4",)
