# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""Gateway building blocks (T-007): route patterns, balancer, lifecycle states, change events
(in-process and Redis) and the connect-time SSRF resolution."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Sequence
from pathlib import Path
from typing import Any

import pytest

from apiedge.db.base import make_engine, make_session_factory, run_migrations
from apiedge.db.models import Product, Tenant, User
from apiedge.gateway.bus import ConfigBus, RedisConfigBus, build_bus, install_change_notifier
from apiedge.gateway.snapshot import (
    DEPRECATED,
    RETIRED,
    SERVED,
    WeightedBalancer,
    _state,
    compile_route_path,
)
from apiedge.security.ssrf import SsrfError, SsrfPolicy, resolve_checked_async


@pytest.mark.parametrize(
    ("route", "path", "matches"),
    [
        ("/", "/", True),
        ("/", "/x", False),
        ("/*", "/", True),
        ("/*", "/a/b", True),
        ("/orders/{id}", "/orders/1", True),
        ("/orders/{id}", "/orders/", False),
        ("/orders/{id}", "/orders/1/2", False),
        ("/a.b", "/aXb", False),  # literal dots are escaped
        ("/files/*", "/files", True),
        ("/files/*", "/files/x/y", True),
        ("/files/*", "/filesx", False),
        ("/{a}/x/{b}", "/1/x/2", True),
    ],
)
def test_route_patterns(route: str, path: str, matches: bool) -> None:
    assert (compile_route_path(route).fullmatch(path) is not None) is matches


def test_balancer_spreads_by_weight_and_honours_exclusions() -> None:
    lb = WeightedBalancer([5, 1, 1])
    picks = [lb.pick() for _ in range(7)]
    assert picks.count(0) == 5 and picks.count(1) == 1 and picks.count(2) == 1
    assert picks[:2] == [0, 0] and picks[2] != 0  # interleaved, not bunched
    assert lb.pick(frozenset({0})) in (1, 2)
    assert lb.pick(frozenset({0, 1, 2})) in (0, 1, 2)  # everything tried: start over


@pytest.mark.parametrize(
    ("api", "product", "state"),
    [
        ("draft", "published", None),
        ("published", "draft", SERVED),
        ("published", "published", SERVED),
        ("published", "deprecated", DEPRECATED),
        ("deprecated", "published", DEPRECATED),
        ("retired", "published", RETIRED),
        ("published", "retired", RETIRED),
        ("draft", "retired", RETIRED),
    ],
)
def test_lifecycle_states(api: str, product: str, state: str | None) -> None:
    assert _state(api, product) == state


def test_in_process_bus() -> None:
    bus = ConfigBus()
    calls: list[str] = []
    unsubscribe = bus.subscribe(lambda: calls.append("x"))

    def broken() -> None:
        raise RuntimeError("boom")

    bus.subscribe(broken)  # does not stop delivery to others
    bus.publish()
    unsubscribe()
    bus.publish()
    assert calls == ["x"]
    assert type(build_bus(None)) is ConfigBus
    assert isinstance(build_bus("redis://localhost:6379/0"), RedisConfigBus)


class FakeSyncRedis:
    def __init__(self, fail: bool = False) -> None:
        self.published: list[tuple[str, bytes]] = []
        self.fail = fail

    def publish(self, channel: str, message: bytes) -> None:
        if self.fail:
            raise ConnectionError("down")
        self.published.append((channel, message))


class FakePubSub:
    def __init__(self, messages: Sequence[dict[str, Any]]) -> None:
        self.messages = messages
        self.channels: list[str] = []

    async def subscribe(self, channel: str) -> None:
        self.channels.append(channel)

    async def listen(self) -> AsyncIterator[dict[str, Any]]:
        for m in self.messages:
            yield m
        await asyncio.sleep(3600)


class FakeAsyncRedis:
    def __init__(self, pubsub: FakePubSub | None) -> None:
        self._pubsub = pubsub
        self.closed = False

    def pubsub(self) -> FakePubSub:
        if self._pubsub is None:
            raise ConnectionError("down")
        return self._pubsub

    async def aclose(self) -> None:
        self.closed = True


def test_redis_bus_publishes_locally_and_to_redis() -> None:
    sync = FakeSyncRedis()
    bus = RedisConfigBus("redis://x", sync_client=sync)
    calls: list[int] = []
    bus.subscribe(lambda: calls.append(1))
    bus.publish()
    assert sync.published == [("apiedge:config", b"reload")]
    assert calls == [1]
    # Redis down: the change still reaches local subscribers and nothing is raised.
    down = RedisConfigBus("redis://x", sync_client=FakeSyncRedis(fail=True))
    down.subscribe(lambda: calls.append(2))
    down.publish()
    assert calls == [1, 2]


async def test_redis_listener_reloads_on_messages_and_reconnects() -> None:
    pubsub = FakePubSub([{"type": "subscribe"}, {"type": "message", "data": b"reload"}])
    clients = [FakeAsyncRedis(None), FakeAsyncRedis(pubsub)]
    made: list[FakeAsyncRedis] = []

    def factory() -> FakeAsyncRedis:
        made.append(clients.pop(0))
        return made[-1]

    bus = RedisConfigBus("redis://x", async_client_factory=factory, retry_seconds=0.01)
    calls: list[int] = []
    bus.subscribe(lambda: calls.append(1))
    task = asyncio.create_task(bus.run_listener())
    for _ in range(200):
        if len(calls) >= 2:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert calls == [1, 1]  # once on (re)subscribe, once for the message
    assert pubsub.channels == ["apiedge:config"]
    assert all(c.closed for c in made)


def test_change_notifier(tmp_path: Path) -> None:
    url = f"sqlite:///{(tmp_path / 'n.db').as_posix()}"
    run_migrations(url)
    engine = make_engine(url)
    factory = make_session_factory(engine)
    bus = ConfigBus()
    events: list[int] = []
    bus.subscribe(lambda: events.append(1))
    install_change_notifier(factory, bus)
    install_change_notifier(factory, bus)  # idempotent
    with factory() as s:
        t = Tenant(slug="t", name="T")
        s.add(t)
        s.commit()
        assert events == [1]
        s.add(User(username="u", password_hash="x", tenant_id=t.id))
        s.commit()  # users do not affect routing
        assert events == [1]
        s.add(Product(tenant_id=t.id, name="P"))
        s.flush()
        s.rollback()
        assert events == [1]
        s.add(Product(tenant_id=t.id, name="P"))
        s.commit()
        assert events == [1, 1]
    engine.dispose()


async def test_connect_time_resolution() -> None:
    policy = SsrfPolicy.from_strings(allow_cidrs=["127.0.0.1/32"])

    async def resolver(host: str, port: int) -> Sequence[str]:
        return {"ok": ["127.0.0.1"], "bad": ["127.0.0.1", "192.168.1.1"]}.get(host, [])

    assert await resolve_checked_async("ok", 80, policy, resolver) == ("127.0.0.1",)
    assert await resolve_checked_async("[::ffff:127.0.0.1]", 80, policy) == ("::ffff:7f00:1",)
    for host in ("bad", "none", "", "2130706433", "169.254.169.254"):
        with pytest.raises(SsrfError):
            await resolve_checked_async(host, 80, policy, resolver)
    ports = SsrfPolicy.from_strings(allow_cidrs=["127.0.0.1/32"], allowed_ports=[443])
    with pytest.raises(SsrfError):
        await resolve_checked_async("ok", 80, ports, resolver)
