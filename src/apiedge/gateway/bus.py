# Copyright 2026 Alingan Patra
# SPDX-License-Identifier: Apache-2.0
"""Configuration change events for gateway hot reload (T-007, ADR 0007).

The admin API commits a change to an API, product or tenant; :func:`install_change_notifier`
sees the commit and calls :meth:`ConfigBus.publish`. Gateways subscribe and reload their routing
snapshot, so no restart is needed after publishing.

* :class:`ConfigBus` delivers events inside one process (admin API and gateway started together
  by ``apiedge run``). This is the fallback when Redis is not configured.
* :class:`RedisConfigBus` also publishes to a Redis channel and listens to it, so gateways in
  other processes or on other hosts reload too.

Events carry no data: subscribers always re-read the configuration from the database, so a lost
or duplicated event cannot leave a gateway with a wrong configuration (and the periodic reload
catches anything missed).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import threading
from collections.abc import Callable, Iterable
from typing import Any

from sqlalchemy import event
from sqlalchemy.orm import Session, sessionmaker

from apiedge.db.models import Api, ApiRoute, ApiUpstream, Product, Tenant

log = logging.getLogger("apiedge.gateway")

CHANNEL = "apiedge:config"
Listener = Callable[[], None]


class ConfigBus:
    """In-process change events. ``publish`` may be called from any thread."""

    def __init__(self) -> None:
        self._listeners: list[Listener] = []
        self._lock = threading.Lock()

    def subscribe(self, listener: Listener) -> Callable[[], None]:
        with self._lock:
            self._listeners.append(listener)

        def unsubscribe() -> None:
            with self._lock:
                if listener in self._listeners:
                    self._listeners.remove(listener)

        return unsubscribe

    def notify_local(self) -> None:
        with self._lock:
            listeners = list(self._listeners)
        for listener in listeners:
            try:
                listener()
            except Exception:  # a broken subscriber must not break the admin request
                log.exception("config change listener failed")

    def publish(self) -> None:
        self.notify_local()

    async def run_listener(self) -> None:
        """Receive events from other processes (nothing to do in-process)."""
        return None


class RedisConfigBus(ConfigBus):
    """Change events through Redis pub/sub, plus immediate in-process delivery."""

    def __init__(
        self,
        url: str,
        *,
        channel: str = CHANNEL,
        sync_client: Any | None = None,
        async_client_factory: Callable[[], Any] | None = None,
        retry_seconds: float = 2.0,
    ) -> None:
        super().__init__()
        self._url = url
        self._channel = channel
        self._sync_client = sync_client
        self._async_client_factory = async_client_factory
        self._retry_seconds = retry_seconds

    def _client(self) -> Any:
        if self._sync_client is None:
            import redis

            self._sync_client = redis.Redis.from_url(
                self._url, socket_timeout=2, socket_connect_timeout=2
            )
        return self._sync_client

    def publish(self) -> None:
        self.notify_local()
        try:
            self._client().publish(self._channel, b"reload")
        except Exception:  # the change is committed; the periodic reload catches up
            log.warning("could not publish a config change event to Redis", exc_info=True)

    def _async_client(self) -> Any:
        if self._async_client_factory is not None:
            return self._async_client_factory()
        import redis.asyncio

        return redis.asyncio.Redis.from_url(self._url, socket_connect_timeout=2)

    async def run_listener(self) -> None:
        """Subscribe until cancelled, reconnecting after errors."""
        while True:
            client = self._async_client()
            try:
                pubsub = client.pubsub()
                await pubsub.subscribe(self._channel)
                # Anything published while we were not subscribed is unknown: reload once.
                self.notify_local()
                async for message in pubsub.listen():
                    if message.get("type") == "message":
                        self.notify_local()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.warning("Redis config channel unavailable; retrying", exc_info=True)
            finally:
                with contextlib.suppress(Exception):  # best-effort close
                    await client.aclose()
            await asyncio.sleep(self._retry_seconds)


def build_bus(redis_url: str | None) -> ConfigBus:
    return RedisConfigBus(redis_url) if redis_url else ConfigBus()


WATCHED = (Tenant, Product, Api, ApiUpstream, ApiRoute)
_CHANGED = "apiedge_gateway_config_changed"
_INSTALLED = "_apiedge_change_notifier"


def _touches_config(objects: Iterable[object]) -> bool:
    return any(isinstance(obj, WATCHED) for obj in objects)


def install_change_notifier(factory: sessionmaker[Session], bus: ConfigBus) -> None:
    """Publish a change event after every commit that wrote gateway-relevant rows."""
    if vars(factory).get(_INSTALLED):
        return

    def after_flush(session: Session, _ctx: Any) -> None:
        if _touches_config([*session.new, *session.dirty, *session.deleted]):
            session.info[_CHANGED] = True

    def after_commit(session: Session) -> None:
        if session.info.pop(_CHANGED, False):
            bus.publish()

    def after_rollback(session: Session) -> None:
        session.info.pop(_CHANGED, None)

    event.listen(factory, "after_flush", after_flush)
    event.listen(factory, "after_commit", after_commit)
    event.listen(factory, "after_rollback", after_rollback)
    setattr(factory, _INSTALLED, True)
