# Copyright 2026 OpenEdge Labs
# SPDX-License-Identifier: Apache-2.0
"""Shared state behind the ``rate-limit`` and ``cache`` policies (T-008, ADR 0009).

Both live for the whole gateway process (they survive configuration reloads) and are bounded:

* :class:`MemoryLimiter` - fixed-window counters in process memory, at most ``max_keys``
  windows (least recently used evicted first);
* :class:`RedisLimiter` - the same counters in Redis (``INCR`` plus ``EXPIRE``), shared by every
  gateway process. When Redis fails the limiter falls back to its in-process counters and logs a
  warning (at most once a minute), so an outage degrades to per-process limits instead of
  rejecting or letting through everything;
* :class:`ResponseCache` - an LRU of complete responses capped by total bytes.

Keys are hashed, so client-controlled values (IP addresses, consumer names) never become Redis
key syntax.
"""

from __future__ import annotations

import hashlib
import logging
import math
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Protocol

log = logging.getLogger("apiedge.gateway.policies")


@dataclass(frozen=True)
class Window:
    count: int  # requests in the current window, including this one
    reset_after: float  # seconds until the window ends


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


class Limiter(Protocol):
    async def hit(self, key: str, window_seconds: int) -> Window: ...


class MemoryLimiter:
    def __init__(self, max_keys: int = 100_000, clock: Any = time.time) -> None:
        self._max = max_keys
        self._clock = clock
        self._windows: OrderedDict[str, tuple[int, int]] = OrderedDict()
        self._lock = threading.Lock()

    def hit_sync(self, key: str, window_seconds: int) -> Window:
        now = self._clock()
        index = int(now // window_seconds)
        name = _hash(key)
        with self._lock:
            start, count = self._windows.pop(name, (index, 0))
            if start != index:
                start, count = index, 0
            count += 1
            self._windows[name] = (start, count)
            while len(self._windows) > self._max:
                self._windows.popitem(last=False)
        return Window(count, (index + 1) * window_seconds - now)

    async def hit(self, key: str, window_seconds: int) -> Window:
        return self.hit_sync(key, window_seconds)


class RedisLimiter:
    """Fixed windows in Redis; falls back to process memory while Redis is unavailable."""

    def __init__(self, redis: Any, fallback: MemoryLimiter | None = None) -> None:
        self._redis = redis
        self._fallback = fallback or MemoryLimiter()
        self._warned_at = 0.0

    async def hit(self, key: str, window_seconds: int) -> Window:
        now = time.time()
        index = int(now // window_seconds)
        name = f"apiedge:rl:{_hash(key)}:{window_seconds}:{index}"
        try:
            count = int(await self._redis.incr(name))
            if count == 1:
                # The window index is part of the key: a missed EXPIRE only leaks one key.
                await self._redis.expire(name, window_seconds + 1)
        except Exception:  # redis errors, timeouts, connection loss
            if now - self._warned_at > 60:
                self._warned_at = now
                log.warning("Redis rate limiting unavailable; using per-process counters")
            return await self._fallback.hit(key, window_seconds)
        return Window(count, (index + 1) * window_seconds - now)


@dataclass
class CachedResponse:
    status: int
    headers: list[tuple[str, str]]
    body: bytes
    stored_at: float
    expires_at: float

    @property
    def size(self) -> int:
        return len(self.body) + sum(len(k) + len(v) for k, v in self.headers) + 64

    def age(self, now: float) -> int:
        return max(0, math.floor(now - self.stored_at))


class ResponseCache:
    """LRU response store capped by total size (``max_bytes`` = 0 disables caching)."""

    def __init__(self, max_bytes: int, clock: Any = time.time) -> None:
        self.max_bytes = max_bytes
        self._clock = clock
        self._entries: OrderedDict[str, CachedResponse] = OrderedDict()
        self._size = 0
        self._lock = threading.Lock()

    @property
    def size(self) -> int:
        return self._size

    def get(self, key: str) -> CachedResponse | None:
        name = _hash(key)
        with self._lock:
            entry = self._entries.get(name)
            if entry is None:
                return None
            if entry.expires_at <= self._clock():
                self._drop(name)
                return None
            self._entries.move_to_end(name)
            return entry

    def put(self, key: str, entry: CachedResponse) -> bool:
        if entry.size > self.max_bytes:
            return False
        name = _hash(key)
        with self._lock:
            if name in self._entries:
                self._drop(name)
            self._entries[name] = entry
            self._size += entry.size
            while self._size > self.max_bytes and self._entries:
                self._drop(next(iter(self._entries)))
        return True

    def _drop(self, name: str) -> None:
        entry = self._entries.pop(name)
        self._size -= entry.size
