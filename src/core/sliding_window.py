"""Bounded event-time windows. Rates use the configured full interval."""
from __future__ import annotations

import math
import threading
import time
from collections import Counter, OrderedDict, deque


class SlidingWindow:
    def __init__(self, window_seconds: float, max_events: int = 8192):
        if not math.isfinite(window_seconds) or window_seconds <= 0 or max_events < 1:
            raise ValueError("window_seconds and max_events must be positive")
        self.window_seconds = window_seconds
        self.max_events = max_events
        self._events = deque()
        self._values = Counter()
        self._lock = threading.RLock()
        self.discarded = 0
        self.late = 0
        self._latest = -math.inf

    def add(self, value=1, ts=None):
        with self._lock:
            now = time.monotonic() if ts is None else ts
            if now < self._latest:
                self.late += 1
                return False
            self._latest = now
            self._prune(now)
            if len(self._events) >= self.max_events:
                self.discarded += 1
                return False
            self._events.append((now, value))
            self._values[value] += 1
            return True

    def count(self, ts=None):
        with self._lock:
            self._prune(time.monotonic() if ts is None else ts)
            return len(self._events)

    def sum(self, ts=None):
        with self._lock:
            self.count(ts)
            return sum(v for _, v in self._events)

    def rate(self, ts=None):
        return self.count(ts) / self.window_seconds

    def unique_values(self, ts=None):
        with self._lock:
            self.count(ts)
            return set(self._values)

    def unique_count(self, ts=None):
        with self._lock:
            self.count(ts)
            return len(self._values)

    def clear(self):
        with self._lock:
            self._events.clear()
            self._values.clear()

    def _prune(self, now):
        while self._events and self._events[0][0] < now - self.window_seconds:
            _, value = self._events.popleft()
            self._values[value] -= 1
            if not self._values[value]:
                del self._values[value]


class SlidingWindowDict:
    """LRU-bounded keys and a global event budget; losses are observable."""
    def __init__(self, window_seconds, cleanup_interval=60.0, max_keys=2048,
                 max_events=65536, max_events_per_key=8192):
        if max_keys < 1 or max_events < 1 or not math.isfinite(window_seconds) or window_seconds <= 0:
            raise ValueError("state budgets must be positive")
        self.window_seconds = window_seconds
        self.cleanup_interval = cleanup_interval
        self.max_keys = max_keys
        self.max_events = max_events
        self.max_events_per_key = max_events_per_key
        self._windows = OrderedDict()
        self._touched = {}
        self._lock = threading.RLock()
        self._total = 0
        self._last_cleanup = -math.inf
        self._evicted = 0
        self._discarded = 0

    def _window(self, key, now):
        wall = time.monotonic()
        if wall - self._last_cleanup >= self.cleanup_interval:
            self._last_cleanup = wall
            for old, win in list(self._windows.items()):
                # A different source's newer event timestamp must never expire
                # this source's queued history. Idle expiry uses processing time.
                if wall - self._touched.get(old, wall) > max(60, self.window_seconds * 2):
                    self._total -= len(win._events)
                    del self._windows[old]
                    self._touched.pop(old, None)
                    self._evicted += 1
        if key not in self._windows:
            if len(self._windows) >= self.max_keys:
                victim_key, victim = self._windows.popitem(last=False)
                self._touched.pop(victim_key, None)
                self._total -= len(victim._events)
                self._evicted += 1
            self._windows[key] = SlidingWindow(self.window_seconds, self.max_events_per_key)
        win = self._windows[key]
        self._windows.move_to_end(key)
        self._touched[key] = wall
        self._total -= len(win._events) - win.count(now)
        return win

    def add(self, key, value=1, ts=None):
        with self._lock:
            now = time.monotonic() if ts is None else ts
            win = self._window(key, now)
            if self._total >= self.max_events:
                for other in self._windows.values():
                    self._total -= len(other._events) - other.count(other._latest)
                if self._total >= self.max_events:
                    self._discarded += 1
                    return False
            accepted = win.add(value, now)
            self._total += int(accepted)
            self._discarded += int(not accepted)
            return accepted

    def _query(self, key, method, ts):
        now = time.monotonic() if ts is None else ts
        with self._lock:
            win = self._windows.get(key)
            if win is None:
                return set() if method == "unique_values" else 0
            before = len(win._events)
            value = getattr(win, method)(now)
            self._total -= before - len(win._events)
            return value

    def count(self, key, ts=None):
        return self._query(key, "count", ts)

    def rate(self, key, ts=None):
        return self.count(key, ts) / self.window_seconds

    def unique_values(self, key, ts=None):
        return self._query(key, "unique_values", ts)

    def unique_count(self, key, ts=None):
        return self._query(key, "unique_count", ts)

    def keys(self):
        with self._lock:
            return list(self._windows)

    @property
    def stats(self):
        with self._lock:
            return {"keys": len(self._windows), "events": self._total,
                    "evicted_keys": self._evicted, "discarded_events": self._discarded}


class AlertThrottle:
    """Atomic reservation, bounded cardinality, and nonextending expiry."""
    def __init__(self, window_seconds, max_keys=8192):
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._entries = OrderedDict()
        self._lock = threading.Lock()
        self.evictions = 0

    def acquire(self, key, ts=None):
        now = time.monotonic() if ts is None else ts
        with self._lock:
            previous = self._entries.get(key)
            if previous is not None and now - previous <= self.window_seconds:
                return False
            if key not in self._entries and len(self._entries) >= self.max_keys:
                self._entries.popitem(last=False)
                self.evictions += 1
            self._entries[key] = now
            self._entries.move_to_end(key)
            return True

    def keys(self):
        with self._lock:
            return list(self._entries)
