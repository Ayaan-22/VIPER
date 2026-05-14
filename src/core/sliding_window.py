"""
sliding_window.py
-----------------
Thread-safe sliding window counter used by all detectors.
Stores timestamped events and exposes count/rate queries
over a configurable lookback period.
"""

import time
import threading
from collections import deque
from typing import Any, Optional


class SlidingWindow:
    """
    A time-based sliding window that tracks events within
    a rolling time range.  All operations are O(n) worst-case
    but amortised O(1) for steady-state traffic because stale
    entries are pruned lazily on every access.
    """

    def __init__(self, window_seconds: float):
        self.window_seconds = window_seconds
        self._events: deque = deque()          # deque of (timestamp, value)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add(self, value: Any = 1, ts: Optional[float] = None) -> None:
        """Record a new event (optionally with an explicit timestamp)."""
        ts = ts or time.monotonic()
        with self._lock:
            self._events.append((ts, value))
            self._prune(ts)

    def count(self) -> int:
        """Return the number of events in the current window."""
        with self._lock:
            self._prune(time.monotonic())
            return len(self._events)

    def sum(self) -> float:
        """Return the sum of event values in the current window."""
        with self._lock:
            self._prune(time.monotonic())
            return sum(v for _, v in self._events)

    def rate(self) -> float:
        """Return events per second over the current window."""
        with self._lock:
            now = time.monotonic()
            self._prune(now)
            if not self._events:
                return 0.0
            # Use the window_seconds for the time denominator instead of instantaneous 
            # elapsed time to prevent extreme rate spikes from OS packet buffering bursts.
            return len(self._events) / max(self.window_seconds, 1e-9)

    def unique_values(self) -> set:
        """Return the set of distinct values seen in the current window."""
        with self._lock:
            self._prune(time.monotonic())
            return {v for _, v in self._events}

    def clear(self) -> None:
        with self._lock:
            self._events.clear()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _prune(self, now: float) -> None:
        """Remove events older than the window boundary (lock must be held)."""
        cutoff = now - self.window_seconds
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()


class SlidingWindowDict:
    """
    A defaultdict-like mapping of key → SlidingWindow.
    Creates windows on first access and cleans up stale keys
    periodically to avoid unbounded memory growth.
    """

    def __init__(self, window_seconds: float, cleanup_interval: float = 60.0):
        self.window_seconds = window_seconds
        self.cleanup_interval = cleanup_interval
        self._windows: dict = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.monotonic()

    def add(self, key: Any, value: Any = 1) -> None:
        self._get_or_create(key).add(value)

    def count(self, key: Any) -> int:
        return self._get_or_create(key).count()

    def rate(self, key: Any) -> float:
        return self._get_or_create(key).rate()

    def unique_values(self, key: Any) -> set:
        return self._get_or_create(key).unique_values()

    def keys(self):
        with self._lock:
            return list(self._windows.keys())

    def _get_or_create(self, key: Any) -> SlidingWindow:
        with self._lock:
            self._maybe_cleanup()
            if key not in self._windows:
                self._windows[key] = SlidingWindow(self.window_seconds)
            return self._windows[key]

    def _maybe_cleanup(self) -> None:
        """Evict windows that have been empty for a full window period."""
        now = time.monotonic()
        if now - self._last_cleanup < self.cleanup_interval:
            return
        self._last_cleanup = now
        stale = [k for k, w in self._windows.items() if w.count() == 0]
        for k in stale:
            del self._windows[k]
