"""State helpers for sliding-window event analysis."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta

from app.models import WindowsSecurityEvent


class SlidingEventWindow:
    """Track recent events per key within a fixed time window."""

    def __init__(self, window_seconds: int) -> None:
        self._window = timedelta(seconds=window_seconds)
        self._storage: dict[str, deque[WindowsSecurityEvent]] = defaultdict(deque)

    def append(self, key: str, event: WindowsSecurityEvent) -> list[WindowsSecurityEvent]:
        bucket = self._storage[key]
        bucket.append(event)
        self._prune(key, event.timestamp)
        return list(bucket)

    def get(self, key: str, reference_time: datetime) -> list[WindowsSecurityEvent]:
        self._prune(key, reference_time)
        return list(self._storage.get(key, deque()))

    def _prune(self, key: str, reference_time: datetime) -> None:
        threshold = reference_time - self._window
        bucket = self._storage.get(key)
        if not bucket:
            return
        while bucket and bucket[0].timestamp < threshold:
            bucket.popleft()
        if not bucket:
            self._storage.pop(key, None)

