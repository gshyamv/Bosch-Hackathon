"""A min-heap priority queue (heapq) shared by the agents that decide what is handled first.

Used by:  Detection     -> which suspicious findings go to the triage agent (highest risk first, up to the cap)
          Prioritizer   -> the order of the prioritised risks (urgent first, then score)
          Remediation   -> which risk clusters get a fix proposal first (P0 before P1 ..., urgent, score)
Lower key = higher priority. Ties keep insertion order, so results are deterministic.
"""
from __future__ import annotations

import heapq
import itertools
from typing import Callable, Generic, Iterable, TypeVar

T = TypeVar("T")


class PriorityQueue(Generic[T]):
    def __init__(self, items: Iterable[T] = (), key: Callable[[T], tuple] = lambda x: (0,)):
        self._key, self._n = key, itertools.count()
        self._heap = [(key(x), next(self._n), x) for x in items]
        heapq.heapify(self._heap)

    def push(self, item: T) -> None:
        heapq.heappush(self._heap, (self._key(item), next(self._n), item))

    def pop(self) -> T:
        return heapq.heappop(self._heap)[2]

    def take(self, n: int | None = None) -> list[T]:
        """Pop up to n items (all when n is None) in priority order."""
        out = []
        while self._heap and (n is None or len(out) < n):
            out.append(self.pop())
        return out

    def __len__(self) -> int:
        return len(self._heap)
