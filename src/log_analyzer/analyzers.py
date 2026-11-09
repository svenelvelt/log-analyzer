"""Streaming analyzers. Each one sees every record once and produces a JSON-serializable result."""

import ipaddress
import math
from abc import ABC, abstractmethod
from collections import Counter
from collections.abc import Iterable
from typing import Protocol, TypedDict

from log_analyzer.models import LogRecord


class Analyzer(Protocol):
    name: str

    def update(self, record: LogRecord) -> None:
        """Take one record into account. Called once per record, in input order."""

    def result(self) -> object:
        """Return the result, as something JSON-serializable."""


class IpResult(TypedDict):
    ips: list[str]
    count: int


class _IpFrequency(ABC):
    """Counts requests per client IP. Subclasses choose which count they report."""

    name: str

    def __init__(self) -> None:
        self._counts: Counter[str] = Counter()

    def update(self, record: LogRecord) -> None:
        self._counts[record.client_ip] += 1

    def result(self) -> IpResult:
        if not self._counts:
            return {"ips": [], "count": 0}
        target = self._select(self._counts.values())
        ips = [ip for ip, n in self._counts.items() if n == target]
        return {"ips": sorted(ips, key=_address_order), "count": target}

    @abstractmethod
    def _select(self, counts: Iterable[int]) -> int:
        """Pick the request count to report, from the counts of all IPs."""


class MostFrequentIp(_IpFrequency):
    """Client IP(s) with the most requests. All tied IPs are returned."""

    name = "mfip"

    def _select(self, counts: Iterable[int]) -> int:
        return max(counts)


class LeastFrequentIp(_IpFrequency):
    """Client IP(s) with the fewest requests. All tied IPs are returned."""

    name = "lfip"

    def _select(self, counts: Iterable[int]) -> int:
        return min(counts)


class EpsResult(TypedDict):
    average: float
    peak: int


class EventsPerSecond:
    """Average and peak events per second.

    The average is taken over the whole seconds from the earliest to the latest
    event, inclusive. The peak counts consecutive events in the same second, so
    it runs in constant memory but assumes input in time order, which is how
    Squid writes its log.
    """

    name = "eps"

    def __init__(self) -> None:
        self._events = 0
        self._earliest = math.inf
        self._latest = -math.inf
        self._peak = 0
        self._second: int | None = None
        self._run = 0

    def update(self, record: LogRecord) -> None:
        self._events += 1
        self._earliest = min(self._earliest, record.timestamp)
        self._latest = max(self._latest, record.timestamp)

        second = int(record.timestamp)
        if second == self._second:
            self._run += 1
        else:
            self._second, self._run = second, 1
        self._peak = max(self._peak, self._run)

    def result(self) -> EpsResult:
        if not self._events:
            return {"average": 0.0, "peak": 0}
        seconds = int(self._latest) - int(self._earliest) + 1
        return {"average": self._events / seconds, "peak": self._peak}


class BytesResult(TypedDict):
    total: int
    unknown: int


class TotalBytes:
    """Total response bytes delivered to clients.

    Squid logs -1 when the size is unknown. Those events are counted in
    `unknown` instead of the total, so the total is a lower bound.
    """

    name = "bytes"

    def __init__(self) -> None:
        self._total = 0
        self._unknown = 0

    def update(self, record: LogRecord) -> None:
        if record.response_size is None:
            self._unknown += 1
        else:
            self._total += record.response_size

    def result(self) -> BytesResult:
        return {"total": self._total, "unknown": self._unknown}


_ALL: tuple[type[Analyzer], ...] = (MostFrequentIp, LeastFrequentIp, EventsPerSecond, TotalBytes)

# Analyzers by name, in the order their results appear in the output.
ANALYZERS: dict[str, type[Analyzer]] = {cls.name: cls for cls in _ALL}


def _address_order(value: str) -> tuple[int, int, int, str]:
    """Sort key: IPv4 by address, then IPv6 by address, then anything else as text."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return (1, 0, 0, value)
    return (0, ip.version, int(ip), value)
