"""Streaming analyzers. Each one sees every record once and produces a JSON-serializable result."""

import ipaddress
from abc import ABC, abstractmethod
from collections import Counter
from collections.abc import Iterable
from typing import Protocol, TypedDict

from log_analyzer.models import LogRecord


class Analyzer(Protocol):
    name: str

    def update(self, record: LogRecord) -> None: ...

    def result(self) -> object: ...


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
    def _select(self, counts: Iterable[int]) -> int: ...


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


def _address_order(value: str) -> tuple[int, int, int, str]:
    """Sort key: IPv4 by address, then IPv6 by address, then anything else as text."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return (1, 0, 0, value)
    return (0, ip.version, int(ip), value)
