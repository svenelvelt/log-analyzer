"""Streaming analyzers. Each one sees every record once and produces a JSON-serializable result."""

import inspect
import ipaddress
import math
from abc import ABC, abstractmethod
from collections import Counter
from typing import Any, NamedTuple, Protocol, TypedDict, get_type_hints

from log_analyzer.models import LogRecord


class Analyzer(Protocol):
    name: str

    def update(self, record: LogRecord) -> None:
        """Take one record into account. Called once per record, in input order."""

    def result(self) -> object:
        """Return the result, as something JSON-serializable."""


class ClientCount(TypedDict):
    ip: str
    count: int


class RankingResult(TypedDict):
    n: int
    clients: list[ClientCount]


class _Ranking(ABC):
    """Counts requests per client IP and reports the N that come first.

    Clients tied with the Nth are included too, so the list can be longer than N.
    Subclasses decide the order.
    """

    name: str

    def __init__(self, n: int = 1) -> None:
        if n < 1:
            raise ValueError(f"n must be at least 1, got {n}")
        self._n = n
        self._counts: Counter[str] = Counter()

    def update(self, record: LogRecord) -> None:
        self._counts[record.client_ip] += 1

    def result(self) -> RankingResult:
        ranked = sorted(
            self._counts.items(), key=lambda item: (self._rank(item[1]), _address_order(item[0]))
        )
        if len(ranked) > self._n:
            cutoff = self._rank(ranked[self._n - 1][1])
            ranked = [item for item in ranked if self._rank(item[1]) <= cutoff]
        return {"n": self._n, "clients": [{"ip": ip, "count": count} for ip, count in ranked]}

    @abstractmethod
    def _rank(self, count: int) -> int:
        """Sort key for a request count: lower comes first."""


class MostFrequentIp(_Ranking):
    """The N client IPs with the most requests, 1 by default. Ties at the Nth are included."""

    name = "mfip"

    def _rank(self, count: int) -> int:
        return -count


class LeastFrequentIp(_Ranking):
    """The N client IPs with the fewest requests, 1 by default. Ties at the Nth are included."""

    name = "lfip"

    def _rank(self, count: int) -> int:
        return count


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


class Parameter(NamedTuple):
    name: str
    type: type
    default: Any


def parameter(cls: type[Analyzer]) -> Parameter | None:
    """The value an operation takes: its constructor's argument, if it has one.

    MostFrequentIp(n: int = 1) takes an int called n, 1 by default, which the CLI
    offers as --mfip [N]. So giving an operation a value only means giving its
    constructor an argument with a type hint and a default.
    """
    arguments = list(inspect.signature(cls).parameters.values())
    if not arguments:
        return None
    (argument,) = arguments  # one value per operation
    return Parameter(argument.name, get_type_hints(cls.__init__)[argument.name], argument.default)


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
