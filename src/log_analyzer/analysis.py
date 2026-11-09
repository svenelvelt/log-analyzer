"""Run the analyzers over log sources. This is the tool without its command line."""

import io
import logging
import math
import os
import sys
from collections.abc import Callable, Iterable, Iterator, Mapping
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from typing import Any

from log_analyzer.analyzers import ANALYZERS, Analyzer, parameter
from log_analyzer.errors import InputError, ParseError
from log_analyzer.models import LogRecord
from log_analyzer.parsers import PARSERS
from log_analyzer.reader import Parser, ReadStats, read_records, read_stream

log = logging.getLogger(__name__)

TOOL = f"log-analyzer {version('log-analyzer')}"

Source = str | os.PathLike[str] | io.BufferedReader


def analyze(
    sources: Iterable[Source],
    operations: Iterable[str] | Mapping[str, Any] | None = None,
    *,
    input_format: str = "squid",
) -> dict[str, Any]:
    """Analyze log sources and return the report as a dictionary.

    A source is a file path, a binary stream (plain or gzipped), or the string "-"
    for stdin; a Path named "-" is a file. `operations` are analyzer names such as
    "mfip", all of them by default, or a mapping from name to the operation's value,
    e.g. {"mfip": 5}; None there means its default. Results come in a fixed order.
    `input_format` is a name from PARSERS, or "auto" to detect it per source.

    Every source is read once. One that can't be read is logged and recorded with
    its error in meta["files"] instead of raising, and records read before the
    error (e.g. from a truncated gzip) stay in the results.

    Raises ValueError for an unknown operation or input format, or an invalid value.
    """
    requested = _requested(operations)
    if input_format != "auto" and input_format not in PARSERS:
        raise ValueError(f"unknown input format {input_format!r}")
    analyzers = [
        _create(cls, requested[name]) for name, cls in ANALYZERS.items() if name in requested
    ]

    time_range = _TimeRange()
    files = [_read(source, input_format, analyzers, time_range) for source in sources]
    meta = {
        "tool": TOOL,
        "files": files,
        "lines": sum(f["lines"] for f in files),
        "events": sum(f["events"] for f in files),
        "skipped": sum(f["skipped"] for f in files),
        "first": _iso(time_range.earliest),
        "last": _iso(time_range.latest),
    }
    return {"meta": meta, "results": {a.name: a.result() for a in analyzers}}


def _requested(operations: Iterable[str] | Mapping[str, Any] | None) -> dict[str, Any]:
    """The requested operations as {name: value}, where None means the default value."""
    if operations is None:
        requested: dict[str, Any] = dict.fromkeys(ANALYZERS)
    elif isinstance(operations, Mapping):
        requested = dict(operations)
    else:
        requested = dict.fromkeys(operations)
    if unknown := requested.keys() - ANALYZERS.keys():
        raise ValueError(f"unknown operation {', '.join(map(repr, sorted(unknown)))}")
    return requested


class _TimeRange:
    """The earliest and latest event over all sources, for meta's first and last."""

    def __init__(self) -> None:
        self.earliest = math.inf
        self.latest = -math.inf

    def update(self, record: LogRecord) -> None:
        self.earliest = min(self.earliest, record.timestamp)
        self.latest = max(self.latest, record.timestamp)


def _read(
    source: Source, input_format: str, analyzers: list[Analyzer], time_range: _TimeRange
) -> dict[str, Any]:
    """Feed every record of `source` to the analyzers and return its entry for meta["files"].

    A source that can't be read is logged and gets its error in the entry instead of
    raising. Records read before the error (e.g. from a truncated gzip) still count.
    """
    stats = ReadStats()
    parse = _Detect() if input_format == "auto" else PARSERS[input_format]
    name, records = _open(source, parse, stats)
    error = None
    try:
        for record in records:
            time_range.update(record)
            for analyzer in analyzers:
                analyzer.update(record)
    except InputError as e:
        log.error("%s", e)
        error = e.reason
    return {
        "path": name,
        "format": parse.format if isinstance(parse, _Detect) else input_format,
        "lines": stats.lines,
        "events": stats.records,
        "skipped": stats.skipped,
        "error": error,
    }


def _create(cls: type[Analyzer], value: Any) -> Analyzer:
    """Instantiate an analyzer, passing `value` if the operation was given one."""
    if value is None:
        return cls()
    if parameter(cls) is None:
        raise ValueError(f"operation {cls.name!r} takes no value")
    factory: Callable[..., Analyzer] = cls  # the Analyzer protocol says nothing about __init__
    try:
        return factory(value)
    except ValueError as e:
        raise ValueError(f"invalid value for {cls.name!r}: {e}") from e


class _Detect:
    """Parser for input_format="auto", used for one source.

    The first line that one of the parsers accepts decides the format, and the
    rest of the source is read with that parser.
    """

    def __init__(self) -> None:
        self.format: str | None = None

    def __call__(self, line: str) -> LogRecord:
        if self.format:
            return PARSERS[self.format](line)
        for name, parse in PARSERS.items():
            try:
                record = parse(line)
            except ParseError:
                continue
            self.format = name
            return record
        raise ParseError("not in any known format")


def _open(source: Source, parse: Parser, stats: ReadStats) -> tuple[str, Iterator[LogRecord]]:
    """Return a display name for `source` and its records, read lazily."""
    if isinstance(source, io.BufferedReader):
        # sys.stdin.buffer is named "<stdin>"; in-memory streams have no name
        name = getattr(source, "name", None)
        name = name if isinstance(name, str) else "<stream>"
        return name, read_stream(source, name, parse, stats)
    if source == "-":
        return "<stdin>", _read_stdin(parse, stats)
    path = Path(source)
    return str(path), read_records(path, parse, stats)


def _read_stdin(parse: Parser, stats: ReadStats) -> Iterator[LogRecord]:
    # Normally a BufferedReader, but stdin can be closed (None) or replaced by an
    # object without a byte buffer. As a generator, this raises inside the caller's
    # loop, where InputError is reported like any other unreadable input.
    stdin = getattr(sys.stdin, "buffer", None)
    if not isinstance(stdin, io.BufferedReader):
        raise InputError("<stdin>", "stdin is not readable")
    yield from read_stream(stdin, "<stdin>", parse, stats)


def _iso(timestamp: float) -> str | None:
    if not math.isfinite(timestamp):
        return None
    dt = datetime.fromtimestamp(timestamp, UTC)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")
