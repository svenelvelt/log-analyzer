"""Run the analyzers over log sources. This is the tool without its command line."""

import io
import logging
import math
import os
import sys
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from typing import Any

from log_analyzer.analyzers import ANALYZERS
from log_analyzer.errors import InputError
from log_analyzer.models import LogRecord
from log_analyzer.parsers import PARSERS
from log_analyzer.reader import Parser, ReadStats, read_records, read_stream

log = logging.getLogger(__name__)

TOOL = f"log-analyzer {version('log-analyzer')}"

Source = str | os.PathLike[str] | io.BufferedReader


def analyze(
    sources: Iterable[Source],
    operations: Iterable[str] | None = None,
    *,
    input_format: str = "squid",
) -> dict[str, Any]:
    """Analyze log sources and return the report as a dictionary.

    A source is a file path, a binary stream (plain or gzipped), or the string "-"
    for stdin; a Path named "-" is a file. `operations` are analyzer names such as
    "mfip", all of them by default. Results come in a fixed order.

    Every source is read once. One that can't be read is logged and recorded with
    its error in meta["files"] instead of raising, and records read before the
    error (e.g. from a truncated gzip) stay in the results.

    Raises ValueError for an unknown operation or input format.
    """
    requested = set(ANALYZERS if operations is None else operations)
    if unknown := requested - ANALYZERS.keys():
        raise ValueError(f"unknown operation {', '.join(map(repr, sorted(unknown)))}")
    if input_format not in PARSERS:
        raise ValueError(f"unknown input format {input_format!r}")
    parse = PARSERS[input_format]
    analyzers = [cls() for name, cls in ANALYZERS.items() if name in requested]

    read: list[tuple[str, ReadStats, str | None]] = []
    earliest, latest = math.inf, -math.inf

    for source in sources:
        stats = ReadStats()
        error = None
        name, records = _open(source, parse, stats)
        try:
            for record in records:
                earliest = min(earliest, record.timestamp)
                latest = max(latest, record.timestamp)
                for analyzer in analyzers:
                    analyzer.update(record)
        except InputError as e:
            log.error("%s", e)
            error = e.reason
        read.append((name, stats, error))

    meta = {
        "tool": TOOL,
        "files": [
            {
                "path": name,
                "lines": s.lines,
                "events": s.records,
                "skipped": s.skipped,
                "error": err,
            }
            for name, s, err in read
        ],
        "lines": sum(s.lines for _, s, _ in read),
        "events": sum(s.records for _, s, _ in read),
        "skipped": sum(s.skipped for _, s, _ in read),
        "first": _iso(earliest),
        "last": _iso(latest),
    }
    return {"meta": meta, "results": {a.name: a.result() for a in analyzers}}


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
