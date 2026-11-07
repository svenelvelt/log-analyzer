"""Stream parsed records from plain or gzip-compressed log files."""

import gzip
import logging
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from log_analyzer.errors import ParseError
from log_analyzer.models import LogRecord

log = logging.getLogger(__name__)

GZIP_MAGIC = b"\x1f\x8b"

Parser = Callable[[str], LogRecord]


@dataclass
class ReadStats:
    lines: int = 0
    records: int = 0
    skipped: int = 0


def read_records(path: Path, parse: Parser, stats: ReadStats) -> Iterator[LogRecord]:
    """Yield a record for every valid line in `path`, updating `stats` as it goes.

    Malformed lines are skipped. Each one is logged at DEBUG, with a WARNING
    summary per file.
    """
    with _open(path) as f:
        for lineno, line in enumerate(f, 1):
            stats.lines += 1
            try:
                record = parse(line)
            except ParseError as e:
                stats.skipped += 1
                log.debug("%s:%d: %s", path, lineno, e)
                continue
            stats.records += 1
            yield record

    if stats.skipped:
        log.warning("%s: skipped %d of %d lines", path, stats.skipped, stats.lines)


def _open(path: Path) -> TextIO:
    """Open `path` as text, decompressing if it starts with the gzip magic bytes."""
    with path.open("rb") as f:
        is_gzip = f.read(2) == GZIP_MAGIC
    if is_gzip:
        return gzip.open(path, "rt", encoding="utf-8")
    return path.open(encoding="utf-8")
