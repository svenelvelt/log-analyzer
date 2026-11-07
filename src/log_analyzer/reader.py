"""Stream parsed records from plain or gzip-compressed log files."""

import gzip
import io
import logging
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from log_analyzer.errors import ParseError
from log_analyzer.models import LogRecord

log = logging.getLogger(__name__)

GZIP_MAGIC = b"\x1f\x8b"
MAX_LINE_BYTES = 64 * 1024

Parser = Callable[[str], LogRecord]


@dataclass
class ReadStats:
    lines: int = 0
    records: int = 0
    skipped: int = 0


def read_records(
    path: Path,
    parse: Parser,
    stats: ReadStats,
    max_line_bytes: int = MAX_LINE_BYTES,
) -> Iterator[LogRecord]:
    """Yield a record for every valid line in `path`, updating `stats` as it goes.

    Malformed lines are skipped. Each one is logged at DEBUG, with a WARNING
    summary per file. Invalid UTF-8 is replaced with U+FFFD.
    """
    with _open(path) as f:
        for lineno, line in enumerate(_bounded_lines(f, max_line_bytes), 1):
            stats.lines += 1
            try:
                if line is None:
                    raise ParseError(f"line longer than {max_line_bytes} bytes")
                record = parse(line.decode("utf-8", errors="replace"))
            except ParseError as e:
                stats.skipped += 1
                log.debug("%s:%d: %s", path, lineno, e)
                continue
            stats.records += 1
            yield record

    if stats.skipped:
        log.warning("%s: skipped %d of %d lines", path, stats.skipped, stats.lines)


def _open(path: Path) -> io.BufferedIOBase:
    """Open `path` for binary reading, decompressing if it starts with the gzip magic bytes."""
    with path.open("rb") as f:
        is_gzip = f.read(2) == GZIP_MAGIC
    if is_gzip:
        return gzip.open(path, "rb")
    return path.open("rb")


def _bounded_lines(f: io.BufferedIOBase, max_bytes: int) -> Iterator[bytes | None]:
    """Yield lines of at most `max_bytes` (newline included), or None for longer ones.

    The rest of a long line is read in chunks and thrown away, so memory use
    stays bounded no matter what the file contains.
    """
    while line := f.readline(max_bytes + 1):
        if len(line) <= max_bytes:
            yield line
            continue
        while not line.endswith(b"\n") and (line := f.readline(max_bytes)):
            pass
        yield None
