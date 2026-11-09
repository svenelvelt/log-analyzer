"""Stream parsed records from plain or gzip-compressed log files and streams."""

import contextlib
import gzip
import io
import logging
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from log_analyzer.errors import InputError, ParseError
from log_analyzer.models import LogRecord

log = logging.getLogger(__name__)

GZIP_MAGIC = b"\x1f\x8b"
MAX_LINE_BYTES = 64 * 1024
# The report turns timestamps into dates, so whatever the format, a record must
# fall between 1970 and the last second a datetime can hold.
MAX_TIMESTAMP = datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC).timestamp()

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
    """Yield a record for every valid line in the file at `path`. See read_stream."""
    try:
        f = path.open("rb")
    except OSError as e:
        raise InputError(str(path), _reason(e)) from e
    with f:
        yield from read_stream(f, str(path), parse, stats, max_line_bytes)


def read_stream(
    stream: io.BufferedReader,
    name: str,
    parse: Parser,
    stats: ReadStats,
    max_line_bytes: int = MAX_LINE_BYTES,
) -> Iterator[LogRecord]:
    """Yield a record for every valid line in `stream`, updating `stats` as it goes.

    The stream may be plain or gzip-compressed, and is left open, so stdin works
    too. `name` identifies it in messages. Malformed lines are skipped; each one
    is logged at DEBUG, with a WARNING summary per stream. Invalid UTF-8 is
    replaced with U+FFFD.

    Raises InputError if the stream can't be read or decompressed. Records
    yielded before the error (e.g. from a truncated gzip) stay counted.
    """
    try:
        with contextlib.ExitStack() as stack:
            f: io.BufferedIOBase = stream
            # peek doesn't consume, which matters for pipes that can't seek back
            if stream.peek(2)[:2] == GZIP_MAGIC:
                f = stack.enter_context(gzip.GzipFile(fileobj=stream))
            yield from _parse_lines(f, name, parse, stats, max_line_bytes)
    except (OSError, EOFError, zlib.error) as e:
        raise InputError(name, _reason(e)) from e

    if stats.skipped:
        log.warning("%s: skipped %d of %d lines", name, stats.skipped, stats.lines)


def _parse_lines(
    f: io.BufferedIOBase, name: str, parse: Parser, stats: ReadStats, max_line_bytes: int
) -> Iterator[LogRecord]:
    for lineno, line in enumerate(_bounded_lines(f, max_line_bytes), 1):
        stats.lines += 1
        try:
            if line is None:
                raise ParseError(f"line longer than {max_line_bytes} bytes")
            record = parse(line.decode("utf-8", errors="replace"))
            if not 0 <= record.timestamp <= MAX_TIMESTAMP:
                raise ParseError(f"timestamp {record.timestamp:g} out of range")
        except ParseError as e:
            stats.skipped += 1
            log.debug("%s:%d: %s", name, lineno, e)
            continue
        stats.records += 1
        yield record


def _reason(e: BaseException) -> str:
    # strerror leaves out the path, which OSError's str() repeats
    return e.strerror if isinstance(e, OSError) and e.strerror else str(e)


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
