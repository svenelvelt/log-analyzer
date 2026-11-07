"""Stream parsed records from log files."""

import logging
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from log_analyzer.errors import ParseError
from log_analyzer.models import LogRecord

log = logging.getLogger(__name__)

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
    with path.open(encoding="utf-8") as f:
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
