"""Stream parsed records from log files."""

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from log_analyzer.models import LogRecord

Parser = Callable[[str], LogRecord]


@dataclass
class ReadStats:
    lines: int = 0
    records: int = 0


def read_records(path: Path, parse: Parser, stats: ReadStats) -> Iterator[LogRecord]:
    """Yield a record for every line in `path`, updating `stats` as it goes."""
    with path.open(encoding="utf-8") as f:
        for line in f:
            stats.lines += 1
            record = parse(line)
            stats.records += 1
            yield record
