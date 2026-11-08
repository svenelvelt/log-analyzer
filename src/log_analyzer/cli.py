import argparse
import inspect
import json
import logging
import math
import os
import secrets
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from log_analyzer import __version__
from log_analyzer.analyzers import ANALYZERS, Analyzer
from log_analyzer.errors import InputError
from log_analyzer.parsers import PARSERS
from log_analyzer.reader import Parser, ReadStats, read_records

log = logging.getLogger(__name__)


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_intermixed_args(argv)

    selected = [name for name in ANALYZERS if getattr(args, name)] or list(ANALYZERS)
    analyzers = [ANALYZERS[name]() for name in selected]

    report = _analyze(args.inputs, PARSERS["squid"], analyzers)
    text = json.dumps(report, indent=2) + "\n"
    try:
        if args.output == "-":
            sys.stdout.write(text)
        else:
            _write_atomic(Path(args.output), text)
    except OSError as e:
        log.error("%s: %s", args.output, e.strerror or e)
        return 1
    failed = any(f["error"] for f in report["meta"]["files"])
    return 1 if failed else 0


def _write_atomic(path: Path, text: str) -> None:
    """Write to a temp file next to `path`, then rename it over `path`.

    A failure at any point leaves the previous file untouched. Opening with
    "x" refuses to reuse an existing file or symlink at the temp path.
    """
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    try:
        with tmp.open("x", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        tmp.replace(path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _analyze(paths: Sequence[Path], parse: Parser, analyzers: list[Analyzer]) -> dict[str, Any]:
    """Read every file once, feeding each record to all analyzers.

    A file that can't be read is logged and recorded with its error. Records
    read before the error (e.g. from a truncated gzip) stay in the results.
    """
    read: list[tuple[Path, ReadStats, str | None]] = []
    earliest, latest = math.inf, -math.inf

    for path in paths:
        stats = ReadStats()
        error = None
        try:
            for record in read_records(path, parse, stats):
                earliest = min(earliest, record.timestamp)
                latest = max(latest, record.timestamp)
                for analyzer in analyzers:
                    analyzer.update(record)
        except InputError as e:
            log.error("%s", e)
            error = e.reason
        read.append((path, stats, error))

    meta = {
        "tool": f"log-analyzer {__version__}",
        "files": [
            {
                "path": str(p),
                "lines": s.lines,
                "events": s.records,
                "skipped": s.skipped,
                "error": err,
            }
            for p, s, err in read
        ],
        "lines": sum(s.lines for _, s, _ in read),
        "events": sum(s.records for _, s, _ in read),
        "skipped": sum(s.skipped for _, s, _ in read),
        "first": _iso(earliest),
        "last": _iso(latest),
    }
    return {"meta": meta, "results": {a.name: a.result() for a in analyzers}}


def _iso(timestamp: float) -> str | None:
    if not math.isfinite(timestamp):
        return None
    dt = datetime.fromtimestamp(timestamp, UTC)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Analyze Squid access logs. Runs all operations if none is selected.",
    )
    parser.add_argument("inputs", nargs="+", type=Path, metavar="INPUT", help="log file(s)")
    # Kept as str: Path("./-") would normalize to "-" and make a file named "-" unreachable.
    parser.add_argument("output", metavar="OUTPUT", help="JSON file to write, - for stdout")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    ops = parser.add_argument_group("operations")
    for name, cls in ANALYZERS.items():
        ops.add_argument(f"--{name}", action="store_true", help=_summary(cls))
    return parser


def _summary(cls: type) -> str:
    doc = inspect.getdoc(cls) or ""
    return doc.split("\n\n")[0].replace("\n", " ")
