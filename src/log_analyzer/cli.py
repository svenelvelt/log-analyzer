import argparse
import inspect
import json
from collections.abc import Sequence
from pathlib import Path

from log_analyzer import __version__
from log_analyzer.analyzers import ANALYZERS
from log_analyzer.parsers import PARSERS
from log_analyzer.reader import ReadStats, read_records


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_intermixed_args(argv)

    selected = [name for name in ANALYZERS if getattr(args, name)] or list(ANALYZERS)
    analyzers = [ANALYZERS[name]() for name in selected]
    parse = PARSERS["squid"]

    for path in args.inputs:
        for record in read_records(path, parse, ReadStats()):
            for analyzer in analyzers:
                analyzer.update(record)

    report = {"results": {a.name: a.result() for a in analyzers}}
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Analyze Squid access logs. Runs all operations if none is selected.",
    )
    parser.add_argument("inputs", nargs="+", type=Path, metavar="INPUT", help="log file(s)")
    parser.add_argument("output", type=Path, metavar="OUTPUT", help="JSON file to write")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    ops = parser.add_argument_group("operations")
    for name, cls in ANALYZERS.items():
        ops.add_argument(f"--{name}", action="store_true", help=_summary(cls))
    return parser


def _summary(cls: type) -> str:
    doc = inspect.getdoc(cls) or ""
    return doc.split("\n\n")[0].replace("\n", " ")
