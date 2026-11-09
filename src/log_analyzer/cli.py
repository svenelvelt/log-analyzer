import argparse
import inspect
import logging
import os
import secrets
import sys
from collections.abc import Sequence
from pathlib import Path

from log_analyzer import __version__
from log_analyzer.analysis import analyze
from log_analyzer.analyzers import ANALYZERS
from log_analyzer.formatters import FORMATTERS

log = logging.getLogger(__name__)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_intermixed_args(argv)
    if args.inputs.count("-") > 1:
        parser.error("stdin (-) can only be read once")
    files = [Path(i) for i in args.inputs if i != "-"]
    if args.output != "-" and any(_same_file(Path(args.output), f) for f in files):
        parser.error(f"output {args.output} is also an input")
    _configure_logging(args.verbosity)

    selected = [name for name in ANALYZERS if getattr(args, name)]
    report = analyze(args.inputs, selected or None)
    text = FORMATTERS["json"](report)
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


def _same_file(a: Path, b: Path) -> bool:
    """True if both paths exist and are the same file, also through links."""
    try:
        return a.samefile(b)
    except OSError:
        return False


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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Analyze Squid access logs. Runs all operations if none is selected.",
    )
    # Kept as str for the same reason as OUTPUT below.
    parser.add_argument("inputs", nargs="+", metavar="INPUT", help="log file(s), - for stdin")
    # Kept as str: Path("./-") would normalize to "-" and make a file named "-" unreachable.
    parser.add_argument("output", metavar="OUTPUT", help="JSON file to write, - for stdout")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument(
        "-v",
        "--verbose",
        dest="verbosity",
        action="store_const",
        const=logging.DEBUG,
        default=logging.WARNING,
        help="also log every skipped line",
    )
    verbosity.add_argument(
        "-q",
        "--quiet",
        dest="verbosity",
        action="store_const",
        const=logging.ERROR,
        help="only log errors",
    )

    ops = parser.add_argument_group("operations")
    for name, cls in ANALYZERS.items():
        ops.add_argument(f"--{name}", action="store_true", help=_summary(cls))
    return parser


def _summary(cls: type) -> str:
    doc = inspect.getdoc(cls) or ""
    return doc.split("\n\n")[0].replace("\n", " ")


def _configure_logging(level: int) -> None:
    """Log to stderr as "log-analyzer: <level>: <message>".

    The handler goes on the package logger, not the root logger, so importing
    log_analyzer as a library leaves the caller's logging alone. It is replaced
    on every call, so running main() repeatedly doesn't duplicate output.
    """
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_Formatter())

    logger = logging.getLogger("log_analyzer")
    for old in logger.handlers[:]:
        logger.removeHandler(old)
    logger.addHandler(handler)
    logger.setLevel(level)


class _Formatter(logging.Formatter):
    # Builds the line instead of lowercasing record.levelname, which other
    # handlers further up would see too.
    def format(self, record: logging.LogRecord) -> str:
        return f"log-analyzer: {record.levelname.lower()}: {record.getMessage()}"
