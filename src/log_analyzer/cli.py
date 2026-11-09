import argparse
import inspect
import logging
import os
import secrets
import signal
import sys
from collections.abc import Sequence
from pathlib import Path
from types import FrameType
from typing import NoReturn

from log_analyzer import __version__
from log_analyzer.analysis import analyze
from log_analyzer.analyzers import ANALYZERS
from log_analyzer.formatters import FORMATTERS
from log_analyzer.parsers import PARSERS

log = logging.getLogger(__name__)


def main(argv: Sequence[str] | None = None) -> int:
    # docker stop and Kubernetes send SIGTERM. Its default action is to kill the
    # process without cleanup, and as PID 1 in a container Python would even
    # ignore it, so handle it like Ctrl-C.
    previous = signal.signal(signal.SIGTERM, _terminate)
    try:
        return _run(argv)
    except KeyboardInterrupt:
        _stopped("interrupted")
        return 130  # 128 + SIGINT, like other Unix tools
    except _Terminated:
        _stopped("terminated")
        return 143  # 128 + SIGTERM
    finally:
        signal.signal(signal.SIGTERM, previous)


class _Terminated(BaseException):
    """Raised on SIGTERM. A BaseException, like KeyboardInterrupt, so only main() catches it."""


def _terminate(signum: int, frame: FrameType | None) -> NoReturn:
    raise _Terminated


def _stopped(how: str) -> None:
    # print, not log: logging may not be set up yet
    print(f"log-analyzer: error: {how}", file=sys.stderr)


def _run(argv: Sequence[str] | None) -> int:
    parser = _build_parser()
    args = parser.parse_intermixed_args(argv)
    if args.inputs.count("-") > 1:
        parser.error("stdin (-) can only be read once")
    files = [Path(i) for i in args.inputs if i != "-"]
    if args.output != "-" and any(_same_file(Path(args.output), f) for f in files):
        parser.error(f"output {args.output} is also an input")
    _configure_logging(args.verbosity)
    if args.output != "-" and (problem := _output_problem(Path(args.output))):
        # checked before reading, which can take minutes for large logs
        log.error("%s: %s", args.output, problem)
        return 1

    selected = [name for name in ANALYZERS if getattr(args, name)]
    report = analyze(args.inputs, selected or None, input_format=args.input_format)
    text = FORMATTERS["json"](report)
    try:
        if args.output == "-":
            sys.stdout.write(text)
            sys.stdout.flush()  # so a closed pipe fails here, not at interpreter exit
        else:
            _write_atomic(Path(args.output), text)
    except BrokenPipeError:
        # The reader went away, e.g. `| head`, which isn't worth an error message.
        # Point stdout at /dev/null so Python's final flush has nothing to fail on.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        os.close(devnull)
        return 141  # 128 + SIGPIPE, like other Unix tools
    except OSError as e:
        log.error("%s: %s", args.output, e.strerror or e)
        return 1
    failed = any(f["error"] for f in report["meta"]["files"])
    return 1 if failed else 0


def _output_problem(path: Path) -> str | None:
    """Why `path` can't be written, if that's already clear before writing."""
    if path.is_dir():
        return "Is a directory"
    if not path.parent.is_dir():
        return "No such file or directory"
    if not os.access(path.parent, os.W_OK):
        return "Permission denied"
    return None


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
        description="Analyze access logs. Runs all operations if none is selected.",
    )
    # Kept as str for the same reason as OUTPUT below.
    parser.add_argument("inputs", nargs="+", metavar="INPUT", help="log file(s), - for stdin")
    # Kept as str: Path("./-") would normalize to "-" and make a file named "-" unreachable.
    parser.add_argument("output", metavar="OUTPUT", help="JSON file to write, - for stdout")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--input-format",
        choices=list(PARSERS),
        default="squid",
        help="squid: Squid's native access.log (default); "
        "common: Common Log Format, also combined, as written by Squid, Apache and nginx",
    )

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
