import argparse
import inspect
import logging
import os
import secrets
import signal
import sys
from argparse import SUPPRESS
from collections.abc import Sequence
from pathlib import Path
from types import FrameType
from typing import NoReturn

from log_analyzer import __version__
from log_analyzer.analysis import analyze
from log_analyzer.analyzers import ANALYZERS, parameter
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
    _configure_logging(args.verbosity)
    _check(parser, args)
    if problem := _output_problem(args.output):
        # checked before reading, which can take minutes for large logs
        log.error("%s: %s", args.output, problem)
        return 1

    # Only the operations given on the command line are in args (default=SUPPRESS),
    # and plain --mfip is None, which means the analyzer's default.
    operations = {name: getattr(args, name) for name in ANALYZERS if hasattr(args, name)}
    try:
        report = analyze(args.inputs, operations or None, input_format=args.input_format)
    except ValueError as e:
        # analyze() creates the analyzers before reading any input, so this is a
        # value the command line asked for that the operation refuses, e.g. --mfip 0
        parser.error(str(e))

    if code := _write(args.output, FORMATTERS[args.output_format](report)):
        return code
    return 1 if any(f["error"] for f in report["meta"]["files"]) else 0


def _check(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Reject command lines that can't work, with exit 2 like other usage errors."""
    if args.inputs.count("-") > 1:
        parser.error("stdin (-) can only be read once")
    if any(_same_file(args.output, i) for i in args.inputs if i != "-"):
        parser.error(f"output {args.output} is also an input")


def _output_problem(output: str) -> str | None:
    """Why `output` can't be written, if that's already clear before writing."""
    if output == "-":
        return None
    path = Path(output)
    if path.is_dir():
        return "Is a directory"
    if not path.parent.is_dir():
        return "No such file or directory"
    if not os.access(path.parent, os.W_OK):
        return "Permission denied"
    return None


def _write(output: str, text: str) -> int:
    """Write the report to the file `output`, or to stdout for "-". Returns an exit code."""
    try:
        if output == "-":
            sys.stdout.write(text)
            sys.stdout.flush()  # so a closed pipe fails here, not at interpreter exit
        else:
            _write_atomic(Path(output), text)
    except BrokenPipeError:
        # The reader went away, e.g. `| head`, which isn't worth an error message.
        # Point stdout at /dev/null so Python's final flush has nothing to fail on.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        os.close(devnull)
        return 141  # 128 + SIGPIPE, like other Unix tools
    except OSError as e:
        log.error("%s: %s", output, e.strerror or e)
        return 1
    return 0


def _same_file(a: str, b: str) -> bool:
    """True if both paths exist and are the same file, also through links."""
    try:
        return Path(a).samefile(b)
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
        # Files first: an option with an optional value (--mfip [N]) would read a file
        # name that follows it as its value. The options are listed below the usage line.
        usage="%(prog)s INPUT [INPUT ...] OUTPUT [options]",
        description="Analyze access logs. Runs all operations if none is selected.",
    )
    # Kept as str for the same reason as OUTPUT below.
    parser.add_argument("inputs", nargs="+", metavar="INPUT", help="log file(s), - for stdin")
    # Kept as str: Path("./-") would normalize to "-" and make a file named "-" unreachable.
    parser.add_argument(
        "output", metavar="OUTPUT", help="file to write the report to, - for stdout"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--input-format",
        choices=[*PARSERS, "auto"],
        default="squid",
        help="squid: Squid's native access.log (default); "
        "common: Common Log Format, also combined, as written by Squid, Apache and nginx; "
        "auto: detect it for each input",
    )
    parser.add_argument(
        "--output-format",
        choices=list(FORMATTERS),
        default="json",
        help="json: the complete report (default); text: a short summary for people",
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

    # An operation that isn't given stays out of args (SUPPRESS); one that is given
    # without a value is None, meaning the analyzer's default.
    ops = parser.add_argument_group("operations")
    for name, cls in ANALYZERS.items():
        value = parameter(cls)
        if value is None:
            ops.add_argument(
                f"--{name}", action="store_const", const=None, default=SUPPRESS, help=_summary(cls)
            )
        else:
            # e.g. MostFrequentIp(n: int = 1) becomes --mfip [N], converted with int();
            # the value is optional, so plain --mfip keeps working as the spec has it
            ops.add_argument(
                f"--{name}",
                nargs="?",
                const=None,
                default=SUPPRESS,
                type=value.type,
                metavar=value.name.upper(),
                help=_summary(cls),
            )
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
