import gzip
import io
import json
import logging
import os
import signal
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from log_analyzer import __version__
from log_analyzer.cli import main
from samples import FIXTURES, LINES


@pytest.fixture(autouse=True)
def _in_tmp_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Relative output paths, intended or not, land in tmp_path instead of the repo.
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def out(tmp_path: Path) -> Path:
    return tmp_path / "out.json"


def run(out: Path, *args: str | Path) -> tuple[int, dict[str, Any]]:
    code = main([str(a) for a in args])
    return code, json.loads(out.read_text())


def test_single_operation(log: Path, out: Path) -> None:
    code, data = run(out, log, out, "--mfip")

    assert code == 0
    assert data["results"] == {"mfip": {"n": 1, "clients": [{"ip": "10.0.0.1", "count": 2}]}}


def test_results_in_fixed_order_regardless_of_flag_order(log: Path, out: Path) -> None:
    _, data = run(out, "--bytes", "--eps", log, out, "--lfip", "--mfip", "2")

    assert list(data["results"]) == ["mfip", "lfip", "eps", "bytes"]


def test_no_flags_runs_all_operations(log: Path, out: Path) -> None:
    _, data = run(out, log, out)

    assert data["results"] == {
        "mfip": {"n": 1, "clients": [{"ip": "10.0.0.1", "count": 2}]},
        "lfip": {"n": 1, "clients": [{"ip": "10.0.0.2", "count": 1}]},
        "eps": {"average": 1.5, "peak": 2},
        "bytes": {"total": 500, "unknown": 0},
    }


def test_aggregates_multiple_inputs(log: Path, out: Path) -> None:
    other = log.parent / "access.log.1"
    other.write_text(LINES[1] + "\n")

    _, data = run(out, log, other, out, "--mfip")

    assert data["results"] == {
        "mfip": {
            "n": 1,
            "clients": [{"ip": "10.0.0.1", "count": 2}, {"ip": "10.0.0.2", "count": 2}],
        }
    }


def test_flags_between_inputs(log: Path, out: Path) -> None:
    other = log.parent / "access.log.1"
    other.write_text(LINES[1] + "\n")

    _, data = run(out, log, "--bytes", other, out)

    assert data["results"] == {"bytes": {"total": 600, "unknown": 0}}


def test_missing_output_argument_is_usage_error(log: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        main([str(log)])
    assert exc.value.code == 2


def test_help_lists_operations(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    for flag in ("--mfip", "--lfip", "--eps", "--bytes"):
        assert flag in out


def test_meta_tool_version(log: Path, out: Path) -> None:
    _, data = run(out, log, out)

    assert data["meta"]["tool"] == f"log-analyzer {__version__}"


def test_meta_files_and_totals(log: Path, out: Path) -> None:
    other = log.parent / "access.log.1"
    other.write_text(f"{LINES[1]}\ngarbage\n")

    _, data = run(out, log, other, out)
    meta = data["meta"]

    assert meta["files"] == [
        {"path": str(log), "format": "squid", "lines": 3, "events": 3, "skipped": 0, "error": None},
        {
            "path": str(other),
            "format": "squid",
            "lines": 2,
            "events": 1,
            "skipped": 1,
            "error": None,
        },
    ]
    assert (meta["lines"], meta["events"], meta["skipped"]) == (5, 4, 1)


def test_meta_time_range(log: Path, out: Path) -> None:
    _, data = run(out, log, out, "--mfip")
    meta = data["meta"]

    assert meta["first"] == "2006-09-08T04:22:04.156Z"
    assert meta["last"] == "2006-09-08T04:22:05.500Z"


def test_meta_time_range_without_events(out: Path, tmp_path: Path) -> None:
    empty = tmp_path / "empty.log"
    empty.write_text("")

    _, data = run(out, empty, out)
    meta = data["meta"]

    assert (meta["first"], meta["last"]) == (None, None)


def test_unreadable_input_is_reported_and_others_still_analyzed(log: Path, out: Path) -> None:
    missing = log.parent / "missing.log"

    code, data = run(out, missing, log, out, "--mfip")

    assert code == 1
    assert data["meta"]["files"] == [
        {
            "path": str(missing),
            "format": "squid",
            "lines": 0,
            "events": 0,
            "skipped": 0,
            "error": "No such file or directory",
        },
        {"path": str(log), "format": "squid", "lines": 3, "events": 3, "skipped": 0, "error": None},
    ]
    assert data["results"] == {"mfip": {"n": 1, "clients": [{"ip": "10.0.0.1", "count": 2}]}}


def test_unreadable_input_is_logged(log: Path, out: Path, caplog: pytest.LogCaptureFixture) -> None:
    missing = log.parent / "missing.log"

    with caplog.at_level(logging.ERROR, logger="log_analyzer"):
        run(out, missing, log, out)

    assert caplog.messages == [f"{missing}: No such file or directory"]


def test_truncated_gzip_keeps_partial_counts(out: Path, tmp_path: Path) -> None:
    path = tmp_path / "access.log.gz"
    data = gzip.compress(("\n".join(LINES * 500) + "\n").encode())
    path.write_bytes(data[: len(data) // 2])

    code, report = run(out, path, out, "--bytes")
    [entry] = report["meta"]["files"]

    assert code == 1
    assert entry["error"] == "Compressed file ended before the end-of-stream marker was reached"
    assert 0 < entry["events"] < 1500
    assert report["meta"]["events"] == entry["events"]


def test_all_inputs_unreadable_still_writes_output(out: Path, tmp_path: Path) -> None:
    code, data = run(out, tmp_path / "nope.log", out)

    assert code == 1
    assert data["meta"]["events"] == 0


def test_overwrites_existing_output(log: Path, out: Path) -> None:
    out.write_text("old")

    code, data = run(out, log, out, "--bytes")

    assert code == 0
    assert data["results"] == {"bytes": {"total": 500, "unknown": 0}}


def test_leaves_no_temp_files(log: Path, out: Path) -> None:
    run(out, log, out)

    assert sorted(p.name for p in out.parent.iterdir()) == ["access.log", "out.json"]


def test_failed_write_keeps_previous_output(
    log: Path, out: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out.write_text("old")

    def fail(*_: object, **__: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Path, "replace", fail)
    code = main([str(log), str(out)])

    assert code == 1
    assert out.read_text() == "old"
    assert sorted(p.name for p in out.parent.iterdir()) == ["access.log", "out.json"]


def test_dash_writes_to_stdout(log: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main([str(log), "-", "--bytes"])

    assert code == 0
    assert json.loads(capsys.readouterr().out)["results"] == {"bytes": {"total": 500, "unknown": 0}}


def test_stdout_stays_valid_json_when_input_fails(
    log: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main([str(log.parent / "missing.log"), str(log), "-"])

    assert code == 1
    assert json.loads(capsys.readouterr().out)["meta"]["events"] == 3


def test_dot_slash_dash_is_a_file(log: Path, tmp_path: Path) -> None:
    assert main([str(log), "./-"]) == 0
    assert (tmp_path / "-").is_file()


@pytest.fixture
def bad_log(tmp_path: Path) -> Path:
    path = tmp_path / "bad.log"
    path.write_text(f"{LINES[0]}\ngarbage\n")
    return path


def test_errors_go_to_stderr(log: Path, out: Path, capsys: pytest.CaptureFixture[str]) -> None:
    missing = log.parent / "missing.log"

    main([str(missing), str(log), str(out)])

    assert capsys.readouterr().err == f"log-analyzer: error: {missing}: No such file or directory\n"


def test_skipped_lines_summary_shown_by_default(
    bad_log: Path, out: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main([str(bad_log), str(out)])

    assert capsys.readouterr().err == f"log-analyzer: warning: {bad_log}: skipped 1 of 2 lines\n"


def test_verbose_shows_each_skipped_line(
    bad_log: Path, out: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main([str(bad_log), str(out), "-v"])

    assert capsys.readouterr().err.splitlines() == [
        f"log-analyzer: debug: {bad_log}:2: expected 10 fields, got 1",
        f"log-analyzer: warning: {bad_log}: skipped 1 of 2 lines",
    ]


def test_quiet_hides_warnings_but_not_errors(
    bad_log: Path, out: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = bad_log.parent / "missing.log"

    main([str(missing), str(bad_log), str(out), "-q"])

    assert capsys.readouterr().err == f"log-analyzer: error: {missing}: No such file or directory\n"


def test_verbose_and_quiet_together_is_usage_error(log: Path, out: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        main([str(log), str(out), "-v", "-q"])
    assert exc.value.code == 2


def test_repeated_runs_do_not_duplicate_log_lines(
    bad_log: Path, out: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main([str(bad_log), str(out)])
    capsys.readouterr()

    main([str(bad_log), str(out)])

    assert len(capsys.readouterr().err.splitlines()) == 1


def test_line_with_out_of_range_timestamp_is_skipped(out: Path, tmp_path: Path) -> None:
    path = tmp_path / "access.log"
    huge = LINES[0].replace("1157689324.156", "99999999999999999999.0")
    path.write_text(f"{LINES[0]}\n{huge}\n")

    code, data = run(out, path, out)

    assert code == 0
    assert (data["meta"]["events"], data["meta"]["skipped"]) == (1, 1)


def test_output_same_as_input_is_refused(log: Path, capsys: pytest.CaptureFixture[str]) -> None:
    before = log.read_text()

    with pytest.raises(SystemExit) as exc:
        main([str(log), str(log)])

    assert exc.value.code == 2
    assert log.read_text() == before
    assert f"output {log} is also an input" in capsys.readouterr().err


def test_output_linked_to_input_is_refused(log: Path, tmp_path: Path) -> None:
    link = tmp_path / "report.json"
    link.symlink_to(log)
    before = log.read_text()

    with pytest.raises(SystemExit) as exc:
        main([str(log), str(link)])

    assert exc.value.code == 2
    assert log.read_text() == before


def feed_stdin(monkeypatch: pytest.MonkeyPatch, data: bytes) -> None:
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BufferedReader(io.BytesIO(data))))


def test_dash_reads_stdin(monkeypatch: pytest.MonkeyPatch, out: Path) -> None:
    feed_stdin(monkeypatch, ("\n".join(LINES) + "\n").encode())

    code, data = run(out, "-", out, "--mfip")

    assert code == 0
    assert data["meta"]["files"] == [
        {"path": "<stdin>", "format": "squid", "lines": 3, "events": 3, "skipped": 0, "error": None}
    ]
    assert data["results"] == {"mfip": {"n": 1, "clients": [{"ip": "10.0.0.1", "count": 2}]}}


def test_dash_reads_gzip_from_stdin(monkeypatch: pytest.MonkeyPatch, out: Path) -> None:
    feed_stdin(monkeypatch, gzip.compress(("\n".join(LINES) + "\n").encode()))

    _, data = run(out, "-", out, "--bytes")

    assert data["results"] == {"bytes": {"total": 500, "unknown": 0}}


def test_stdin_and_files_together(monkeypatch: pytest.MonkeyPatch, log: Path, out: Path) -> None:
    feed_stdin(monkeypatch, (LINES[1] + "\n").encode())

    _, data = run(out, log, "-", out, "--mfip")

    assert [f["path"] for f in data["meta"]["files"]] == [str(log), "<stdin>"]
    assert data["results"] == {
        "mfip": {
            "n": 1,
            "clients": [{"ip": "10.0.0.1", "count": 2}, {"ip": "10.0.0.2", "count": 2}],
        }
    }


def test_stdin_twice_is_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["-", "-", "out.json"])

    assert exc.value.code == 2
    assert "stdin (-) can only be read once" in capsys.readouterr().err


def test_dot_slash_dash_input_is_a_file(tmp_path: Path, out: Path) -> None:
    (tmp_path / "-").write_text(LINES[0] + "\n")

    _, data = run(out, "./-", out, "--mfip")

    assert data["meta"]["files"][0]["path"] == "-"
    assert data["results"] == {"mfip": {"n": 1, "clients": [{"ip": "10.0.0.1", "count": 1}]}}


@pytest.mark.parametrize("stdin", [None, io.StringIO("text only")], ids=["closed", "no-buffer"])
def test_unusable_stdin_is_an_input_error(
    monkeypatch: pytest.MonkeyPatch, out: Path, stdin: object
) -> None:
    monkeypatch.setattr(sys, "stdin", stdin)

    code, data = run(out, "-", out)

    assert code == 1
    assert data["meta"]["files"][0]["error"] == "stdin is not readable"


def test_closed_stdout_pipe_exits_quietly(
    log: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # like `log-analyzer ... - | head -1`, with head already gone
    read_end, write_end = os.pipe()
    os.close(read_end)
    with os.fdopen(write_end, "w") as closed_pipe:
        monkeypatch.setattr(sys, "stdout", closed_pipe)
        code = main([str(log), "-"])

    assert code == 141
    assert capsys.readouterr().err == ""


def test_ctrl_c_exits_130_without_traceback(
    log: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def interrupt(*_: object, **__: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("log_analyzer.cli.analyze", interrupt)

    assert main([str(log), "-"]) == 130
    assert capsys.readouterr().err == "log-analyzer: error: interrupted\n"


def test_ctrl_c_while_writing_keeps_previous_output(
    log: Path, out: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out.write_text("old")

    def interrupt(*_: object, **__: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(Path, "replace", interrupt)

    assert main([str(log), str(out)]) == 130
    assert out.read_text() == "old"
    assert sorted(p.name for p in out.parent.iterdir()) == ["access.log", "out.json"]


@pytest.fixture
def sigterm_safety_net() -> Iterator[None]:
    # If main() doesn't handle SIGTERM, fail the test instead of killing pytest.
    def unhandled(*_: object, **__: object) -> None:
        raise AssertionError("SIGTERM reached the test process unhandled")

    previous = signal.signal(signal.SIGTERM, unhandled)
    yield
    signal.signal(signal.SIGTERM, previous)


@pytest.mark.usefixtures("sigterm_safety_net")
def test_sigterm_exits_143(
    log: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # what docker stop or Kubernetes sends, arriving in the middle of the analysis
    def terminated(*_: object, **__: object) -> None:
        os.kill(os.getpid(), signal.SIGTERM)

    monkeypatch.setattr("log_analyzer.cli.analyze", terminated)

    assert main([str(log), "-"]) == 143
    assert capsys.readouterr().err == "log-analyzer: error: terminated\n"


@pytest.mark.usefixtures("sigterm_safety_net")
def test_sigterm_handler_is_restored(log: Path, out: Path) -> None:
    before = signal.getsignal(signal.SIGTERM)

    main([str(log), str(out)])

    assert signal.getsignal(signal.SIGTERM) is before


@pytest.fixture
def must_not_read(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_: object, **__: object) -> None:
        raise AssertionError("inputs were read although the output can't be written")

    monkeypatch.setattr("log_analyzer.cli.analyze", fail)


@pytest.mark.usefixtures("must_not_read")
@pytest.mark.parametrize(
    ("make_output", "reason"),
    [
        pytest.param(lambda d: d / "nope" / "out.json", "No such file or directory", id="no-dir"),
        pytest.param(lambda d: d, "Is a directory", id="is-dir"),
    ],
)
def test_unusable_output_fails_before_reading(
    log: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    make_output: Callable[[Path], Path],
    reason: str,
) -> None:
    out = make_output(tmp_path)

    assert main([str(log), str(out)]) == 1
    assert capsys.readouterr().err == f"log-analyzer: error: {out}: {reason}\n"


@pytest.mark.usefixtures("must_not_read")
@pytest.mark.skipif(os.geteuid() == 0, reason="root can write anywhere")
def test_unwritable_output_directory_fails_before_reading(
    log: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    locked = tmp_path / "locked"
    locked.mkdir(mode=0o500)
    out = locked / "out.json"

    assert main([str(log), str(out)]) == 1
    assert capsys.readouterr().err == f"log-analyzer: error: {out}: Permission denied\n"


def test_input_format_common(out: Path) -> None:
    code, data = run(out, FIXTURES / "squid-6.13-common.log", out, "--input-format", "common")

    assert code == 0
    assert data["meta"]["events"] == 4
    assert data["results"]["mfip"] == {"n": 1, "clients": [{"ip": "172.23.0.4", "count": 4}]}


def test_input_format_defaults_to_squid(out: Path) -> None:
    _, data = run(out, FIXTURES / "squid-6.13-common.log", out)

    assert (data["meta"]["events"], data["meta"]["skipped"]) == (0, 4)


def test_unknown_input_format_is_usage_error(log: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main([str(log), "-", "--input-format", "xml"])

    assert exc.value.code == 2
    assert "invalid choice: 'xml'" in capsys.readouterr().err


def test_input_format_auto(log: Path, out: Path) -> None:
    _, data = run(out, log, FIXTURES / "squid-6.13-common.log", out, "--input-format", "auto")

    assert [f["format"] for f in data["meta"]["files"]] == ["squid", "common"]
    assert data["meta"]["events"] == 7


def test_output_format_text(log: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main([str(log), "-", "--output-format", "text", "--mfip"])

    assert code == 0
    assert capsys.readouterr().out.endswith("Most frequent IP    10.0.0.1 (2 requests)\n")


def test_output_format_defaults_to_json(log: Path, capsys: pytest.CaptureFixture[str]) -> None:
    main([str(log), "-", "--mfip"])

    assert json.loads(capsys.readouterr().out)["results"]["mfip"]["clients"][0]["count"] == 2


def test_text_names_an_undetected_format(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "junk.log"
    path.write_text("garbage\n")

    main([str(path), "-", "--input-format", "auto", "--output-format", "text"])

    assert f"{path} (no known format): 0 events, 1 line skipped" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        pytest.param(
            ["--mfip"], {"mfip": {"n": 1, "clients": [{"ip": "10.0.0.1", "count": 2}]}}, id="mfip"
        ),
        pytest.param(
            ["--mfip", "2"],
            {
                "mfip": {
                    "n": 2,
                    "clients": [{"ip": "10.0.0.1", "count": 2}, {"ip": "10.0.0.2", "count": 1}],
                }
            },
            id="mfip-2",
        ),
        pytest.param(
            ["--mfip=1"],
            {"mfip": {"n": 1, "clients": [{"ip": "10.0.0.1", "count": 2}]}},
            id="equals",
        ),
        pytest.param(
            ["--lfip", "1"],
            {"lfip": {"n": 1, "clients": [{"ip": "10.0.0.2", "count": 1}]}},
            id="lfip-1",
        ),
    ],
)
def test_operation_with_an_optional_value(
    log: Path, out: Path, args: list[str], expected: dict[str, Any]
) -> None:
    _, data = run(out, log, out, *args)

    assert data["results"] == expected


@pytest.mark.parametrize(
    ("args", "message"),
    [
        pytest.param(
            ["--mfip", "0"], "invalid value for 'mfip': n must be at least 1, got 0", id="zero"
        ),
        pytest.param(["--lfip", "ten"], "invalid int value: 'ten'", id="text"),
    ],
)
def test_invalid_operation_value_is_usage_error(
    log: Path, capsys: pytest.CaptureFixture[str], args: list[str], message: str
) -> None:
    with pytest.raises(SystemExit) as exc:
        main([str(log), "-", *args])

    assert exc.value.code == 2
    assert message in capsys.readouterr().err


def test_optional_value_takes_the_next_argument(
    log: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # documented pitfall: right before a file name, the file name is read as N
    with pytest.raises(SystemExit) as exc:
        main(["--mfip", str(log), "-"])

    assert exc.value.code == 2
    assert f"invalid int value: '{log}'" in capsys.readouterr().err


def test_help_shows_the_optional_value(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["--help"])

    out = capsys.readouterr().out
    assert "--mfip [N]" in out
    assert "--lfip [N]" in out
