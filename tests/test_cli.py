import gzip
import json
import logging
from pathlib import Path
from typing import Any

import pytest

from log_analyzer import __version__
from log_analyzer.cli import main

LINES = [
    "1157689324.156   1372 10.0.0.1 TCP_MISS/200 399 GET http://a.com/ - DIRECT/1.2.3.4 text/html",
    "1157689324.900    100 10.0.0.2 TCP_MISS/200 100 GET http://b.com/ - DIRECT/1.2.3.4 text/html",
    "1157689325.500    100 10.0.0.1 TCP_MISS/200 1 GET http://c.com/ - DIRECT/1.2.3.4 text/html",
]


@pytest.fixture(autouse=True)
def _in_tmp_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Relative output paths, intended or not, land in tmp_path instead of the repo.
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def log(tmp_path: Path) -> Path:
    path = tmp_path / "access.log"
    path.write_text("\n".join(LINES) + "\n")
    return path


@pytest.fixture
def out(tmp_path: Path) -> Path:
    return tmp_path / "out.json"


def run(out: Path, *args: str | Path) -> tuple[int, dict[str, Any]]:
    code = main([str(a) for a in args])
    return code, json.loads(out.read_text())


def test_single_operation(log: Path, out: Path) -> None:
    code, data = run(out, log, out, "--mfip")

    assert code == 0
    assert data["results"] == {"mfip": {"ips": ["10.0.0.1"], "count": 2}}


def test_results_in_fixed_order_regardless_of_flag_order(log: Path, out: Path) -> None:
    _, data = run(out, "--bytes", "--eps", log, out, "--lfip", "--mfip")

    assert list(data["results"]) == ["mfip", "lfip", "eps", "bytes"]


def test_no_flags_runs_all_operations(log: Path, out: Path) -> None:
    _, data = run(out, log, out)

    assert data["results"] == {
        "mfip": {"ips": ["10.0.0.1"], "count": 2},
        "lfip": {"ips": ["10.0.0.2"], "count": 1},
        "eps": {"average": 1.5, "peak": 2},
        "bytes": {"total": 500, "unknown": 0},
    }


def test_aggregates_multiple_inputs(log: Path, out: Path) -> None:
    other = log.parent / "access.log.1"
    other.write_text(LINES[1] + "\n")

    _, data = run(out, log, other, out, "--mfip")

    assert data["results"] == {"mfip": {"ips": ["10.0.0.1", "10.0.0.2"], "count": 2}}


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
        {"path": str(log), "lines": 3, "events": 3, "skipped": 0, "error": None},
        {"path": str(other), "lines": 2, "events": 1, "skipped": 1, "error": None},
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
            "lines": 0,
            "events": 0,
            "skipped": 0,
            "error": "No such file or directory",
        },
        {"path": str(log), "lines": 3, "events": 3, "skipped": 0, "error": None},
    ]
    assert data["results"] == {"mfip": {"ips": ["10.0.0.1"], "count": 2}}


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

    def fail(*_: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Path, "replace", fail)
    code = main([str(log), str(out)])

    assert code == 1
    assert out.read_text() == "old"
    assert sorted(p.name for p in out.parent.iterdir()) == ["access.log", "out.json"]


def test_output_directory_missing(
    log: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    out = tmp_path / "nope" / "out.json"

    with caplog.at_level(logging.ERROR, logger="log_analyzer"):
        code = main([str(log), str(out)])

    assert code == 1
    assert caplog.messages == [f"{out}: No such file or directory"]


def test_output_is_a_directory(log: Path, tmp_path: Path) -> None:
    assert main([str(log), str(tmp_path)]) == 1


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
