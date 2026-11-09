import io
import sys
from pathlib import Path

import pytest

from log_analyzer import analyze

LINES = [
    "1157689324.156   1372 10.0.0.1 TCP_MISS/200 399 GET http://a.com/ - DIRECT/1.2.3.4 text/html",
    "1157689324.900    100 10.0.0.2 TCP_MISS/200 100 GET http://b.com/ - DIRECT/1.2.3.4 text/html",
    "1157689325.500    100 10.0.0.1 TCP_MISS/200 1 GET http://c.com/ - DIRECT/1.2.3.4 text/html",
]
DATA = ("\n".join(LINES) + "\n").encode()


@pytest.fixture
def log(tmp_path: Path) -> Path:
    path = tmp_path / "access.log"
    path.write_bytes(DATA)
    return path


def test_all_operations_by_default(log: Path) -> None:
    report = analyze([log])

    assert list(report["results"]) == ["mfip", "lfip", "eps", "bytes"]
    assert report["meta"]["events"] == 3


def test_selected_operations_in_fixed_order(log: Path) -> None:
    report = analyze([log], ["bytes", "mfip"])

    assert report["results"] == {
        "mfip": {"ips": ["10.0.0.1"], "count": 2},
        "bytes": {"total": 500, "unknown": 0},
    }


def test_accepts_str_and_path(log: Path) -> None:
    assert analyze([str(log)], ["bytes"]) == analyze([log], ["bytes"])


def test_reads_a_stream() -> None:
    report = analyze([io.BufferedReader(io.BytesIO(DATA))], ["mfip"])

    assert report["meta"]["files"][0]["path"] == "<stream>"
    assert report["results"] == {"mfip": {"ips": ["10.0.0.1"], "count": 2}}


def test_dash_reads_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BufferedReader(io.BytesIO(DATA))))

    report = analyze(["-"], ["bytes"])

    assert report["meta"]["files"][0]["path"] == "<stdin>"
    assert report["results"] == {"bytes": {"total": 500, "unknown": 0}}


def test_path_named_dash_is_a_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "-").write_bytes(DATA)

    assert analyze([Path("-")], ["bytes"])["meta"]["files"][0]["path"] == "-"


def test_unreadable_input_is_recorded_not_raised(tmp_path: Path) -> None:
    report = analyze([tmp_path / "missing.log"])

    assert report["meta"]["files"][0]["error"] == "No such file or directory"


def test_unknown_operation() -> None:
    with pytest.raises(ValueError, match="unknown operation 'nope'"):
        analyze([], ["nope"])


def test_unknown_input_format() -> None:
    with pytest.raises(ValueError, match="unknown input format 'nope'"):
        analyze([], input_format="nope")


FIXTURES = Path(__file__).parent / "fixtures"
CLF = FIXTURES / "squid-6.13-common.log"


def test_each_file_reports_its_format(log: Path) -> None:
    report = analyze([log], ["bytes"])

    assert report["meta"]["files"][0]["format"] == "squid"


def test_auto_detects_the_format_per_file(log: Path) -> None:
    report = analyze([log, CLF], ["mfip"], input_format="auto")

    assert [f["format"] for f in report["meta"]["files"]] == ["squid", "common"]
    assert report["meta"]["events"] == 7


def test_auto_skips_unknown_lines_before_detection(tmp_path: Path) -> None:
    path = tmp_path / "access.log"
    path.write_text("garbage\n" + CLF.read_text())

    files = analyze([path], input_format="auto")["meta"]["files"]

    assert (files[0]["format"], files[0]["events"], files[0]["skipped"]) == ("common", 4, 1)


def test_auto_keeps_the_detected_format_for_the_rest_of_the_file(tmp_path: Path) -> None:
    path = tmp_path / "access.log"
    path.write_text(LINES[0] + "\n" + CLF.read_text())

    files = analyze([path], input_format="auto")["meta"]["files"]

    assert (files[0]["format"], files[0]["events"], files[0]["skipped"]) == ("squid", 1, 4)


def test_auto_without_any_known_line(tmp_path: Path) -> None:
    path = tmp_path / "access.log"
    path.write_text("garbage\n")

    assert analyze([path], input_format="auto")["meta"]["files"][0]["format"] is None
