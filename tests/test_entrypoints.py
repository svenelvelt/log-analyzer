"""Check the wiring from the outside: the installed console script and python -m."""

import json
import runpy
import sys
from importlib.metadata import entry_points
from pathlib import Path

import pytest

from log_analyzer.cli import main
from samples import LINES


def run_module(monkeypatch: pytest.MonkeyPatch, *args: str) -> int | str | None:
    """Run `python -m log_analyzer` in-process and return its exit code."""
    monkeypatch.setattr(sys, "argv", ["log-analyzer", *args])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("log_analyzer", run_name="__main__")
    return exc.value.code


def test_console_script_points_to_main() -> None:
    # read from the installed package metadata, so a typo in pyproject.toml fails here
    [script] = entry_points(group="console_scripts", name="log-analyzer")
    assert script.load() is main


def test_python_dash_m_succeeds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log = tmp_path / "access.log"
    log.write_text(LINES[0] + "\n")

    code = run_module(monkeypatch, str(log), "-", "--mfip")

    assert code == 0
    assert json.loads(capsys.readouterr().out)["results"] == {
        "mfip": {"ips": ["10.0.0.1"], "count": 1}
    }


def test_python_dash_m_passes_on_exit_code(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    assert run_module(monkeypatch, str(tmp_path / "missing.log"), "-") == 1
