import json

from log_analyzer.formatters import FORMATTERS, to_json

REPORT = {
    "meta": {"tool": "log-analyzer", "first": None},
    "results": {"mfip": {"ips": ["10.0.0.1"], "count": 2}, "bytes": {"total": 5, "unknown": 0}},
}


def test_json_is_indented_and_ends_with_newline() -> None:
    text = to_json(REPORT)

    assert text.startswith('{\n  "meta": {\n')
    assert text.endswith("}\n")
    assert json.loads(text) == REPORT


def test_json_keeps_key_order() -> None:
    text = to_json(REPORT)

    assert text.index('"mfip"') < text.index('"bytes"')


def test_json_is_registered() -> None:
    assert FORMATTERS["json"] is to_json
