import json

from log_analyzer.formatters import FORMATTERS, to_json, to_text

REPORT = {
    "meta": {"tool": "log-analyzer", "first": None},
    "results": {
        "mfip": {"n": 1, "clients": [{"ip": "10.0.0.1", "count": 2}]},
        "bytes": {"total": 5, "unknown": 0},
    },
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


SAMPLE = {
    "meta": {
        "tool": "log-analyzer 0.1.0",
        "files": [
            {
                "path": "access.log.gz",
                "format": "squid",
                "lines": 1643520,
                "events": 1643518,
                "skipped": 2,
                "error": None,
            },
            {
                "path": "missing.log",
                "format": "squid",
                "lines": 0,
                "events": 0,
                "skipped": 0,
                "error": "No such file or directory",
            },
        ],
        "lines": 1643520,
        "events": 1643518,
        "skipped": 2,
        "first": "2002-10-19T20:30:37.745Z",
        "last": "2012-05-02T03:18:57.000Z",
    },
    "results": {
        "mfip": {"n": 1, "clients": [{"ip": "127.0.0.1", "count": 1422267}]},
        "lfip": {"n": 1, "clients": [{"ip": f"10.0.0.{i}", "count": 1} for i in range(1, 31)]},
        "eps": {"average": 0.005462564623700176, "peak": 7952},
        "bytes": {"total": 2216979451, "unknown": 1001183},
    },
}


def test_text_summary() -> None:
    assert to_text(SAMPLE) == (
        "log-analyzer 0.1.0\n"
        "access.log.gz (squid): 1,643,518 events, 2 lines skipped\n"
        "missing.log: No such file or directory\n"
        "Period: 2002-10-19T20:30:37.745Z to 2012-05-02T03:18:57.000Z\n"
        "\n"
        "Most frequent IP    127.0.0.1 (1,422,267 requests)\n"
        "Least frequent IP   10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4, 10.0.0.5 and 25 more"
        " (1 request each)\n"
        "Events per second   0.005463 on average, 7,952 at peak\n"
        "Bytes               2,216,979,451 (size unknown for 1,001,183 events)\n"
    )


def test_text_without_events() -> None:
    report = {
        "meta": {"tool": "log-analyzer 0.1.0", "files": [], "first": None, "last": None},
        "results": {"mfip": {"n": 1, "clients": []}, "bytes": {"total": 0, "unknown": 0}},
    }

    assert to_text(report) == (
        "log-analyzer 0.1.0\nPeriod: no events\n\nMost frequent IP    none\nBytes               0\n"
    )


def test_text_shows_unknown_results_generically() -> None:
    # a future analyzer the text format doesn't know about yet
    report = {
        "meta": {"tool": "log-analyzer 0.1.0", "files": [], "first": None, "last": None},
        "results": {"methods": {"GET": 3, "HEAD": 1}},
    }

    assert to_text(report).endswith('methods             {"GET": 3, "HEAD": 1}\n')


def test_text_is_registered() -> None:
    assert FORMATTERS["text"] is to_text


def test_text_ranking_with_different_counts_is_a_table() -> None:
    report = {
        "meta": {"tool": "log-analyzer 0.1.0", "files": [], "first": None, "last": None},
        "results": {
            "mfip": {
                "n": 3,
                "clients": [
                    {"ip": "127.0.0.1", "count": 1422267},
                    {"ip": "10.105.23.212", "count": 7224},
                    {"ip": "210.8.79.210", "count": 5178},
                ],
            }
        },
    }

    assert to_text(report).endswith(
        "Top 3 IPs           127.0.0.1      1,422,267\n"
        "                    10.105.23.212      7,224\n"
        "                    210.8.79.210       5,178\n"
    )


def test_text_labels_for_n() -> None:
    report = {
        "meta": {"tool": "log-analyzer 0.1.0", "files": [], "first": None, "last": None},
        "results": {"mfip": {"n": 10, "clients": []}, "lfip": {"n": 5, "clients": []}},
    }

    assert to_text(report).endswith("Top 10 IPs          none\nRarest 5 IPs        none\n")
