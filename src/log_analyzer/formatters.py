"""Output formats: each turns the finished report into the text that gets written."""

import json
from collections.abc import Callable
from typing import Any

Formatter = Callable[[dict[str, Any]], str]


def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2) + "\n"


def to_text(report: dict[str, Any]) -> str:
    """A short summary for people. JSON remains the complete, machine-readable form."""
    meta = report["meta"]
    lines = [meta["tool"]]
    for file in meta["files"]:
        if file["error"]:
            lines.append(f"{file['path']}: {file['error']}")
        else:
            lines.append(
                f"{file['path']} ({file['format'] or 'no known format'}): "
                f"{_count(file['events'], 'event')}, {_count(file['skipped'], 'line')} skipped"
            )
    period = f"{meta['first']} to {meta['last']}" if meta["first"] else "no events"
    lines += [f"Period: {period}", ""]

    for name, result in report["results"].items():
        label, render = _RESULTS.get(name, (name, _as_json))
        lines.append(f"{label:<20}{render(result)}")
    return "\n".join(lines) + "\n"


def _ips(result: dict[str, Any], shown: int = 5) -> str:
    ips, count = result["ips"], result["count"]
    if not ips:
        return "none"
    text = ", ".join(ips[:shown])
    if len(ips) > shown:
        text += f" and {len(ips) - shown} more"
    each = " each" if len(ips) > 1 else ""
    return f"{text} ({_count(count, 'request')}{each})"


def _eps(result: dict[str, Any]) -> str:
    return f"{result['average']:.4g} on average, {result['peak']:,} at peak"


def _bytes(result: dict[str, Any]) -> str:
    text = f"{result['total']:,}"
    if result["unknown"]:
        text += f" (size unknown for {_count(result['unknown'], 'event')})"
    return text


def _count(n: int, word: str) -> str:
    return f"{n:,} {word}{'' if n == 1 else 's'}"


def _as_json(result: Any) -> str:
    # results this format doesn't know yet, e.g. from a newly added analyzer
    return json.dumps(result)


_RESULTS: dict[str, tuple[str, Callable[[Any], str]]] = {
    "mfip": ("Most frequent IP", _ips),
    "lfip": ("Least frequent IP", _ips),
    "eps": ("Events per second", _eps),
    "bytes": ("Bytes", _bytes),
}

FORMATTERS: dict[str, Formatter] = {"json": to_json, "text": to_text}
