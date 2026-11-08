"""Output formats: each turns the finished report into the text that gets written."""

import json
from collections.abc import Callable
from typing import Any

Formatter = Callable[[dict[str, Any]], str]


def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2) + "\n"


FORMATTERS: dict[str, Formatter] = {"json": to_json}
