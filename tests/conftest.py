from pathlib import Path

import pytest

from samples import LINES


@pytest.fixture
def log(tmp_path: Path) -> Path:
    """The three sample LINES as an access.log file."""
    path = tmp_path / "access.log"
    path.write_text("\n".join(LINES) + "\n")
    return path
