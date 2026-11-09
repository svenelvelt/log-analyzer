"""Analyze log files, from the command line or from Python."""

from importlib.metadata import version

from log_analyzer.analysis import analyze

# pyproject.toml is the one place the version is set
__version__ = version("log-analyzer")
__all__ = ["__version__", "analyze"]
