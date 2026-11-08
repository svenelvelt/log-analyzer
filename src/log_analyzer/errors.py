from pathlib import Path


class LogAnalyzerError(Exception):
    pass


class ParseError(LogAnalyzerError):
    pass


class InputError(LogAnalyzerError):
    def __init__(self, path: Path, reason: str) -> None:
        super().__init__(f"{path}: {reason}")
        self.path = path
        self.reason = reason
