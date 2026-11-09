class LogAnalyzerError(Exception):
    pass


class ParseError(LogAnalyzerError):
    pass


class InputError(LogAnalyzerError):
    def __init__(self, source: str, reason: str) -> None:
        super().__init__(f"{source}: {reason}")
        self.source = source
        self.reason = reason
