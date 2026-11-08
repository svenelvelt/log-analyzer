from log_analyzer.parsers import squid
from log_analyzer.reader import Parser

PARSERS: dict[str, Parser] = {"squid": squid.parse_line}
