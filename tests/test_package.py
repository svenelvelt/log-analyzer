import log_analyzer


def test_version_is_set() -> None:
    assert isinstance(log_analyzer.__version__, str)
    assert log_analyzer.__version__
