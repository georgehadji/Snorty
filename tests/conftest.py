import pytest


@pytest.fixture(autouse=True)
def _default_engine_is_snort(monkeypatch: pytest.MonkeyPatch) -> None:
    """The default engine depends on what this PC has installed; tests must not."""
    monkeypatch.setattr("snorty.dashboard.config.default_engine", lambda: "snort")
