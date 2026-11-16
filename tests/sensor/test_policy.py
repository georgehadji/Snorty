import dataclasses

import pytest

from snorty.sensor.config import SensorConfig
from snorty.sensor.policy import backoff_delay, should_give_up
from snorty.snort.models import SnortPaths


def test_backoff_doubles_then_caps() -> None:
    assert [backoff_delay(n) for n in range(1, 8)] == [2, 4, 8, 16, 32, 60, 60]


def test_backoff_custom_base() -> None:
    assert backoff_delay(3, base=0.2, cap=1.0) == pytest.approx(0.8)


@pytest.mark.parametrize(("failures", "expected"), [(0, False), (4, False), (5, True), (6, True)])
def test_give_up_at_max_restarts(failures: int, expected: bool) -> None:
    assert should_give_up(failures, 5) is expected


def test_config_defaults_match_spec() -> None:
    cfg = SensorConfig()
    assert cfg.paths == SnortPaths()
    assert (cfg.interface_ip, cfg.poll_interval, cfg.network_check_interval) == (None, 0.5, 30.0)
    assert (cfg.max_restarts, cfg.stable_after, cfg.stop_timeout) == (5, 60.0, 15.0)


def test_config_is_frozen() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        SensorConfig().poll_interval = 1.0  # type: ignore[misc]
