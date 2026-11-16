import logging
from pathlib import Path
from typing import Any

import pytest
from dash_fakes import FakeSensor, make_services
from fastapi import FastAPI

from snorty.compose import Runtime
from snorty.dashboard.__main__ import HOST, LOG_NAME, main, run
from snorty.dashboard.config import DashConfig


class Rig:
    """Fake `build` and `serve` that record what the CLI asked for."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp_path = tmp_path
        self.build_args: dict[str, Any] = {}
        self.served: list[tuple[str, int]] = []
        self.order: list[str] = []
        self.exit_code: int | None = None
        self.runtime: Runtime | None = None

    def build(self, data_dir: Path, **kwargs: Any) -> Runtime:
        self.build_args = {"data_dir": data_dir, **kwargs}
        services = make_services(self.tmp_path)
        sensor = services.sensor
        assert isinstance(sensor, FakeSensor)
        self.runtime = Runtime(services, None, None)
        return self.runtime

    async def serve(self, app: FastAPI, host: str, port: int) -> None:
        self.served.append((host, port))
        self.order.append("serve")
        if self.exit_code is not None:
            raise SystemExit(self.exit_code)


def cli(tmp_path: Path, rig: Rig, *args: str) -> int:
    return main(["--data-dir", str(tmp_path / "data"), *args], build=rig.build, serve=rig.serve)


def sensor_calls(rig: Rig) -> list[str]:
    assert rig.runtime is not None and isinstance(rig.runtime.services.sensor, FakeSensor)
    return rig.runtime.services.sensor.calls


def test_serves_on_loopback_and_the_default_port(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    assert cli(tmp_path, rig) == 0
    assert rig.served == [(HOST, 8765)]
    assert HOST == "127.0.0.1"


def test_flags_reach_the_services(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    code = cli(tmp_path, rig, "--port", "9001", "--no-notify", "--interface-ip", "10.0.0.2")
    assert code == 0 and rig.served == [(HOST, 9001)]
    assert rig.build_args["notify"] is False and rig.build_args["interface_ip"] == "10.0.0.2"
    assert rig.build_args["data_dir"] == tmp_path / "data"


def test_the_sensor_starts_only_when_asked(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    cli(tmp_path, rig)
    assert "start" not in sensor_calls(rig)
    rig2 = Rig(tmp_path)
    cli(tmp_path, rig2, "--start-sensor")
    assert sensor_calls(rig2)[:1] == ["start"]


def test_the_sensor_is_stopped_on_exit(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    cli(tmp_path, rig, "--start-sensor")
    assert sensor_calls(rig) == ["start", "stop"]


def test_journal_needs_a_vault_and_the_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("OBSIDIAN_VAULT_PATH", raising=False)
    rig = Rig(tmp_path)
    cli(tmp_path, rig)
    assert rig.build_args["journal_store"] is None
    rig = Rig(tmp_path)
    cli(tmp_path, rig, "--vault", str(tmp_path / "vault"))
    assert rig.build_args["journal_store"] is not None
    rig = Rig(tmp_path)
    cli(tmp_path, rig, "--vault", str(tmp_path / "vault"), "--no-journal")
    assert rig.build_args["journal_store"] is None


def test_the_vault_can_come_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OBSIDIAN_VAULT_PATH", str(tmp_path / "v"))
    rig = Rig(tmp_path)
    cli(tmp_path, rig)
    assert rig.build_args["journal_store"] is not None


def test_a_port_that_cannot_be_bound_exits_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rig = Rig(tmp_path)
    rig.exit_code = 1
    assert cli(tmp_path, rig) == 1
    assert "port" in capsys.readouterr().err
    assert "start" not in sensor_calls(rig)


def test_a_crash_exits_1_and_still_shuts_down(tmp_path: Path) -> None:
    rig = Rig(tmp_path)

    async def boom(app: FastAPI, host: str, port: int) -> None:
        raise RuntimeError("secret internals")

    code = main(
        ["--data-dir", str(tmp_path / "data"), "--start-sensor"], build=rig.build, serve=boom
    )
    assert code == 1 and sensor_calls(rig) == ["start", "stop"]


def test_bad_options_exit_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rig = Rig(tmp_path)
    with pytest.raises(SystemExit) as exc:
        cli(tmp_path, rig, "--port", "abc")
    assert exc.value.code == 2
    assert cli(tmp_path, rig, "--port", "70000") == 2
    assert "port" in capsys.readouterr().err
    assert rig.served == []


def test_a_bad_config_file_exits_2(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / "snorty.toml").write_text("port = 'x'")
    rig = Rig(tmp_path)
    assert cli(tmp_path, rig) == 2 and rig.served == []


async def test_a_bind_address_other_than_loopback_is_refused(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    cfg = DashConfig(data_dir=tmp_path)
    assert await run(cfg, build=rig.build, serve=rig.serve, host="0.0.0.0") == 2
    assert rig.served == [] and rig.runtime is None


def test_the_log_is_written_in_the_data_folder_without_the_token(tmp_path: Path) -> None:
    rig = Rig(tmp_path)

    async def boom(app: FastAPI, host: str, port: int) -> None:
        raise RuntimeError("kaboom")

    main(["--data-dir", str(tmp_path / "data")], build=rig.build, serve=boom)
    text = (tmp_path / "data" / LOG_NAME).read_text(encoding="utf-8")
    assert "kaboom" in text and "X-Snorty-Token" not in text
    assert not any(
        isinstance(h, logging.FileHandler) and LOG_NAME in str(h.baseFilename)
        for h in logging.getLogger().handlers
    )


def test_startup_prints_the_url_without_a_token(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rig = Rig(tmp_path)
    cli(tmp_path, rig, "--port", "9002")
    out = capsys.readouterr().out
    assert "http://127.0.0.1:9002/" in out and "token" not in out.lower()
