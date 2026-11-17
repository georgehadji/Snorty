import asyncio
import logging
import socket
import threading
from collections.abc import AsyncIterator
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from dash_fakes import FakeSensor, alert, make_services
from fastapi import FastAPI
from fastapi.responses import StreamingResponse

from snorty.compose import Runtime
from snorty.core.repository import AlertRepository
from snorty.dashboard.__main__ import (
    CONTEXT_DAYS,
    HOST,
    LOG_NAME,
    STOP_NAME,
    main,
    prune_old,
    request_stop,
    run,
    serve_uvicorn,
)
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
        self.serve_until_stopped = False
        self.stopped_at_once: bool | None = None

    def build(self, data_dir: Path, **kwargs: Any) -> Runtime:
        self.build_args = {"data_dir": data_dir, **kwargs}
        services = make_services(self.tmp_path)
        sensor = services.sensor
        assert isinstance(sensor, FakeSensor)
        self.runtime = Runtime(services, None, None)
        return self.runtime

    async def serve(self, app: FastAPI, host: str, port: int, stop: asyncio.Event) -> None:
        self.served.append((host, port))
        self.order.append("serve")
        if self.exit_code is not None:
            raise SystemExit(self.exit_code)
        await asyncio.sleep(0.05)
        self.stopped_at_once = stop.is_set()
        if self.serve_until_stopped:
            await asyncio.wait_for(stop.wait(), 5)


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

    async def boom(app: FastAPI, host: str, port: int, stop: asyncio.Event) -> None:
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

    async def boom(app: FastAPI, host: str, port: int, stop: asyncio.Event) -> None:
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


async def test_a_stop_request_shuts_everything_down_then_is_removed(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.serve_until_stopped = True
    cfg = DashConfig(data_dir=tmp_path, autostart_sensor=True, retention_days=0)

    async def ask_later() -> None:
        await asyncio.sleep(0.2)
        (tmp_path / STOP_NAME).touch()

    asker = asyncio.create_task(ask_later())
    assert await run(cfg, build=rig.build, serve=rig.serve) == 0
    await asker
    assert sensor_calls(rig) == ["start", "stop"]
    assert not (tmp_path / STOP_NAME).exists()  # what `--stop` waits for


def test_a_stale_stop_request_does_not_stop_the_next_start(tmp_path: Path) -> None:
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / STOP_NAME).touch()  # `--stop` ran when nothing was running
    rig = Rig(tmp_path)
    assert cli(tmp_path, rig) == 0
    assert rig.stopped_at_once is False


def test_stop_without_a_running_dashboard_writes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = DashConfig(data_dir=tmp_path)
    assert request_stop(cfg, answers=lambda port: False) == 1
    assert "no Snorty dashboard" in capsys.readouterr().err
    assert not (tmp_path / STOP_NAME).exists()


def test_stop_waits_until_the_dashboard_has_finished(tmp_path: Path) -> None:
    cfg = DashConfig(data_dir=tmp_path)
    path = tmp_path / STOP_NAME

    def dashboard() -> None:  # sees the request, shuts down, removes it
        while not path.exists():
            threading.Event().wait(0.01)
        threading.Event().wait(0.2)
        path.unlink()

    worker = threading.Thread(target=dashboard)
    worker.start()
    assert request_stop(cfg, answers=lambda port: True, poll=0.02) == 0
    worker.join()


def test_stop_gives_up_when_the_dashboard_does_not_finish(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = DashConfig(data_dir=tmp_path)
    assert request_stop(cfg, answers=lambda port: True, wait=0.1, poll=0.02) == 1
    assert "did not finish" in capsys.readouterr().err


async def test_uvicorn_exits_when_stop_is_set() -> None:
    stop = asyncio.Event()
    serving = asyncio.create_task(serve_uvicorn(FastAPI(), HOST, 0, stop))
    await asyncio.sleep(0.5)
    assert not serving.done()
    stop.set()
    await asyncio.wait_for(serving, 5)


async def test_an_open_live_stream_does_not_hold_up_the_stop(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A dashboard tab left open keeps /events streaming; the stop must still finish."""
    caplog.set_level(logging.INFO)
    app = FastAPI()

    @app.get("/events")
    async def events() -> StreamingResponse:
        async def forever() -> AsyncIterator[bytes]:
            while True:
                yield b": heartbeat\n\n"
                await asyncio.sleep(0.05)

        return StreamingResponse(forever(), media_type="text/event-stream")

    with socket.socket() as probe:  # a free port, so the test can connect to it
        probe.bind((HOST, 0))
        port = probe.getsockname()[1]
    stop = asyncio.Event()
    serving = asyncio.create_task(serve_uvicorn(app, HOST, port, stop, grace=1))
    for _ in range(50):
        try:
            reader, writer = await asyncio.open_connection(HOST, port)
            break
        except OSError:
            await asyncio.sleep(0.1)
    writer.write(f"GET /events HTTP/1.1\r\nHost: {HOST}\r\n\r\n".encode())
    await writer.drain()
    assert b"200" in await asyncio.wait_for(reader.readline(), 5)
    stop.set()
    await asyncio.wait_for(serving, 5)
    writer.close()
    assert "timeout graceful shutdown exceeded" in caplog.text  # the cut happened, and
    assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []  # is not an error


def seed(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    repo = AlertRepository(tmp_path / "t.db")
    repo.add(alert(sid=1, ts=now - timedelta(days=100)))
    repo.add(alert(sid=2, ts=now - timedelta(days=1)))
    repo.close()


def stored_sids(tmp_path: Path) -> list[int]:
    repo = AlertRepository(tmp_path / "t.db")
    try:
        return sorted(a.sid for a in repo.query(limit=10))
    finally:
        repo.close()


def test_startup_deletes_alerts_older_than_the_retention(tmp_path: Path) -> None:
    """Retention: the alert store must not grow without bound."""
    seed(tmp_path)
    assert cli(tmp_path, Rig(tmp_path)) == 0
    assert stored_sids(tmp_path) == [2]


def test_retention_zero_keeps_everything(tmp_path: Path) -> None:
    seed(tmp_path)
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "snorty.toml").write_text("retention_days = 0\n", encoding="utf-8")
    assert cli(tmp_path, Rig(tmp_path)) == 0
    assert stored_sids(tmp_path) == [1, 2]


async def test_connection_context_is_pruned_after_a_week_even_when_alerts_are_kept(
    tmp_path: Path,
) -> None:
    from snorty.core.models import Lookup

    now = datetime.now(UTC)
    with closing(AlertRepository(tmp_path / "t.db")) as repo:
        old = [Lookup(now - timedelta(days=CONTEXT_DAYS + 1), "pc", "old.example", "x")]
        repo.add_context([], [*old, Lookup(now, "pc", "new.example", "x")])
        assert await prune_old(repo, 0) == 0  # retention 0 keeps every alert
        assert [x.name for x in repo.lookups_of("x", now, timedelta(days=30))] == ["new.example"]


async def test_a_failing_prune_is_logged_not_raised(tmp_path: Path) -> None:
    repo = AlertRepository(tmp_path / "t.db")
    repo.close()  # a closed connection makes prune raise
    assert await prune_old(repo, 90) == 0
