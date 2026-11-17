import asyncio
import json
import socket
from collections.abc import Sequence
from datetime import UTC
from pathlib import Path

import pytest

from snorty.core.bus import EventBus
from snorty.core.decoder import EveDecoder
from snorty.core.repository import AlertRepository
from snorty.sensor import Sensor, SensorConfig
from snorty.sensor.port import SuricataAdapter
from snorty.snort.models import Interface, RunResult, SnortError
from snorty.suricata import SuricataPaths, check_config, local_interfaces, start_live
from snorty.suricata.service import check_command, live_command

PATHS = SuricataPaths(exe=Path("s.exe"), conf=Path("s.yaml"), log_dir=Path("logs"))


class FakeRunner:
    def __init__(self, result: RunResult | SnortError) -> None:
        self.result = result
        self.calls: list[list[str]] = []

    async def __call__(self, argv: Sequence[str], *, timeout: float) -> RunResult:
        self.calls.append(list(argv))
        if isinstance(self.result, SnortError):
            raise self.result
        return self.result


def hostname_answer(*addresses: str) -> object:
    return lambda _: ("host", [], list(addresses))


def test_commands_are_argv_lists() -> None:
    assert check_command(PATHS) == ["s.exe", "-T", "-c", "s.yaml", "-l", "logs"]
    assert check_command(PATHS, conf=Path("x.yaml"))[3] == "x.yaml"
    iface = Interface(0, "", "192.168.1.5", "", "")
    assert live_command(PATHS, iface) == [
        "s.exe", "-c", "s.yaml", "-i", "192.168.1.5", "-l", "logs",
    ]  # fmt: skip


def test_alert_file_is_eve_json() -> None:
    assert PATHS.alert_file == "eve.json"


def test_local_interfaces_skip_loopback_and_repeats(monkeypatch: pytest.MonkeyPatch) -> None:
    answer = hostname_answer("127.0.0.1", "10.0.0.2", "10.0.0.2", "10.0.0.3")
    monkeypatch.setattr(socket, "gethostbyname_ex", answer)
    assert [i.ip for i in local_interfaces()] == ["10.0.0.2", "10.0.0.3"]


def test_local_interfaces_without_a_hostname_answer_are_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(_: str) -> tuple[str, list[str], list[str]]:
        raise OSError

    monkeypatch.setattr(socket, "gethostbyname_ex", boom)
    assert local_interfaces() == []


async def test_check_config_ok_reads_the_rule_count() -> None:
    out = RunResult(0, "", "<Notice> - 42 rules successfully loaded, 0 rules failed")
    check = await check_config(PATHS, FakeRunner(out))
    assert (check.ok, check.rule_count, check.errors) == (True, 42, ())


async def test_check_config_failure_reports_error_lines() -> None:
    out = RunResult(1, "", "<Error> - [ERRCODE: SC_ERR_X(1)] - bad rule\nother")
    check = await check_config(PATHS, FakeRunner(out))
    assert not check.ok
    assert check.errors == ("<Error> - [ERRCODE: SC_ERR_X(1)] - bad rule",)


async def test_check_config_failure_without_text_still_says_something() -> None:
    check = await check_config(PATHS, FakeRunner(RunResult(2, "", "")))
    assert check.errors == ("suricata exited with code 2 and no error text",)


async def test_check_config_missing_exe_is_a_result_not_a_raise() -> None:
    check = await check_config(PATHS, FakeRunner(SnortError("cannot start s.exe")))
    assert (check.ok, check.errors) == (False, ("cannot start s.exe",))


async def test_start_needs_an_ipv4_address() -> None:
    with pytest.raises(SnortError, match="no IPv4"):
        await start_live(PATHS, Interface(1, "", None, "", ""))


async def test_adapter_looks_for_suricata_exe_not_snort_exe() -> None:
    row = '"suricata.exe","77","Console","1","9 K"\n'
    adapter = SuricataAdapter(PATHS, FakeRunner(RunResult(0, row, "")))
    assert await adapter.is_snort_running(77) is True
    other = SuricataAdapter(PATHS, FakeRunner(RunResult(0, '"snort.exe","77","c","1","9 K"', "")))
    assert await other.is_snort_running(77) is False


async def test_sensor_reads_eve_json_from_the_log_dir(tmp_path: Path) -> None:
    log_dir = tmp_path / "log"
    log_dir.mkdir()
    event = {
        "timestamp": "2026-11-17T10:15:30.000001+0000",
        "flow_id": 5,
        "event_type": "alert",
        "src_ip": "10.0.0.5",
        "dest_ip": "203.0.113.9",
        "proto": "UDP",
        "alert": {"signature_id": 1, "signature": "test", "severity": 2},
    }
    text = json.dumps({"event_type": "stats"}) + "\n" + json.dumps(event) + "\n"
    (log_dir / "eve.json").write_text(text)
    repo = AlertRepository(tmp_path / "a.db")
    paths = SuricataPaths(log_dir=log_dir)
    sensor = Sensor(
        SensorConfig(paths=paths),
        SuricataAdapter(paths),
        repo,
        EventBus(),
        clock=lambda: 0.0,
        sleep=asyncio.sleep,
        tz=UTC,
        decoder=EveDecoder(),
    )
    await sensor._poll_once()
    status = sensor.status()
    assert (status.alerts_seen, status.unparsed) == (1, 0)
    repo.close()


async def test_check_config_reads_the_e_prefixed_errors_of_this_build() -> None:
    err = "E: detect-parse: unknown rule keyword 'file.magic'.\ni: suricata: not an error"
    check = await check_config(PATHS, FakeRunner(RunResult(1, "", err)))
    assert check.errors == ("E: detect-parse: unknown rule keyword 'file.magic'.",)
