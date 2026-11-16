"""Test doubles for the dashboard: fake services that record calls and return scripted data."""

import asyncio
from datetime import UTC, datetime
from pathlib import Path

from snorty.core.bus import EventBus
from snorty.core.models import Alert
from snorty.core.repository import AlertRepository
from snorty.journal.service import JournalStatus
from snorty.lab.models import LabJob, LabResult
from snorty.notify.service import NotifyStatus
from snorty.packets import (
    AlertPacket,
    AlertPacketResult,
    Capabilities,
    Conversation,
    Decoded,
    DecodeResult,
    Launched,
    LaunchResult,
    Layer,
    PacketView,
    ProtocolRow,
    Recorded,
    RecordResult,
    Summary,
    SummaryResult,
)
from snorty.rules.blocks import MutedRule, Track
from snorty.rules.service import EditReport, UpdateReport
from snorty.rules.state import RulesState
from snorty.sensor import SensorStatus, State
from snorty.services import Services

T0 = datetime(2026, 11, 16, 12, 0, 0, tzinfo=UTC)


def alert(
    sid: int = 2000001,
    *,
    msg: str = "test alert",
    priority: int = 1,
    ts: datetime = T0,
    src_port: int | None = 4444,
) -> Alert:
    return Alert(
        ts=ts,
        gid=1,
        sid=sid,
        rev=1,
        msg=msg,
        classification="Misc",
        priority=priority,
        proto="TCP",
        src_ip="10.0.0.1",
        src_port=src_port,
        dst_ip="10.0.0.2",
        dst_port=80,
        raw=f"{sid}|{ts.isoformat()}|{msg}|{priority}",
    )


def status(state: State = State.STOPPED, **kw: object) -> SensorStatus:
    base: dict[str, object] = {
        "state": state,
        "reason": None,
        "interface": None,
        "pid": None,
        "started_at": None,
        "alerts_seen": 0,
        "last_alert_ts": None,
        "unparsed": 0,
        "restarts": 0,
        "last_error": None,
    }
    base.update(kw)
    return SensorStatus(**base)  # type: ignore[arg-type]


class FakeSensor:
    def __init__(self, state: State = State.STOPPED) -> None:
        self._status = status(state)
        self.calls: list[str] = []

    @property
    def state(self) -> State:
        return self._status.state

    def status(self) -> SensorStatus:
        return self._status

    def set_state(self, state: State, **kw: object) -> None:
        self._status = status(state, **kw)

    async def start(self) -> None:
        self.calls.append("start")
        self.set_state(State.RUNNING)

    async def stop(self) -> None:
        self.calls.append("stop")
        self.set_state(State.STOPPED)

    async def restart(self) -> None:
        self.calls.append("restart")
        self.set_state(State.RUNNING, restarts=self._status.restarts + 1)


class FakeRules:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.state = RulesState(
            last_md5="abc", updated_at="2026-11-16T03:00:00", rule_count=1234, result="updated"
        )
        self.muted_rules: list[MutedRule] = []
        self.home = ("[10.0.0.0/8]", "default")
        self.update_report = UpdateReport("updated", 1234, "abc", 0, "1234 rules")
        self.edit_report = EditReport(True, True, "done")
        self.delay = 0.0
        self.update_error = False

    async def update(self, *, force: bool = False) -> UpdateReport:
        self.calls.append(("update", force))
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.update_error:
            raise RuntimeError("secret internals")
        return self.update_report

    async def status(self) -> RulesState:
        return self.state

    async def muted(self) -> list[MutedRule]:
        return list(self.muted_rules)

    async def mute(
        self,
        sid: int,
        note: str = "",
        *,
        restart: bool = True,
        track: Track | None = None,
        ip: str | None = None,
    ) -> EditReport:
        self.calls.append(("mute", sid, note, restart) + ((track, ip) if track else ()))
        rule = MutedRule(sid, note, track, ip)
        if all(m.key != rule.key for m in self.muted_rules):
            self.muted_rules.append(rule)
        return self.edit_report

    async def unmute(
        self, sid: int, *, restart: bool = True, track: Track | None = None, ip: str | None = None
    ) -> EditReport:
        self.calls.append(("unmute", sid, restart) + ((track, ip) if track else ()))
        self.muted_rules = [m for m in self.muted_rules if m.key != (sid, track, ip)]
        return self.edit_report

    async def home_net(self) -> tuple[str, str]:
        return self.home

    async def set_home_net(self, value: str | None = None, *, restart: bool = True) -> EditReport:
        self.calls.append(("home_net", value, restart))
        return self.edit_report


class FakeJournal:
    def __init__(self) -> None:
        self.flushes = 0
        self.info = JournalStatus("C:/vault/Security/Snort", None, 0, None)

    def status(self) -> JournalStatus:
        return self.info

    async def flush(self) -> None:
        self.flushes += 1


class FakeNotify:
    def __init__(self) -> None:
        self.info = NotifyStatus(toasts_shown=0, min_priority=1)

    def status(self) -> NotifyStatus:
        return self.info


class FakeLab:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []
        self.result = LabResult(True)

    async def run(self, job: LabJob) -> LabResult:
        self.calls.append(("run", job))
        return self.result

    async def check(self, rules_text: str) -> LabResult:
        self.calls.append(("check", rules_text))
        return self.result


class FakePackets:
    def __init__(self) -> None:
        self.calls: list[tuple[Path, int]] = []
        self.summaries: list[Path] = []
        self.alert_calls: list[Alert] = []
        self.open_calls: list[Alert] = []
        self.can_open = True
        self.can_record = True
        self.recorded: list[tuple[str, int]] = []
        self.record_result: RecordResult = Recorded(2048)
        self.record_gate: asyncio.Event | None = None  # set it to hold a capture open
        self.launch: LaunchResult = Launched()
        self.summary: SummaryResult = Summary(
            (ProtocolRow("frame", 0, 3, 229), ProtocolRow("tcp", 1, 2, 154)),
            (Conversation("TCP", "10.0.0.5:40000", "10.0.0.9:80", 2, "154 bytes", "0.0010"),),
        )
        self.result: DecodeResult = Decoded(
            (
                PacketView(
                    1,
                    "0.000000",
                    "ICMP",
                    "10.0.0.1",
                    "10.0.0.2",
                    74,
                    "type 8 code 0",
                    (Layer("ip", (("ip.ttl", "64"),)),),
                    "0000  45 00",
                ),
            ),
            limit=200,
        )
        self.packet: AlertPacketResult = AlertPacket("exact", 1, b"PCAPDATA", self.result)

    def capabilities(self) -> Capabilities:
        return Capabilities(decode=True, open=self.can_open, record=self.can_record)

    async def record(self, device: str, seconds: int, target: Path) -> RecordResult:
        self.recorded.append((device, seconds))
        if self.record_gate is not None:
            target.write_bytes(b"partial")
            await self.record_gate.wait()
        if isinstance(self.record_result, Recorded):
            target.write_bytes(b"\xd4\xc3\xb2\xa1" + bytes(max(0, self.record_result.size - 4)))
        return self.record_result

    async def alert_packet(self, alert: Alert) -> AlertPacketResult:
        self.alert_calls.append(alert)
        return self.packet

    async def open_alert_packet(self, alert: Alert) -> LaunchResult:
        self.open_calls.append(alert)
        return self.launch

    async def decode(self, pcap: Path, limit: int = 200) -> DecodeResult:
        self.calls.append((pcap, limit))
        return self.result

    async def summarize(self, pcap: Path) -> SummaryResult:
        self.summaries.append(pcap)
        return self.summary


def make_services(tmp_path: Path) -> Services:
    return Services(
        sensor=FakeSensor(),
        rules=FakeRules(),
        journal=FakeJournal(),
        notify=FakeNotify(),
        lab=FakeLab(),
        repo=AlertRepository(tmp_path / "t.db"),
        bus=EventBus(),
        tz=UTC,
        data_dir=tmp_path,
        packets=FakePackets(),
    )
