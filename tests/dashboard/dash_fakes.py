"""Test doubles for the dashboard: fake services that record calls and return scripted data."""

from datetime import UTC, datetime
from pathlib import Path

from snorty.core.bus import EventBus
from snorty.core.models import Alert
from snorty.core.repository import AlertRepository
from snorty.dashboard.services import Services
from snorty.lab.models import LabJob, LabResult
from snorty.rules.blocks import MutedRule
from snorty.rules.service import EditReport, UpdateReport
from snorty.rules.state import RulesState
from snorty.sensor import SensorStatus, State

T0 = datetime(2026, 11, 16, 12, 0, 0, tzinfo=UTC)


def alert(sid: int = 2000001, *, msg: str = "test alert", priority: int = 1, n: int = 0) -> Alert:
    return Alert(
        ts=T0.replace(second=n % 60, minute=n // 60),
        gid=1,
        sid=sid,
        rev=1,
        msg=msg,
        classification="Misc",
        priority=priority,
        proto="TCP",
        src_ip="10.0.0.1",
        src_port=4444,
        dst_ip="10.0.0.2",
        dst_port=80,
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

    async def update(self, *, force: bool = False) -> UpdateReport:
        self.calls.append(("update", force))
        return self.update_report

    async def status(self) -> RulesState:
        return self.state

    async def muted(self) -> list[MutedRule]:
        return list(self.muted_rules)

    async def mute(self, sid: int, note: str = "", *, restart: bool = True) -> EditReport:
        self.calls.append(("mute", sid, note, restart))
        if all(m.sid != sid for m in self.muted_rules):
            self.muted_rules.append(MutedRule(sid, note))
        return self.edit_report

    async def unmute(self, sid: int, *, restart: bool = True) -> EditReport:
        self.calls.append(("unmute", sid, restart))
        self.muted_rules = [m for m in self.muted_rules if m.sid != sid]
        return self.edit_report

    async def home_net(self) -> tuple[str, str]:
        return self.home

    async def set_home_net(self, value: str | None = None, *, restart: bool = True) -> EditReport:
        self.calls.append(("home_net", value, restart))
        return self.edit_report


class FakeJournal:
    def __init__(self) -> None:
        self.flushes = 0

    async def flush(self) -> None:
        self.flushes += 1


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


def make_services(tmp_path: Path) -> Services:
    return Services(
        sensor=FakeSensor(),
        rules=FakeRules(),
        journal=FakeJournal(),
        lab=FakeLab(),
        repo=AlertRepository(tmp_path / "t.db"),
        bus=EventBus(),
        tz=UTC,
        data_dir=tmp_path,
    )
