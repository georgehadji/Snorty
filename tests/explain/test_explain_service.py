import asyncio
import logging
from collections.abc import AsyncIterator, Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from snorty.core.bus import EventBus
from snorty.core.events import AlertRaised
from snorty.core.models import Alert
from snorty.core.repository import AlertRepository
from snorty.explain import ExplainError, ExplainService


def make_alert(sid: int = 2522401, rev: int = 6440) -> Alert:
    return Alert(
        ts=datetime(2026, 11, 17, 12, tzinfo=UTC), gid=1, sid=sid, rev=rev, msg="m",
        classification=None, priority=2, proto="TCP", src_ip="1.2.3.4", src_port=1,
        dst_ip="5.6.7.8", dst_port=2, raw=f"raw-{sid}-{rev}",
    )  # fmt: skip


class FakeExplainer:
    model = "fake:1b"

    def __init__(self) -> None:
        self.style = "English/home"
        self.calls: list[str] = []
        self.error: ExplainError | None = None
        self.gate: asyncio.Event | None = None  # when set, each answer waits for it

    async def explain(self, rule_text: str, alert: Alert) -> str:
        if self.gate is not None:
            await self.gate.wait()
        if self.error:
            raise self.error
        self.calls.append(rule_text)
        return f"reading of {alert.sid} in {self.style}"


class Rig:
    def __init__(self, tmp_path: Path) -> None:
        self.repo = AlertRepository(tmp_path / "t.db")
        self.explainer = FakeExplainer()
        self.rules: dict[int, str] = {
            2522401: "alert tcp any any -> any any (sid:2522401;)",
            2000001: "alert tcp any any -> any any (sid:2000001;)",
        }
        self.bus = EventBus()
        self.svc = ExplainService(
            self.repo, self.explainer, self.rules.get, bus=self.bus, retry_after=0.05
        )

    def stored(self, alert: Alert) -> int:
        """Store `alert`; the id it was given."""
        self.repo.add(alert)
        return self.repo.query(limit=1)[0].id


@pytest.fixture
async def rig(tmp_path: Path) -> AsyncIterator[Rig]:
    r = Rig(tmp_path)
    yield r
    await r.svc.stop()
    r.repo.close()


async def until(check: Callable[[], bool], timeout: float = 2.0) -> None:
    async with asyncio.timeout(timeout):
        while not check():
            await asyncio.sleep(0.01)


async def test_an_alert_is_explained_from_its_rule_text(rig: Rig) -> None:
    alert_id = rig.stored(make_alert())
    result = await rig.svc.explain(alert_id)
    assert (result.text, result.model, result.cached) == (
        "reading of 2522401 in English/home",
        "fake:1b",
        False,
    )
    assert rig.explainer.calls == [rig.rules[2522401]]


async def test_the_answer_is_kept_per_rule_version(rig: Rig) -> None:
    first = rig.stored(make_alert())
    second = rig.stored(replace(make_alert(), raw="another line"))  # same rule, another alert
    await rig.svc.explain(first)
    again = await rig.svc.explain(second)
    assert again.cached and again.text == "reading of 2522401 in English/home"
    assert len(rig.explainer.calls) == 1  # the model ran once


async def test_a_new_rule_revision_is_explained_again(rig: Rig) -> None:
    a = rig.stored(make_alert(rev=1))
    b = rig.stored(make_alert(rev=2))
    await rig.svc.explain(a)
    result = await rig.svc.explain(b)
    assert not result.cached and len(rig.explainer.calls) == 2


async def test_an_unknown_alert_and_a_missing_rule_are_clear_errors(rig: Rig) -> None:
    with pytest.raises(ExplainError, match="no longer exists"):
        await rig.svc.explain(999)
    rig.rules.clear()
    with pytest.raises(ExplainError, match="not found in the rules files"):
        await rig.svc.explain(rig.stored(make_alert()))


async def test_a_failed_explanation_is_not_saved(rig: Rig) -> None:
    alert_id = rig.stored(make_alert())
    rig.explainer.error = ExplainError("Ollama did not answer")
    with pytest.raises(ExplainError):
        await rig.svc.explain(alert_id)
    rig.explainer.error = None
    assert not (await rig.svc.explain(alert_id)).cached


async def test_another_language_or_reader_is_explained_again(rig: Rig) -> None:
    alert_id = rig.stored(make_alert())
    await rig.svc.explain(alert_id)
    rig.explainer.style = "Greek/office"
    result = await rig.svc.explain(alert_id)
    assert not result.cached and result.text.endswith("Greek/office")
    assert (await rig.svc.explain(alert_id)).cached  # the new one is kept in place of the old


async def test_a_rule_is_explained_in_the_background_the_first_time_it_fires(rig: Rig) -> None:
    await rig.svc.start()
    alert = make_alert()
    for _ in range(3):  # the same rule firing again is not asked twice
        rig.bus.publish(AlertRaised(alert))
    rig.bus.publish(AlertRaised(make_alert(sid=99)))  # not in the rules files: skipped quietly
    rig.bus.publish(AlertRaised(make_alert(sid=2000001)))
    await until(lambda: len(rig.explainer.calls) == 2)
    result = await rig.svc.explain(rig.stored(alert))
    assert result.cached and len(rig.explainer.calls) == 2


async def test_a_click_goes_before_the_background(rig: Rig) -> None:
    await rig.svc.start()
    rig.explainer.gate = gate = asyncio.Event()
    clicked = asyncio.create_task(rig.svc.explain(rig.stored(make_alert(sid=2000001))))
    await until(lambda: rig.svc._clicks == 1)
    rig.bus.publish(AlertRaised(make_alert()))  # arrives while the person waits
    await asyncio.sleep(0.05)
    gate.set()
    await clicked
    await until(lambda: len(rig.explainer.calls) == 2)
    assert rig.explainer.calls[0] == rig.rules[2000001]  # the click's rule ran first


async def test_the_background_pauses_when_the_model_fails(
    rig: Rig, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, "snorty.explain")
    await rig.svc.start()
    rig.explainer.error = ExplainError("Ollama did not answer on this PC; is it running?")
    rig.bus.publish(AlertRaised(make_alert()))
    await until(lambda: "paused" in caplog.text)
    rig.explainer.error = None
    rig.bus.publish(AlertRaised(make_alert(sid=2000001)))  # taken after the pause
    await until(lambda: rig.explainer.calls == [rig.rules[2000001]])


async def test_without_a_bus_nothing_runs_in_the_background(rig: Rig) -> None:
    quiet = ExplainService(rig.repo, rig.explainer, rig.rules.get)
    await quiet.start()
    assert rig.bus._subs == [] and quiet._task is None
    await quiet.stop()
