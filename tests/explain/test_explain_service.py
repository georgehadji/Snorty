from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

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
        self.calls: list[str] = []
        self.error: ExplainError | None = None

    async def explain(self, rule_text: str, alert: Alert) -> str:
        if self.error:
            raise self.error
        self.calls.append(rule_text)
        return f"reading of {alert.sid}"


class Rig:
    def __init__(self, tmp_path: Path) -> None:
        self.repo = AlertRepository(tmp_path / "t.db")
        self.explainer = FakeExplainer()
        self.rules: dict[int, str] = {2522401: "alert tcp any any -> any any (sid:2522401;)"}
        self.svc = ExplainService(self.repo, self.explainer, self.rules.get)

    def stored(self, alert: Alert) -> int:
        """Store `alert`; the id it was given."""
        self.repo.add(alert)
        return self.repo.query(limit=1)[0].id


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[Rig]:
    r = Rig(tmp_path)
    yield r
    r.repo.close()


async def test_an_alert_is_explained_from_its_rule_text(rig: Rig) -> None:
    alert_id = rig.stored(make_alert())
    result = await rig.svc.explain(alert_id)
    assert (result.text, result.model, result.cached) == ("reading of 2522401", "fake:1b", False)
    assert rig.explainer.calls == [rig.rules[2522401]]


async def test_the_answer_is_kept_per_rule_version(rig: Rig) -> None:
    first = rig.stored(make_alert())
    second = rig.stored(replace(make_alert(), raw="another line"))  # same rule, another alert
    await rig.svc.explain(first)
    again = await rig.svc.explain(second)
    assert again.cached and again.text == "reading of 2522401"
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
