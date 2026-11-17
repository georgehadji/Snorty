from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from dash_fakes import alert, make_services
from starlette.testclient import TestClient

from snorty.dashboard.app import build_app
from snorty.explain import ExplainError, Explanation
from snorty.services import Services

TOKEN = "t" * 64
PORT = 8765
POST = {"X-Snorty-Token": TOKEN}


class FakeExplain:
    def __init__(self) -> None:
        self.calls: list[int] = []
        self.error: ExplainError | None = None
        self.cached = False

    async def explain(self, alert_id: int) -> Explanation:
        self.calls.append(alert_id)
        if self.error:
            raise self.error
        return Explanation("It <b>looks</b> for X.", "qwen3:8b", self.cached)


def make(tmp_path: Path, *, on: bool = True) -> tuple[TestClient, Services, FakeExplain]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    fake = FakeExplain()
    services = replace(make_services(tmp_path), explain=fake if on else None)
    app = build_app(services, token=TOKEN, port=PORT)
    return TestClient(app, base_url=f"http://127.0.0.1:{PORT}"), services, fake


def test_the_text_is_shown_escaped_with_its_model_and_a_warning(tmp_path: Path) -> None:
    c, _, fake = make(tmp_path)
    r = c.post("/alerts/7/explain", headers=POST)
    assert r.status_code == 200 and fake.calls == [7]
    assert "It &lt;b&gt;looks&lt;/b&gt; for X." in r.text and "<b>looks</b>" not in r.text
    assert "generated locally by qwen3:8b" in r.text and "can be wrong" in r.text
    assert "saved from earlier" not in r.text
    fake.cached = True
    assert "saved from earlier" in c.post("/alerts/7/explain", headers=POST).text


def test_a_failure_is_a_message_the_user_can_read(tmp_path: Path) -> None:
    c, _, fake = make(tmp_path)
    fake.error = ExplainError("Ollama did not answer on this PC; is it running?")
    r = c.post("/alerts/7/explain", headers=POST)
    assert r.status_code == 422 and "is it running?" in r.text


def test_the_post_needs_the_token(tmp_path: Path) -> None:
    c, _, fake = make(tmp_path)
    assert c.post("/alerts/7/explain").status_code in (401, 403)
    assert fake.calls == []


def test_the_route_is_a_404_when_explaining_is_off(tmp_path: Path) -> None:
    c, _, _ = make(tmp_path, on=False)
    assert c.post("/alerts/7/explain", headers=POST).status_code == 404


def test_alert_rows_offer_the_button_only_when_explaining_is_on(tmp_path: Path) -> None:
    now = datetime.now(UTC)  # /alerts shows the last 24 hours
    on, s, _ = make(tmp_path)
    s.repo.add(alert(2001, msg="x", ts=now))
    assert "/explain" in on.get("/alerts").text
    off, s2, _ = make(tmp_path / "off", on=False)
    s2.repo.add(alert(2001, msg="x", ts=now))
    assert "/explain" not in off.get("/alerts").text
