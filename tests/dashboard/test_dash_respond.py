from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from dash_fakes import T0, alert, make_services
from starlette.testclient import TestClient

from snorty.core.models import Block
from snorty.dashboard.app import build_app
from snorty.respond import Outcome
from snorty.services import Services

TOKEN = "t" * 64
PORT = 8765
POST = {"X-Snorty-Token": TOKEN}


class FakeRespond:
    def __init__(self) -> None:
        self.rows: list[Block] = []
        self.calls: list[tuple[str, object]] = []
        self.ok = True

    def blocks(self, state: str | None = None) -> list[Block]:
        return self.rows

    async def block(self, ip: str, hours: float | None, alert_id: int | None = None) -> Outcome:
        self.calls.append(("block", (ip, hours, alert_id)))
        if self.ok:
            self.rows = [Block(ip, T0, datetime(2026, 11, 18, tzinfo=UTC), alert_id, "active")]
        return Outcome(self.ok, f"{ip} blocked" if self.ok else f"{ip} not blocked: no")

    async def unblock(self, ip: str) -> Outcome:
        self.calls.append(("unblock", ip))
        self.rows = []
        return Outcome(True, f"{ip} unblocked")


def make(tmp_path: Path, *, on: bool = True) -> tuple[TestClient, Services, FakeRespond]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    fake = FakeRespond()
    services = replace(make_services(tmp_path), respond=fake if on else None)
    app = build_app(services, token=TOKEN, port=PORT)
    return TestClient(app, base_url=f"http://127.0.0.1:{PORT}"), services, fake


def test_block_calls_the_service_and_refreshes_the_card(tmp_path: Path) -> None:
    c, _, fake = make(tmp_path)
    r = c.post("/respond/block?ip=8.8.4.4&hours=2&alert_id=7", headers=POST)
    assert r.status_code == 200 and "8.8.4.4 blocked" in r.text
    assert fake.calls == [("block", ("8.8.4.4", 2.0, 7))]
    assert 'id="blocks-card"' in r.text and 'hx-post="/respond/unblock?ip=8.8.4.4"' in r.text


def test_a_refused_block_is_an_error_message(tmp_path: Path) -> None:
    c, _, fake = make(tmp_path)
    fake.ok = False
    r = c.post("/respond/block?ip=192.168.1.1", headers=POST)
    assert r.status_code == 422 and "not blocked" in r.text


def test_default_block_is_24_hours_without_an_alert(tmp_path: Path) -> None:
    c, _, fake = make(tmp_path)
    c.post("/respond/block?ip=8.8.4.4", headers=POST)
    assert fake.calls == [("block", ("8.8.4.4", 24.0, None))]


def test_unblock_calls_the_service(tmp_path: Path) -> None:
    c, _, fake = make(tmp_path)
    r = c.post("/respond/unblock?ip=8.8.4.4", headers=POST)
    assert r.status_code == 200 and "8.8.4.4 unblocked" in r.text
    assert fake.calls == [("unblock", "8.8.4.4")]


def test_posts_need_the_token(tmp_path: Path) -> None:
    c, _, fake = make(tmp_path)
    assert c.post("/respond/block?ip=8.8.4.4").status_code in (401, 403)
    assert fake.calls == []


def test_rules_page_lists_blocks_only_when_blocking_is_on(tmp_path: Path) -> None:
    c, _, fake = make(tmp_path)
    fake.rows = [Block("8.8.4.4", T0, None, None, "active")]
    html = c.get("/rules").text
    assert 'id="blocks-card"' in html and "8.8.4.4" in html and "until unblocked" in html
    off, _, _ = make(tmp_path / "off", on=False)
    assert 'id="blocks-card"' not in off.get("/rules").text


def test_alert_rows_offer_block_buttons_only_when_blocking_is_on(tmp_path: Path) -> None:
    on, s, _ = make(tmp_path)
    s.repo.add(alert(2001, msg="x", ts=T0))
    assert "/respond/block?ip=" in on.get("/alerts").text
    off, s2, _ = make(tmp_path / "off", on=False)
    s2.repo.add(alert(2001, msg="x", ts=T0))
    assert "/respond/block" not in off.get("/alerts").text


def test_every_route_is_a_404_when_blocking_is_off(tmp_path: Path) -> None:
    c, _, _ = make(tmp_path, on=False)
    assert c.get("/respond/blocks").status_code == 404
    assert c.post("/respond/block?ip=8.8.4.4", headers=POST).status_code == 404
    assert c.post("/respond/unblock?ip=8.8.4.4", headers=POST).status_code == 404
