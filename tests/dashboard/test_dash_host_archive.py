from dataclasses import replace
from pathlib import Path

import pytest
from dash_fakes import alert, make_services
from starlette.testclient import TestClient

from snorty.core.models import FlowFact
from snorty.dashboard.app import build_app
from snorty.dashboard.security import valid_host

TOKEN = "t" * 64
PORT = 8765
POST = {"X-Snorty-Token": TOKEN}


def test_valid_host_normalises_and_refuses_broad_or_odd_names() -> None:
    assert valid_host(" CDN.Example.com. ") == "cdn.example.com"
    for bad in ("com", "", "a..b", "a b.com", "x" * 250 + ".com", "evil.com/x", "%.com"):
        with pytest.raises(ValueError, match="host"):
            valid_host(bad)


def test_the_button_adds_a_host_rule_and_acknowledges_matching_alerts(tmp_path: Path) -> None:
    services = make_services(tmp_path)
    a = replace(alert(2001, msg="x"), raw="eve:42:2001:t")
    services.repo.add(a)
    services.repo.add_flow_facts([FlowFact(42, "tls", "cdn.example.com", a.ts)])
    alert_id = services.repo.query(limit=1)[0].id
    c = TestClient(build_app(services, token=TOKEN, port=PORT), base_url=f"http://127.0.0.1:{PORT}")
    panel = c.get(f"/alerts/{alert_id}/context").text
    assert 'hx-post="/triage/archive-host?host=cdn.example.com"' in panel

    assert c.post("/triage/archive-host?host=example.com").status_code in (401, 403)
    r = c.post("/triage/archive-host?host=Example.com", headers=POST)
    assert r.status_code == 200 and "(1 now)" in r.text
    assert services.repo.archive_rules()[0].host == "example.com"
    assert "example.com" in c.get("/inbox").text
    assert c.post("/triage/archive-host?host=com", headers=POST).status_code == 422
