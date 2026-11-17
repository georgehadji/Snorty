from dataclasses import replace
from pathlib import Path

from dash_fakes import alert, make_services
from starlette.testclient import TestClient

from snorty.core.models import FlowFact
from snorty.dashboard.app import build_app
from snorty.rules.info import RuleInfo

TOKEN = "t" * 64
PORT = 8765


def test_alert_detail_shows_what_was_seen_on_its_flow(tmp_path: Path) -> None:
    services = make_services(tmp_path)
    a = replace(alert(2001, msg="x"), raw="eve:42:2001:t")
    services.repo.add(a)
    alert_id = services.repo.query(limit=1)[0].id
    services.repo.add_flow_facts([FlowFact(42, "tls", "<evil>.example", a.ts)])
    c = TestClient(build_app(services, token=TOKEN, port=PORT), base_url=f"http://127.0.0.1:{PORT}")
    r = c.get(f"/alerts/{alert_id}/context")
    assert r.status_code == 200
    assert "TLS server name" in r.text and "&lt;evil&gt;.example" in r.text


def test_the_alert_detail_shows_the_rules_attack_tags_as_outbound_links(tmp_path: Path) -> None:
    rule = (
        "alert ip any any -> any any (metadata: mitre_tactic_id TA0001, mitre_tactic_name "
        "Initial_Access, mitre_technique_id T1190, mitre_technique_name Exploit; sid:2001;)"
    )
    services = replace(make_services(tmp_path), rule_info=RuleInfo(lambda _: rule))
    services.repo.add(alert(2001, msg="x"))
    alert_id = services.repo.query(limit=1)[0].id
    c = TestClient(build_app(services, token=TOKEN, port=PORT), base_url=f"http://127.0.0.1:{PORT}")
    html = c.get(f"/alerts/{alert_id}/context").text
    assert "ATT&amp;CK" in html and "Initial Access" in html and "No host details" not in html
    assert 'href="https://attack.mitre.org/techniques/T1190/"' in html
    assert 'rel="noopener noreferrer"' in html


def test_an_alert_without_a_flow_has_no_such_lines(tmp_path: Path) -> None:
    services = make_services(tmp_path)
    services.repo.add(alert(2002, msg="y"))
    alert_id = services.repo.query(limit=1)[0].id
    c = TestClient(build_app(services, token=TOKEN, port=PORT), base_url=f"http://127.0.0.1:{PORT}")
    assert "TLS server name" not in c.get(f"/alerts/{alert_id}/context").text
