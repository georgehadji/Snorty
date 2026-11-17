from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

from dash_fakes import alert, make_services
from starlette.testclient import TestClient

from snorty.core.models import Conn, FlowFact, Lookup
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
    html = c.get(f"/alerts/{alert_id}/context").text
    assert "TLS server name" not in html and "This connection" not in html


def test_the_alert_detail_shows_its_connection_and_what_happened_around_it(
    tmp_path: Path,
) -> None:
    services = make_services(tmp_path)
    a = replace(alert(2003, msg="z"), raw="eve:42:2003:t", dst_ip="203.0.113.9")
    services.repo.add(a)
    alert_id = services.repo.query(limit=1)[0].id
    c = TestClient(build_app(services, token=TOKEN, port=PORT), base_url=f"http://127.0.0.1:{PORT}")
    assert "still open, or not logged yet" in c.get(f"/alerts/{alert_id}/context").text

    def conn(flow: int, start: datetime, sent: int, src: str = "10.0.0.1") -> Conn:
        end = start + timedelta(seconds=30)
        return Conn(
            flow,
            start,
            end,
            "TCP",
            "tls",
            src,
            5000,
            "203.0.113.9",
            443,
            3,
            3,
            sent,
            9000,
            "closed",
        )

    services.repo.add_context(
        [conn(42, a.ts, 2_500_000), conn(43, a.ts + timedelta(minutes=1), 400, src="10.0.0.7")],
        [Lookup(a.ts - timedelta(minutes=2), "10.0.0.1", "<b>.example", "203.0.113.9")],
    )
    html = c.get(f"/alerts/{alert_id}/context").text
    assert "2.5 MB sent, 9 KB received over 30 s, closed" in html  # its own connection
    assert "&lt;b&gt;.example" in html and "10.0.0.1" in html  # the lookup, escaped
    assert "TCP tls 10.0.0.7:5000 to 203.0.113.9:443, 400 B out / 9 KB in" in html  # the other
    assert "2.5 MB out" not in html  # the alert's own flow is not listed again
