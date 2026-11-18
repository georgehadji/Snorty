"""The pulled MISP OSINT feed (CIRCL) and the CERT Polska list, and how enrich uses them."""

import hashlib
import json
from pathlib import Path

from test_host_context import stored, with_ends
from test_repository import make_alert

from snorty.core.bus import EventBus
from snorty.core.models import FlowFact
from snorty.core.repository import AlertRepository
from snorty.enrich import EnrichService, ReverseDns
from snorty.enrich.osint import OsintIndex, parse_cert_pl
from snorty.enrich.service import flow_names


def md5(value: str) -> str:
    return hashlib.md5(value.encode(), usedforsecurity=False).hexdigest()


def event(info: str, date: str, tlp: str = "tlp:white") -> dict[str, object]:
    return {"info": info, "date": date, "Tag": [{"name": "type:OSINT"}, {"name": tlp}]}


MANIFEST = json.dumps(
    {
        "old": event("Old report", "2019-01-01"),
        "new": event("New   report\non a  campaign", "2026-11-01", "tlp:clear"),
        "amber": event("Not for sharing", "2026-11-02", "tlp:amber"),
    }
)
HASHES = [
    f"{md5('8.8.8.8')},old",
    f"{md5('8.8.8.8')},new",
    f"{md5('8.8.8.8')},new",  # one report naming it twice counts once
    f"{md5('evil.example')},old",
    f"{md5('secret.example')},amber",  # only shareable reports are used
    "nothex,old",
    f"{'zz' * 16},old",
    "",
]


def test_the_osint_index_counts_the_reports_and_names_the_newest() -> None:
    index = OsintIndex.parse(MANIFEST, HASHES)
    assert len(index) == 4
    assert index.find("8.8.8.8") == (
        "8.8.8.8 is mentioned in 2 reports; newest: New report on a campaign (2026-11-01)"
    )
    assert index.find("evil.example") == (
        "evil.example is mentioned in 1 report; newest: Old report (2019-01-01)"
    )
    assert index.find("secret.example") is None and index.find("1.1.1.1") is None


def test_a_broken_or_missing_feed_is_an_empty_index() -> None:
    assert len(OsintIndex.parse("", HASHES)) == 0
    assert len(OsintIndex.parse("{not json", HASHES)) == 0
    assert len(OsintIndex.parse("[1, 2]", HASHES)) == 0
    assert OsintIndex().find("8.8.8.8") is None


def test_the_cert_pl_list_matches_a_name_or_a_parent_domain() -> None:
    listed = parse_cert_pl("# header\nphish.example\n\nBad-Bank.example.\n")
    assert len(listed) == 2
    assert listed.find("phish.example") == "CERT Polska phishing warning list: phish.example"
    assert listed.find("login.Bad-Bank.example.") == (
        "CERT Polska phishing warning list: bad-bank.example"
    )
    assert listed.find("example") is None and listed.find("other.example") is None


def test_flow_names_are_the_host_names_without_paths_or_fingerprints() -> None:
    facts = [
        ("dns", "Evil.Example."),
        ("http", "evil.example/login.php"),
        ("tls", "cdn.example"),
        ("ja3", "0" * 32),
    ]
    assert flow_names(facts) == ["evil.example", "cdn.example"]


def seed(folder: Path) -> None:
    folder.mkdir(parents=True)
    (folder / "circl-manifest.json").write_text(MANIFEST, encoding="utf-8")
    (folder / "circl-hashes.csv").write_text("\n".join(HASHES), encoding="utf-8")
    (folder / "cert-pl-domains.txt").write_text("phish.example\n", encoding="utf-8")


def service(repo: AlertRepository, folder: Path) -> EnrichService:
    svc = EnrichService(EventBus(), repo, folder, rdns=ReverseDns(lambda ip: None))
    svc.load()
    return svc


def test_a_public_address_in_a_report_gets_a_note_but_is_not_bad(tmp_path: Path) -> None:
    seed(tmp_path / "enrich")
    repo = AlertRepository(tmp_path / "t.db")
    svc = service(repo, tmp_path / "enrich")
    a = stored(repo, with_ends(make_alert(1), dst_ip="8.8.8.8"))
    notes = svc.enrich(a)
    assert notes["osint"].startswith("8.8.8.8 is mentioned in 2 reports") and "bad" not in notes
    repo.close()


def test_names_seen_on_the_flow_are_checked_even_between_private_addresses(
    tmp_path: Path,
) -> None:
    seed(tmp_path / "enrich")
    repo = AlertRepository(tmp_path / "t.db")
    svc = service(repo, tmp_path / "enrich")
    a = stored(repo, with_ends(make_alert(1), raw="eve:7:1000:t"))  # a DNS alert to the router
    repo.add_flow_facts(
        [FlowFact(7, "dns", "login.phish.example", a.ts), FlowFact(7, "tls", "evil.example", a.ts)]
    )
    notes = svc.enrich(a)
    assert notes == {
        "bad": "CERT Polska phishing warning list: phish.example",
        "osint": "evil.example is mentioned in 1 report; newest: Old report (2019-01-01)",
    }
    assert repo.annotations(a.id) == notes
    repo.close()
