"""Phase 3: notes on alerts, which program made a connection, and what public data says."""

import asyncio
import gzip
import json
import os
import socket
import struct
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

import pytest
from test_repository import make_alert

from snorty.attribution import AttributionService, Owner
from snorty.core.bus import EventBus
from snorty.core.events import AlertFlagged, AlertRaised
from snorty.core.models import Alert
from snorty.core.repository import AlertRepository
from snorty.enrich import EnrichService, ReverseDns
from snorty.enrich.ranges import RangeTable, parse_drop, parse_feodo
from snorty.winnet.lookup import WinConnectionLookup, parse_tcp_rows, parse_udp_rows

LOCAL = "10.0.0.2"


async def eventually(check) -> None:  # type: ignore[no-untyped-def]
    for _ in range(400):
        if check():
            return
        await asyncio.sleep(0.005)
    raise AssertionError("condition not met in time")


def stored(repo: AlertRepository, alert: Alert) -> Alert:
    repo.add(alert)
    return repo.query()[0]


def with_ends(alert: Alert, **kw: object) -> Alert:
    fields = {f: getattr(alert, f) for f in alert.__dataclass_fields__}
    fields.update(kw)
    return Alert(**fields)


# --- notes on alerts ------------------------------------------------------------------------


def test_a_note_is_replaced_by_a_later_one_of_the_same_kind(tmp_path: Path) -> None:
    repo = AlertRepository(tmp_path / "t.db")
    a = stored(repo, make_alert(1))
    repo.annotate(a.id, "country", "US")
    repo.annotate(a.id, "asn", "AS15169 Google")
    repo.annotate(a.id, "country", "DE")
    assert repo.annotations(a.id) == {"country": "DE", "asn": "AS15169 Google"}
    repo.close()


def test_a_note_for_a_deleted_alert_is_skipped_and_deleting_an_alert_removes_its_notes(
    tmp_path: Path,
) -> None:
    repo = AlertRepository(tmp_path / "t.db")
    repo.annotate(999, "country", "US")  # never stored
    assert repo.annotations(999) == {}
    a = stored(repo, make_alert(1))
    repo.annotate(a.id, "country", "US")
    repo.prune(datetime(2100, 1, 1, tzinfo=UTC))
    assert repo.annotations(a.id) == {}
    repo.close()


# --- the Windows connection table -----------------------------------------------------------


def raw_ip(text: str) -> int:
    return struct.unpack("<I", socket.inet_aton(text))[0]


def raw_port(port: int) -> int:
    return ((port & 0xFF) << 8) | (port >> 8)


def tcp_table(*rows: tuple[str, int, int]) -> bytes:
    body = b"".join(
        struct.pack("<6I", 5, raw_ip(ip), raw_port(port), raw_ip("1.2.3.4"), raw_port(443), pid)
        for ip, port, pid in rows
    )
    return struct.pack("<I", len(rows)) + body


def udp_table(*rows: tuple[str, int, int]) -> bytes:
    body = b"".join(struct.pack("<3I", raw_ip(ip), raw_port(port), pid) for ip, port, pid in rows)
    return struct.pack("<I", len(rows)) + body


def test_the_tcp_and_udp_tables_are_read_with_ports_in_the_right_order() -> None:
    (tcp,) = parse_tcp_rows(tcp_table((LOCAL, 51234, 4242)))
    assert (tcp.ip, tcp.port, tcp.pid) == (LOCAL, 51234, 4242)
    (udp,) = parse_udp_rows(udp_table(("0.0.0.0", 5353, 77)))
    assert (udp.ip, udp.port, udp.pid) == ("0.0.0.0", 5353, 77)
    assert parse_tcp_rows(tcp_table()) == []


def test_an_exact_address_beats_a_wildcard_and_the_idle_process_is_ignored() -> None:
    table = tcp_table(("0.0.0.0", 8080, 10), (LOCAL, 8080, 20), (LOCAL, 9090, 0))
    lookup = WinConnectionLookup(lambda proto: table, image=lambda pid: f"C:\\app{pid}.exe")
    assert lookup.owner("TCP", LOCAL, 8080) == Owner(20, "C:\\app20.exe")
    assert lookup.owner("TCP", "10.9.9.9", 8080) == Owner(10, "C:\\app10.exe")
    assert lookup.owner("TCP", LOCAL, 9090) is None
    assert lookup.owner("TCP", LOCAL, 1) is None


@pytest.mark.skipif(sys.platform != "win32", reason="reads the Windows connection table")
def test_the_real_table_names_this_process_as_the_owner_of_its_own_listener() -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen()
        found = WinConnectionLookup().owner("TCP", "127.0.0.1", s.getsockname()[1])
    assert found is not None and found.pid == os.getpid()
    assert Path(found.image).name.lower().startswith("python")


# --- attribution ----------------------------------------------------------------------------


class FakeLookup:
    def __init__(self, owner: Owner | None) -> None:
        self.answer = owner
        self.asked: list[tuple[str, str, int]] = []

    def owner(self, proto: Literal["TCP", "UDP"], local_ip: str, local_port: int) -> Owner | None:
        self.asked.append((proto, local_ip, local_port))
        return self.answer


def test_the_local_end_of_the_flow_is_looked_up_and_the_answer_is_stored(tmp_path: Path) -> None:
    repo = AlertRepository(tmp_path / "t.db")
    lookup = FakeLookup(Owner(4242, "C:\\Tools\\nc.exe"))
    svc = AttributionService(EventBus(), repo, lookup, lambda: LOCAL)
    a = stored(repo, make_alert(1))  # 10.0.0.1:1234 -> 10.0.0.2:80
    svc.attribute(a)
    assert lookup.asked == [("TCP", LOCAL, 80)]
    note = json.loads(repo.annotations(a.id)["process"])
    assert note == {"found": True, "pid": 4242, "image": "C:\\Tools\\nc.exe", "via": "table"}
    repo.close()


def test_a_connection_that_is_gone_is_recorded_as_not_found(tmp_path: Path) -> None:
    repo = AlertRepository(tmp_path / "t.db")
    svc = AttributionService(EventBus(), repo, FakeLookup(None), lambda: LOCAL)
    a = stored(repo, make_alert(1))
    svc.attribute(a)
    assert json.loads(repo.annotations(a.id)["process"]) == {"found": False}
    repo.close()


def test_alerts_that_are_not_about_this_pc_or_not_tcp_or_udp_are_not_looked_up(
    tmp_path: Path,
) -> None:
    repo = AlertRepository(tmp_path / "t.db")
    lookup = FakeLookup(Owner(1, "x"))
    svc = AttributionService(EventBus(), repo, lookup, lambda: LOCAL)
    elsewhere = stored(repo, make_alert(1))
    svc.attribute(with_ends(elsewhere, dst_ip="10.5.5.5"))  # neither end is this PC
    icmp = stored(repo, make_alert(2))
    svc.attribute(with_ends(icmp, proto="ICMP"))
    svc2 = AttributionService(EventBus(), repo, lookup, lambda: None)  # no network
    svc2.attribute(elsewhere)
    assert lookup.asked == [] and repo.annotations(elsewhere.id) == {}
    repo.close()


async def test_live_alerts_are_attributed_as_they_arrive(tmp_path: Path) -> None:
    repo = AlertRepository(tmp_path / "t.db")
    bus = EventBus()
    svc = AttributionService(bus, repo, FakeLookup(Owner(7, "a.exe")), lambda: LOCAL)
    await svc.start()
    a = stored(repo, make_alert(1))
    bus.publish(AlertRaised(a))
    await eventually(lambda: "process" in repo.annotations(a.id))
    await svc.stop()
    repo.close()


# --- range tables ---------------------------------------------------------------------------


def test_a_range_table_finds_the_range_an_address_falls_in() -> None:
    table = RangeTable.from_networks([("10.0.0.0/8", "private"), ("8.8.8.0/24", "dns")])
    assert table.find("8.8.8.8") == "dns" and table.find("10.200.1.1") == "private"
    assert table.find("8.8.9.1") is None and table.find("1.1.1.1") is None
    assert table.find("not an address") is None and table.find("2001:db8::1") is None


def test_dbip_rows_become_labelled_ranges_and_bad_rows_are_skipped() -> None:
    lines = ["1.0.0.0,1.0.0.255,AU", "garbage", "2001:db8::,2001:db8::ffff,ZZ", "5.5.5.5"]
    table = RangeTable.from_csv(lines, slice(0, 1))
    assert table.find("1.0.0.77") == "AU" and table.find("2001:db8::10") == "ZZ"
    asn = RangeTable.from_csv(["8.8.8.0,8.8.8.255,15169,GOOGLE"], slice(0, 2))
    assert asn.find("8.8.8.8") == "15169 GOOGLE"


def test_the_feodo_and_drop_lists_are_parsed() -> None:
    feodo = parse_feodo("# Feodo\n45.9.148.10\n\nnope\n")
    assert feodo.find("45.9.148.10") == "Feodo Tracker botnet C2" and len(feodo) == 1
    drop = parse_drop("; Spamhaus\n198.51.100.0/24 ; SBL12345\n")
    assert drop.find("198.51.100.9") == "Spamhaus DROP SBL12345"


def test_ranges_given_out_of_order_are_sorted_and_the_last_equal_start_wins() -> None:
    top = 2**128 - 1
    table = RangeTable(
        [(4, 30, 40, "late"), (6, top - 4, top, "top"), (4, 10, 20, "b"), (4, 10, 20, "a")]
    )
    assert len(table) == 4 and table.find("0.0.0.15") == "b" and table.find("0.0.0.35") == "late"
    assert table.find("0.0.0.25") is None and table.find("0.0.0.9") is None
    assert table.find("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") == "top"
    assert table.find("0.0.0.30") == "late" and table.find("::1e") is None


# --- reverse DNS ----------------------------------------------------------------------------


def test_names_and_misses_are_cached_until_they_expire() -> None:
    now = [0.0]
    calls: list[str] = []

    def resolve(ip: str) -> str:
        calls.append(ip)
        if ip == "9.9.9.9":
            raise socket.herror(1, "no name")
        return f"host-{ip}"

    dns = ReverseDns(resolve, ttl=100, clock=lambda: now[0])
    assert dns.name("8.8.8.8") == "host-8.8.8.8" and dns.name("8.8.8.8") == "host-8.8.8.8"
    assert dns.name("9.9.9.9") is None and dns.name("9.9.9.9") is None
    assert calls == ["8.8.8.8", "9.9.9.9"]
    now[0] = 101
    dns.name("8.8.8.8")
    assert calls == ["8.8.8.8", "9.9.9.9", "8.8.8.8"]


def test_the_cache_is_bounded() -> None:
    dns = ReverseDns(lambda ip: ip, size=3)
    for n in range(10):
        dns.name(f"8.8.8.{n}")
    assert len(dns._cache) == 3


# --- the enrichment pipeline ----------------------------------------------------------------

BAD = "45.9.148.10"


def seed(folder: Path) -> None:
    folder.mkdir(parents=True)
    (folder / "feodo.txt").write_text(f"# c2\n{BAD}\n", encoding="utf-8")
    (folder / "drop.txt").write_text("; drop\n198.51.100.0/24 ; SBL1\n", encoding="utf-8")
    (folder / "dbip-country.csv").write_text("8.8.8.0,8.8.8.255,US\n", encoding="utf-8")
    (folder / "dbip-asn.csv").write_text("8.8.8.0,8.8.8.255,15169,GOOGLE\n", encoding="utf-8")


def test_a_public_address_gets_a_country_a_network_and_a_name(tmp_path: Path) -> None:
    repo = AlertRepository(tmp_path / "t.db")
    seed(tmp_path / "enrich")
    svc = EnrichService(
        EventBus(), repo, tmp_path / "enrich", rdns=ReverseDns(lambda ip: "dns.google")
    )
    svc.load()
    a = stored(repo, make_alert(1))
    notes = svc.enrich(with_ends(a, dst_ip="8.8.8.8"))
    assert notes == {"country": "US", "asn": "15169 GOOGLE", "rdns": "dns.google"}
    assert repo.annotations(a.id) == notes
    repo.close()


def test_a_flow_between_private_addresses_is_not_looked_up(tmp_path: Path) -> None:
    repo = AlertRepository(tmp_path / "t.db")
    seed(tmp_path / "enrich")
    names: list[str] = []
    svc = EnrichService(
        EventBus(), repo, tmp_path / "enrich", rdns=ReverseDns(lambda ip: names.append(ip) or ip)
    )
    svc.load()
    a = stored(repo, make_alert(1))
    assert svc.enrich(a) == {} and names == [] and repo.annotations(a.id) == {}
    repo.close()


def test_missing_data_files_just_mean_no_notes(tmp_path: Path) -> None:
    repo = AlertRepository(tmp_path / "t.db")
    svc = EnrichService(EventBus(), repo, tmp_path / "nothing-here")
    svc.load()
    a = stored(repo, make_alert(1))
    assert svc.enrich(with_ends(a, dst_ip="8.8.8.8")) == {}
    repo.close()


async def test_a_known_bad_address_raises_a_flag(tmp_path: Path) -> None:
    repo = AlertRepository(tmp_path / "t.db")
    seed(tmp_path / "enrich")
    bus = EventBus()
    flags = bus.subscribe(accept=lambda e: isinstance(e, AlertFlagged))
    svc = EnrichService(bus, repo, tmp_path / "enrich")
    await svc.start()
    a = stored(repo, with_ends(make_alert(1), src_ip=BAD))
    bus.publish(AlertRaised(a))
    event = await asyncio.wait_for(anext(aiter(flags)), 2)
    assert isinstance(event, AlertFlagged) and event.reason == "Feodo Tracker botnet C2"
    assert repo.annotations(a.id)["bad"] == "Feodo Tracker botnet C2"
    other = stored(repo, with_ends(make_alert(2), src_ip="8.8.8.8"))
    bus.publish(AlertRaised(other))
    await eventually(lambda: "country" in repo.annotations(other.id))
    assert "bad" not in repo.annotations(other.id)
    await svc.stop()
    repo.close()


def test_stale_files_are_downloaded_once_and_fresh_ones_are_left_alone(tmp_path: Path) -> None:
    repo = AlertRepository(tmp_path / "t.db")
    asked: list[str] = []

    def fetch(url: str) -> bytes:
        asked.append(url)
        return gzip.compress(b"1.0.0.0,1.0.0.255,AU\n") if url.endswith(".gz") else b"1.2.3.4\n"

    now = datetime(2026, 11, 17, tzinfo=UTC)
    folder = tmp_path / "enrich"
    svc = EnrichService(EventBus(), repo, folder, fetch=fetch, now=lambda: now)
    assert svc.refresh() is True
    assert sorted(asked) == sorted(
        [
            "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            "https://www.spamhaus.org/drop/drop.txt",
            "https://download.db-ip.com/free/dbip-country-lite-2026-11.csv.gz",
            "https://download.db-ip.com/free/dbip-asn-lite-2026-11.csv.gz",
            "https://hole.cert.pl/domains/v2/domains.txt",
            "https://www.circl.lu/doc/misp/feed-osint/manifest.json",
            "https://www.circl.lu/doc/misp/feed-osint/hashes.csv",
        ]
    )
    assert (folder / "dbip-country.csv").read_bytes() == b"1.0.0.0,1.0.0.255,AU\n"
    assert not list(folder.glob("*.part"))
    asked.clear()
    assert svc.refresh() is False and asked == []  # all fresh
    later = EnrichService(
        EventBus(),
        repo,
        folder,
        fetch=fetch,
        clock=lambda: (now + timedelta(days=2)).timestamp() + 4e9,
    )
    assert later.refresh() is True  # the lists are a day old, DB-IP a month
    repo.close()


def test_a_failed_download_keeps_the_old_file(tmp_path: Path) -> None:
    repo = AlertRepository(tmp_path / "t.db")
    folder = tmp_path / "enrich"
    seed(folder)
    old = (folder / "feodo.txt").read_text(encoding="utf-8")

    def down(url: str) -> bytes:
        raise OSError("offline")

    svc = EnrichService(EventBus(), repo, folder, fetch=down, clock=lambda: 4e9)
    assert svc.refresh() is False
    assert (folder / "feodo.txt").read_text(encoding="utf-8") == old
    repo.close()
