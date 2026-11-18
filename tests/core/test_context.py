"""Connection and DNS context: Suricata's flow events and DNS answers, decoded and kept."""

import json
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

from snorty.core.decoder import EveDecoder, FastDecoder
from snorty.core.models import Anomaly, Conn, Lookup
from snorty.core.repository import AlertRepository

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
T0 = datetime(2026, 11, 17, 8, 0, tzinfo=UTC)
PEER = "203.0.113.9"
FIVE_MIN = timedelta(minutes=5)


def flow_event(**over: object) -> str:
    event: dict[str, object] = {
        "timestamp": "2026-11-17T10:16:50.552215+0200",
        "flow_id": 42,
        "event_type": "flow",
        "src_ip": "192.168.1.25",
        "src_port": 51000,
        "dest_ip": PEER,
        "dest_port": 443,
        "proto": "TCP",
        "app_proto": "tls",
        "flow": {
            "pkts_toserver": 12,
            "pkts_toclient": 10,
            "bytes_toserver": 3400,
            "bytes_toclient": 52000,
            "start": "2026-11-17T10:15:00.000000+0200",
            "end": "2026-11-17T10:16:10.000000+0200",
            "state": "closed",
        },
    }
    event.update(over)
    return json.dumps(event)


def dns_answer(dns: dict[str, object]) -> str:
    return json.dumps(
        {
            "timestamp": "2026-11-17T10:14:00.000000+0200",
            "flow_id": 7,
            "event_type": "dns",
            "src_ip": "192.168.1.25",
            "dest_ip": "192.168.1.254",
            "dns": dns,
        }
    )


def context(*lines: str) -> tuple[list[Conn], list[Lookup]]:
    d = EveDecoder()
    alerts, bad = d.decode(lines, NOW.year, (), NOW)
    assert alerts == [] and bad == 0  # context lines are never alerts nor failures
    return d.take_context()


def test_a_flow_event_becomes_a_connection() -> None:
    conns, lookups = context(flow_event())
    assert lookups == []
    (c,) = conns
    assert (c.flow_id, c.proto, c.app_proto, c.state) == (42, "TCP", "tls", "closed")
    assert (c.src_ip, c.src_port, c.dst_ip, c.dst_port) == ("192.168.1.25", 51000, PEER, 443)
    assert (c.pkts_out, c.pkts_in, c.bytes_out, c.bytes_in) == (12, 10, 3400, 52000)
    assert c.end - c.start == timedelta(seconds=70) and c.start.utcoffset() is not None


def test_a_flow_event_without_what_places_it_is_skipped() -> None:
    no_end = json.loads(flow_event())
    del no_end["flow"]["end"]
    broken = [flow_event(flow_id="x"), flow_event(src_ip=None), json.dumps(no_end)]
    assert context(*broken) == ([], [])
    odd = {**json.loads(flow_event())["flow"], "bytes_toserver": -1}
    (c,) = context(flow_event(flow=odd))[0]
    assert c.bytes_out == 0  # a nonsense count reads as nothing


def test_dns_answers_become_lookups_by_the_client_for_the_name_asked() -> None:
    answers = [
        {"rrname": "cdn.alias.example", "rrtype": "A", "rdata": PEER},
        {"rrname": "cdn.alias.example", "rrtype": "AAAA", "rdata": "2001:db8::1"},
        {"rrname": "www.example", "rrtype": "CNAME", "rdata": "cdn.alias.example"},
    ]
    v2 = dns_answer({"type": "answer", "rrname": "WWW.Example.", "answers": answers})
    v3 = dns_answer({"queries": [{"rrname": "v3.example"}], "answers": answers[:1]})
    _, lookups = context(v2, v3)
    assert [(x.client, x.name, x.address) for x in lookups] == [
        ("192.168.1.25", "www.example", PEER),
        ("192.168.1.25", "www.example", "2001:db8::1"),
        ("192.168.1.25", "v3.example", PEER),
    ]


def test_context_is_taken_once_and_forgotten_on_reset() -> None:
    d = EveDecoder()
    d.decode([flow_event()], NOW.year, (), NOW)
    assert len(d.take_context()[0]) == 1 and d.take_context() == ([], [])
    d.decode([flow_event()], NOW.year, (), NOW)
    d.reset()
    assert d.take_context() == ([], [])
    assert FastDecoder(UTC).take_context() == ([], [])  # Snort's alerts carry none


def conn(flow: int, start: datetime, src: str = "192.168.1.25", dst: str = PEER) -> Conn:
    end = start + timedelta(seconds=5)
    return Conn(flow, start, end, "TCP", None, src, 5000, dst, 443, 1, 1, 100, 200, None)


def test_connections_are_kept_once_and_found_near_a_time_from_either_side(
    tmp_path: Path,
) -> None:
    with closing(AlertRepository(tmp_path / "c.db")) as repo:
        here = conn(1, T0)
        inbound = conn(2, T0 + timedelta(minutes=2), src=PEER, dst="192.168.1.25")
        later = conn(3, T0 + timedelta(minutes=9))
        other = conn(4, T0, dst="198.51.100.1")
        repo.add_context([here, here, inbound, later, other], [])
        assert repo.conn(1) == here and repo.conn(99) is None
        assert [c.flow_id for c in repo.conns_near(PEER, T0, FIVE_MIN)] == [1, 2]
        assert [c.flow_id for c in repo.conns_near(PEER, T0, FIVE_MIN, skip=1)] == [2]
        assert len(repo.conns_near(PEER, T0, FIVE_MIN, limit=1)) == 1


def test_lookups_of_an_address_are_the_newest_per_client_and_name_before_a_time(
    tmp_path: Path,
) -> None:
    def ask(minutes: int, client: str, name: str, address: str = PEER) -> Lookup:
        return Lookup(T0 + timedelta(minutes=minutes), client, name, address)

    with closing(AlertRepository(tmp_path / "l.db")) as repo:
        repo.add_context(
            [],
            [
                ask(-50, "pc", "a.example"),
                ask(-10, "pc", "a.example"),
                ask(-10, "pc", "a.example"),  # read twice
                ask(-5, "phone", "b.example"),
                ask(-90, "pc", "too.old"),
                ask(+1, "pc", "after.alert"),
                ask(-1, "pc", "elsewhere", "198.51.100.1"),
            ],
        )
        found = repo.lookups_of(PEER, T0, timedelta(hours=1))
        assert [(x.client, x.name, x.ts) for x in found] == [
            ("phone", "b.example", T0 - timedelta(minutes=5)),
            ("pc", "a.example", T0 - timedelta(minutes=10)),
        ]


def test_old_context_is_pruned(tmp_path: Path) -> None:
    with closing(AlertRepository(tmp_path / "p.db")) as repo:
        old, new = T0 - timedelta(days=8), T0
        lookups = [Lookup(old, "pc", "a", "x"), Lookup(new, "pc", "b", "x")]
        repo.add_context([conn(1, old), conn(2, new)], lookups)
        repo.add_anomalies([anomaly(old, "INVALID_GAP"), anomaly(new, "INVALID_GAP")])
        repo.prune_context(T0 - timedelta(days=7))
        assert repo.conn(1) is None and repo.conn(2) is not None
        assert [x.name for x in repo.lookups_of("x", T0, timedelta(days=30))] == ["b"]
        assert repo.anomaly_counts(T0 - timedelta(days=30)) == [
            ("applayer", "http", "INVALID_GAP", 1)
        ]


# --- protocol anomalies -----------------------------------------------------------------


def anomaly_event(**info: object) -> str:
    return json.dumps(
        {
            "timestamp": "2026-11-17T10:16:50.552215+0200",
            "flow_id": 42,
            "event_type": "anomaly",
            "src_ip": "192.168.1.25",
            "src_port": 51000,
            "dest_ip": PEER,
            "dest_port": 80,
            "proto": "TCP",
            "anomaly": {"type": "applayer", "event": "INVALID_GAP", "layer": "proto_parser"} | info,
        }
    )


ALERT = json.dumps(
    {
        "timestamp": "2026-11-17T10:16:53.000000+0200",
        "flow_id": 42,
        "event_type": "alert",
        "src_ip": "192.168.1.25",
        "src_port": 51000,
        "dest_ip": PEER,
        "dest_port": 80,
        "proto": "TCP",
        "alert": {"signature_id": 1, "rev": 1, "signature": "t", "severity": 2},
    }
)


def anomaly(ts: datetime, event: str, dst: str = PEER, port: int | None = 80) -> Anomaly:
    return Anomaly(ts, 42, "applayer", event, "http", "192.168.1.25", dst, port, "TCP")


def test_an_anomaly_event_is_kept_and_named_on_its_alerted_flow() -> None:
    d = EveDecoder()
    d.decode([anomaly_event(app_proto="http"), anomaly_event(event="")], NOW.year, (), NOW)
    [a] = d.take_anomalies()  # the one with no event name is skipped
    assert (a.kind, a.event, a.app_proto, a.flow_id) == ("applayer", "INVALID_GAP", "http", 42)
    assert (a.src_ip, a.dst_ip, a.dst_port, a.proto) == ("192.168.1.25", PEER, 80, "TCP")
    assert d.take_anomalies() == [] and FastDecoder(UTC).take_anomalies() == []
    d.decode([ALERT], NOW.year, (), NOW)
    assert [(f.kind, f.value) for f in d.take_flows()] == [("anomaly", "http INVALID_GAP")]


def test_a_repeated_anomaly_before_its_alert_does_not_crowd_out_other_facts() -> None:
    d = EveDecoder()
    tls = json.dumps(
        {
            "event_type": "tls",
            "timestamp": "2026-11-17T10:16:52.000000+0200",
            "flow_id": 42,
            "tls": {"sni": "evil.example"},
        }
    )
    d.decode([anomaly_event()] * 10 + [tls], NOW.year, (), NOW)
    d.decode([ALERT], NOW.year, (), NOW)
    assert {(f.kind, f.value) for f in d.take_flows()} >= {
        ("anomaly", "INVALID_GAP"),
        ("tls", "evil.example"),
    }


def test_anomalies_are_kept_once_counted_and_grouped_by_connection(tmp_path: Path) -> None:
    with closing(AlertRepository(tmp_path / "a.db")) as repo:
        gap = anomaly(T0, "INVALID_GAP")
        repo.add_anomalies(
            [
                gap,
                gap,  # read twice
                anomaly(T0 + timedelta(seconds=1), "INVALID_GAP"),
                anomaly(
                    T0 + timedelta(seconds=2), "RESPONSE_HEADER_REPETITION", "2001:db8::1", 443
                ),
                anomaly(T0 - timedelta(days=2), "UNABLE_TO_MATCH_RESPONSE_TO_REQUEST"),
            ]
        )
        since = T0 - timedelta(hours=1)
        assert repo.anomaly_counts(since) == [
            ("applayer", "http", "INVALID_GAP", 2),
            ("applayer", "http", "RESPONSE_HEADER_REPETITION", 1),
        ]
        assert repo.anomaly_peers(since) == [
            ("192.168.1.25", PEER, 80, 2),
            ("192.168.1.25", "2001:db8::1", 443, 1),
        ]
        assert len(repo.anomaly_peers(since, limit=1)) == 1
