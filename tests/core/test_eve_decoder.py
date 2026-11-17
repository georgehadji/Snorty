import json
from datetime import UTC, datetime, timedelta

from snorty.core.decoder import EveDecoder, FastDecoder
from snorty.core.models import Alert

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)


def eve(**over: object) -> str:
    event: dict[str, object] = {
        "timestamp": "2026-11-17T10:15:30.123456+0200",
        "flow_id": 1234567890,
        "event_type": "alert",
        "src_ip": "10.0.0.5",
        "src_port": 51000,
        "dest_ip": "203.0.113.9",
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2024897,
            "rev": 3,
            "signature": "ET MALWARE Test Beacon",
            "category": "A Network Trojan was detected",
            "severity": 1,
        },
    }
    event.update(over)
    return json.dumps(event)


def decode(*lines: str) -> tuple[list[Alert], int]:
    return EveDecoder().decode(lines, NOW.year, (), NOW)


def test_alert_event_becomes_alert() -> None:
    alerts, bad = decode(eve())
    assert bad == 0
    (a,) = alerts
    assert (a.gid, a.sid, a.rev, a.priority) == (1, 2024897, 3, 1)
    assert a.msg == "ET MALWARE Test Beacon"
    assert a.classification == "A Network Trojan was detected"
    assert (a.proto, a.src_ip, a.src_port, a.dst_ip, a.dst_port) == (
        "TCP",
        "10.0.0.5",
        51000,
        "203.0.113.9",
        443,
    )


def test_timestamp_keeps_its_offset() -> None:
    (a,), _ = decode(eve())
    assert a.ts.utcoffset() == timedelta(hours=2)
    assert a.ts == datetime(2026, 11, 17, 8, 15, 30, 123456, tzinfo=UTC)


def test_other_event_types_are_skipped_not_counted() -> None:
    alerts, bad = decode(eve(event_type="dns"), eve(event_type="stats"), eve())
    assert (len(alerts), bad) == (1, 0)


def test_icmp_has_no_ports() -> None:
    (a,), bad = decode(eve(proto="ICMP", src_port=None, dest_port=None))
    assert (a.src_port, a.dst_port, bad) == (None, None, 0)


def test_missing_optional_fields_use_defaults() -> None:
    (a,), bad = decode(eve(alert={"signature_id": 7, "signature": "x"}))
    assert (a.gid, a.rev, a.priority, a.classification, bad) == (1, 0, 3, None, 0)


def test_same_event_read_twice_has_the_same_key_and_other_events_differ() -> None:
    (one,), _ = decode(eve())
    (again,), _ = decode(eve())
    (other,), _ = decode(eve(flow_id=99))
    assert one.raw == again.raw != other.raw


def test_bad_lines_are_counted_and_do_not_stop_the_rest() -> None:
    broken = [
        "not json",
        "[1, 2]",
        eve(timestamp="yesterday"),
        eve(timestamp="2026-11-17T10:15:30"),  # no offset
        eve(src_ip=None),
        eve(alert={"signature": "no sid"}),
        eve(alert={"signature_id": "7", "signature": "x"}),
        eve(alert={"signature_id": True, "signature": "x"}),
    ]
    alerts, bad = decode(*broken, eve())
    assert (len(alerts), bad) == (1, len(broken))


def test_out_of_range_port_is_dropped() -> None:
    (a,), _ = decode(eve(src_port=70000))
    assert a.src_port is None


def test_fast_decoder_decodes_nothing_from_nothing() -> None:
    d = FastDecoder(UTC)
    d.reset()
    assert d.decode([], NOW.year, (), NOW) == ([], 0)


def stats(packets: int, drops: int) -> str:
    return json.dumps(
        {
            "event_type": "stats",
            "stats": {"capture": {"kernel_packets": packets, "kernel_drops": drops}},
        }
    )


def test_stats_events_give_the_drop_percentage() -> None:
    dec = EveDecoder()
    assert dec.drop_pct is None
    alerts, bad = dec.decode([stats(200, 3), stats(1000, 25)], NOW.year, (), NOW)
    assert (alerts, bad) == ([], 0)
    assert dec.drop_pct == 2.5  # the latest totals count
    dec.reset()
    assert dec.drop_pct is None


def test_stats_without_traffic_or_capture_are_ignored() -> None:
    dec = EveDecoder()
    dec.decode([stats(0, 0), json.dumps({"event_type": "stats", "stats": {}})], 2026, (), NOW)
    assert dec.drop_pct is None


TS = "2026-11-17T10:15:31.000000+0200"


def facts(decoder: EveDecoder) -> set[tuple[int, str, str]]:
    return {(f.flow_id, f.kind, f.value) for f in decoder.take_flows()}


def test_tls_and_http_facts_follow_an_alert_on_their_flow() -> None:
    d = EveDecoder()
    d.decode([eve()], NOW.year, (), NOW)
    tls = json.dumps(
        {
            "event_type": "tls",
            "timestamp": TS,
            "flow_id": 1234567890,
            "tls": {"sni": "evil.example"},
        }
    )
    http = json.dumps(
        {
            "event_type": "http",
            "timestamp": TS,
            "flow_id": 1234567890,
            "http": {"hostname": "evil.example", "url": "/a/b?token=secret"},
        }
    )
    d.decode([tls, http], NOW.year, (), NOW)
    got = facts(d)
    assert (1234567890, "tls", "evil.example") in got
    assert (1234567890, "http", "evil.example/a/b") in got  # the query string is dropped
    assert not any("secret" in v for _, _, v in got)
    assert d.take_flows() == []  # taken once


def test_a_fact_that_came_before_its_alert_is_kept() -> None:
    d = EveDecoder()
    tls = json.dumps(
        {
            "event_type": "tls",
            "timestamp": TS,
            "flow_id": 1234567890,
            "tls": {"sni": "evil.example"},
        }
    )
    d.decode([tls], NOW.year, (), NOW)
    assert d.take_flows() == []  # no alert yet: held back
    d.decode([eve()], NOW.year, (), NOW)
    assert (1234567890, "tls", "evil.example") in facts(d)


def test_a_dns_answer_names_the_address_an_alert_later_talks_to() -> None:
    d = EveDecoder()
    dns = json.dumps(
        {
            "event_type": "dns",
            "flow_id": 77,
            "dns": {"answers": [{"rrname": "evil.example", "rrtype": "A", "rdata": "203.0.113.9"}]},
        }
    )
    d.decode([dns], NOW.year, (), NOW)
    d.decode([eve()], NOW.year, (), NOW)
    assert (1234567890, "dns", "evil.example") in facts(d)


def test_reset_forgets_what_was_seen() -> None:
    d = EveDecoder()
    tls = json.dumps(
        {
            "event_type": "tls",
            "timestamp": TS,
            "flow_id": 1234567890,
            "tls": {"sni": "evil.example"},
        }
    )
    d.decode([tls], NOW.year, (), NOW)
    d.reset()
    d.decode([eve()], NOW.year, (), NOW)
    assert d.take_flows() == []


def test_alert_flow_id_is_read_from_its_raw_text() -> None:
    alerts, _ = decode(eve())
    assert alerts[0].flow_id == 1234567890
    assert decode(eve(flow_id=None))[0][0].flow_id is None
