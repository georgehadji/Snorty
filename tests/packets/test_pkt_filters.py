"""packets.filters: display filters built from an alert, never from raw alert text."""

import random
import re
from datetime import UTC, datetime

from snorty.core.models import Alert
from snorty.packets import alert_filter, conversation_filter

# What a filter may contain: field names, ==, &&, numbers, and address characters.
SAFE = re.compile(r"^[a-z0-9_. =&:]+$")


def mk(
    proto: str = "TCP",
    src: str = "10.0.0.5",
    sport: int | None = 40000,
    dst: str = "10.0.0.9",
    dport: int | None = 80,
) -> Alert:
    when = datetime(2026, 11, 16, tzinfo=UTC)
    return Alert(when, 1, 2000001, 1, "m", None, 1, proto, src, sport, dst, dport, "")


def test_a_tcp_alert_gives_the_exact_packet_and_the_whole_conversation() -> None:
    a = mk()
    assert alert_filter(a) == (
        "ip.src == 10.0.0.5 && ip.dst == 10.0.0.9 && tcp.srcport == 40000 && tcp.dstport == 80"
    )
    assert conversation_filter(a) == (
        "ip.addr == 10.0.0.5 && ip.addr == 10.0.0.9 && tcp.port == 40000 && tcp.port == 80"
    )


def test_udp_icmp_and_ipv6_pick_their_own_fields() -> None:
    assert "udp.dstport == 53" in (alert_filter(mk("UDP", dport=53)) or "")
    assert alert_filter(mk("ICMP", sport=None, dport=None)) == (
        "ip.src == 10.0.0.5 && ip.dst == 10.0.0.9 && icmp"
    )
    v6 = mk("TCP", "2001:db8::1", 1234, "2001:DB8:0:0::2", 443)
    assert alert_filter(v6) == (
        "ipv6.src == 2001:db8::1 && ipv6.dst == 2001:db8::2"
        " && tcp.srcport == 1234 && tcp.dstport == 443"
    )
    assert conversation_filter(mk("IPV6-ICMP", "fe80::1", None, "fe80::2", None)) == (
        "ipv6.addr == fe80::1 && ipv6.addr == fe80::2 && icmpv6"
    )


def test_missing_ports_and_unknown_protocols_still_give_an_address_filter() -> None:
    assert alert_filter(mk("TCP", sport=None, dport=None)) == (
        "ip.src == 10.0.0.5 && ip.dst == 10.0.0.9 && tcp"
    )
    assert conversation_filter(mk("UDP", sport=None, dport=None)) == (
        "ip.addr == 10.0.0.5 && ip.addr == 10.0.0.9 && udp"
    )
    assert alert_filter(mk("PROTO:255", sport=None, dport=None)) == (
        "ip.src == 10.0.0.5 && ip.dst == 10.0.0.9"
    )


def test_an_out_of_range_port_is_left_out() -> None:
    f = alert_filter(mk(sport=70000, dport=-1)) or ""
    assert "port" not in f and f.endswith("&& tcp")


def test_bad_or_mixed_addresses_give_no_filter() -> None:
    for src, dst in [
        ("not-an-ip", "10.0.0.9"),
        ("10.0.0.5", "x == 1 || true"),
        ("10.0.0.5", "2001:db8::1"),
        ("", ""),
    ]:
        assert alert_filter(mk(src=src, dst=dst)) is None
        assert conversation_filter(mk(src=src, dst=dst)) is None


def test_an_ipv6_scope_id_is_dropped() -> None:
    f = alert_filter(mk("ICMP", "fe80::1%12", None, "fe80::2", None)) or ""
    assert "%" not in f and f.startswith("ipv6.src == fe80::1 ")


def test_random_junk_never_makes_an_unsafe_filter() -> None:
    rnd = random.Random(7)
    chars = "0123456789abcdef:.%/ &|()\"'=!<>;\\\n\tx-"
    protos = ["TCP", "UDP", "ICMP", "IPV6-ICMP", "PROTO:6", "tcp && true", "", "\x00"]

    def junk() -> str:
        return "".join(rnd.choice(chars) for _ in range(rnd.randint(0, 20)))

    for _ in range(3000):
        a = mk(
            rnd.choice(protos),
            junk() if rnd.random() < 0.5 else f"10.0.{rnd.randint(0, 300)}.1",
            rnd.choice([None, rnd.randint(-5, 70000)]),
            junk() if rnd.random() < 0.5 else "2001:db8::" + f"{rnd.randint(0, 70000):x}",
            rnd.choice([None, rnd.randint(-5, 70000)]),
        )
        for f in (alert_filter(a), conversation_filter(a)):
            assert f is None or (SAFE.fullmatch(f) and "||" not in f and "(" not in f), (a, f)
