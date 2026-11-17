"""The Sysmon connection log as a second source for which program made a connection."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

import pytest
from test_host_context import LOCAL, FakeLookup, stored
from test_repository import make_alert

from snorty.attribution import AttributionService, Owner
from snorty.attribution.ports import NoHistory
from snorty.core.bus import EventBus
from snorty.core.repository import AlertRepository
from snorty.dashboard.context_routes import process_text
from snorty.winevt import SysmonHistory, parse_event_xml, probe
from snorty.winevt.sysmon import query_xpath, read_events

T0 = datetime(2026, 11, 17, 9, 30, 0, tzinfo=UTC)


def event(
    *,
    when: datetime = T0,
    proto: str = "tcp",
    src: tuple[str, int] = (LOCAL, 51234),
    dst: tuple[str, int] = ("93.184.216.34", 443),
    pid: int = 4242,
    image: str = r"C:\Tools\nc.exe",
    event_id: int = 3,
) -> str:
    stamp = when.strftime("%Y-%m-%dT%H:%M:%S.%f") + "1Z"  # Windows writes seven digits
    data = {
        "UtcTime": when.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "ProcessId": str(pid),
        "Image": image,
        "Protocol": proto,
        "Initiated": "true",
        "SourceIp": src[0],
        "SourcePort": str(src[1]),
        "DestinationIp": dst[0],
        "DestinationPort": str(dst[1]),
    }
    fields = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in data.items())
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        "<Provider Name='Microsoft-Windows-Sysmon'/>"
        f"<EventID>{event_id}</EventID><TimeCreated SystemTime='{stamp}'/></System>"
        f"<EventData>{fields}</EventData></Event>"
    )


def test_a_rendered_event_three_becomes_a_connection() -> None:
    e = parse_event_xml(event())
    assert e is not None
    assert (e.proto, e.src_ip, e.src_port, e.dst_ip, e.dst_port) == (
        "tcp",
        LOCAL,
        51234,
        "93.184.216.34",
        443,
    )
    assert (e.pid, e.image) == (4242, r"C:\Tools\nc.exe")
    assert abs(e.time - T0) < timedelta(microseconds=1)


@pytest.mark.parametrize(
    "text",
    [
        event(event_id=1),  # a process creation, not a connection
        event().replace("<Data Name='SourcePort'>51234</Data>", ""),
        event(pid=0).replace(">0<", ">x<"),
        "<Event><unclosed>",
        "",
    ],
)
def test_anything_else_is_not_a_connection(text: str) -> None:
    assert parse_event_xml(text) is None


def test_the_query_asks_the_log_for_this_port_near_this_moment() -> None:
    q = query_xpath(51234, T0)
    assert "EventID=3" in q
    assert "@SystemTime>='2026-11-17T09:29:55.000Z'" in q
    assert "@SystemTime<='2026-11-17T09:30:05.000Z'" in q
    assert "Data[@Name='SourcePort']='51234'" in q
    assert "Data[@Name='DestinationPort']='51234'" in q


def test_the_nearest_matching_record_names_the_owner() -> None:
    seen: list[tuple[str, int]] = []

    def read(xpath: str, limit: int) -> list[str]:
        seen.append((xpath, limit))
        return [
            event(when=T0 + timedelta(seconds=4), pid=1, image="far.exe"),
            event(when=T0 + timedelta(seconds=1), pid=2, image="near.exe"),
            event(proto="udp", pid=3, image="udp.exe"),  # other protocol
            event(src=("10.9.9.9", 51234), pid=4, image="other.exe"),  # other address
        ]

    found = SysmonHistory(read).find("TCP", LOCAL, 51234, T0)
    assert found == Owner(2, "near.exe")
    assert seen and seen[0][0] == query_xpath(51234, T0)


def test_an_inbound_connection_matches_on_the_destination_end() -> None:
    inbound = event(src=("203.0.113.5", 60000), dst=(LOCAL, 3389), pid=9, image="svchost.exe")
    assert SysmonHistory(lambda q, n: [inbound]).find("TCP", LOCAL, 3389, T0) == Owner(
        9, "svchost.exe"
    )


def test_no_record_or_an_unreadable_log_is_no_answer() -> None:
    assert SysmonHistory(lambda q, n: []).find("TCP", LOCAL, 1, T0) is None

    def broken(xpath: str, limit: int) -> list[str]:
        raise OSError("Sysmon is not installed (its event log does not exist)")

    assert SysmonHistory(broken).find("TCP", LOCAL, 1, T0) is None
    assert probe(broken) == "Sysmon is not installed (its event log does not exist)"
    assert probe(lambda q, n: []) is None


class FakeHistory:
    def __init__(self, owner: Owner | None) -> None:
        self.answer = owner
        self.asked: list[tuple[str, str, int, datetime]] = []

    def find(
        self, proto: Literal["TCP", "UDP"], local_ip: str, local_port: int, around: datetime
    ) -> Owner | None:
        self.asked.append((proto, local_ip, local_port, around))
        return self.answer


def test_the_log_is_asked_only_when_the_live_table_has_forgotten(tmp_path: Path) -> None:
    repo = AlertRepository(tmp_path / "t.db")
    history = FakeHistory(Owner(77, r"C:\Temp\beacon.exe"))
    a = stored(repo, make_alert(1))
    AttributionService(
        EventBus(), repo, FakeLookup(Owner(5, "live.exe")), lambda: LOCAL, history
    ).attribute(a)
    assert history.asked == []
    assert json.loads(repo.annotations(a.id)["process"])["via"] == "table"

    AttributionService(EventBus(), repo, FakeLookup(None), lambda: LOCAL, history).attribute(a)
    assert history.asked == [("TCP", LOCAL, 80, a.ts)]
    note = repo.annotations(a.id)["process"]
    assert json.loads(note) == {
        "found": True,
        "pid": 77,
        "image": r"C:\Temp\beacon.exe",
        "via": "sysmon",
    }
    assert process_text(note) == r"C:\Temp\beacon.exe (pid 77, from the Sysmon log)"
    repo.close()


def test_with_no_log_a_forgotten_connection_is_still_not_found(tmp_path: Path) -> None:
    repo = AlertRepository(tmp_path / "t.db")
    a = stored(repo, make_alert(1))
    AttributionService(EventBus(), repo, FakeLookup(None), lambda: LOCAL, NoHistory()).attribute(a)
    assert json.loads(repo.annotations(a.id)["process"]) == {"found": False}
    repo.close()


@pytest.mark.sysmon
def test_the_real_log_can_be_queried_when_sysmon_is_here() -> None:
    reason = probe()
    if reason is not None:
        pytest.skip(reason)
    rendered = read_events(query_xpath(443, datetime.now(UTC), timedelta(hours=1)), 5)
    assert all(parse_event_xml(r) is not None for r in rendered)
