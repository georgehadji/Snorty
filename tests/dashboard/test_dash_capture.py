"""Lab: record traffic into the pcap folder, one capture at a time, and clean up after it."""

import asyncio
import time
from datetime import UTC, datetime
from pathlib import Path

from dash_fakes import FakePackets, FakeSensor
from starlette.testclient import TestClient
from test_dash_routes import POST, make

from snorty.dashboard import pcaps
from snorty.packets import Failed, Recorded, Unavailable
from snorty.sensor import State
from snorty.services import Services
from snorty.snort.models import Interface

DEVICE = r"\Device\NPF_{BED98EAD-7F85-47BD-A28D-BF65D85072EE}"
IFACE = Interface(4, "aa:bb", "10.0.0.5", DEVICE, "Ethernet")
FORM = {**POST, "content-type": "application/x-www-form-urlencoded"}


def packets(s: Services) -> FakePackets:
    assert isinstance(s.packets, FakePackets)
    return s.packets


def sensor(s: Services) -> FakeSensor:
    assert isinstance(s.sensor, FakeSensor)
    return s.sensor


def ready(tmp_path: Path) -> tuple[TestClient, Services]:
    c, s = make(tmp_path)
    sensor(s).set_state(State.RUNNING, interface=IFACE)
    return c, s


def record(c: TestClient, seconds: str = "10"):
    return c.post("/lab/capture", headers=FORM, content=f"seconds={seconds}")


def settled(c: TestClient, tries: int = 100) -> str:
    for _ in range(tries):
        r = c.get("/lab/capture/status")
        if "hx-get" not in r.text:
            return r.text
        time.sleep(0.02)
    raise AssertionError("the capture never finished")


def temps(tmp_path: Path) -> list[Path]:
    return list((tmp_path / "pcaps").glob(".snorty-capture-*"))


def test_a_capture_runs_on_the_sensors_adapter_and_lands_in_the_pcap_list(tmp_path: Path) -> None:
    c, s = ready(tmp_path)
    with c:
        first = record(c, "10")
        assert first.status_code == 200 and "Recording on Ethernet" in first.text
        done = settled(c)
    assert "Saved capture-" in done and "pcap list" in done
    assert 'id="pcap-picker"' in done and 'hx-swap-oob="true"' in done and "selected" in done
    assert packets(s).recorded == [(DEVICE, 10)]
    (name,) = pcaps.list_pcaps(tmp_path / "pcaps")
    assert name.startswith("capture-") and name.endswith(".pcap")
    assert temps(tmp_path) == []


def test_a_second_click_during_a_capture_is_refused_and_does_not_start_another(
    tmp_path: Path,
) -> None:
    c, s = ready(tmp_path)
    with c:
        gate = packets(s).record_gate = asyncio.Event()
        assert "Recording" in record(c).text
        again = record(c, "30")
        assert "already running" in again.text and "Recording on Ethernet" in again.text
        assert len(packets(s).recorded) == 1
        assert "hx-get" in c.get("/lab/capture/status").text  # still polling
        c.portal.call(gate.set)  # type: ignore[union-attr]
        assert "Saved capture-" in settled(c)


def test_stopping_the_dashboard_stops_the_capture_and_removes_the_partial_file(
    tmp_path: Path,
) -> None:
    c, s = ready(tmp_path)
    with c:
        packets(s).record_gate = asyncio.Event()  # never set: the capture would run forever
        record(c)
        for _ in range(100):  # wait until the fake wrote its partial file
            if temps(tmp_path):
                break
            time.sleep(0.02)
        assert temps(tmp_path)
    assert temps(tmp_path) == []
    assert pcaps.list_pcaps(tmp_path / "pcaps") == []


def test_the_seconds_must_be_a_whole_number_in_range(tmp_path: Path) -> None:
    c, s = ready(tmp_path)
    with c:
        for bad in ("4", "121", "0", "-5", "abc", "", "1e2", "10.5", "9999"):
            r = record(c, bad)
            assert r.status_code == 422 and "from 5 to 120" in r.text, bad
        assert packets(s).recorded == []
        for good in ("5", "120"):
            assert record(c, good).status_code == 200
            settled(c)


def test_without_dumpcap_or_a_sensor_adapter_it_explains_and_records_nothing(
    tmp_path: Path,
) -> None:
    c, s = make(tmp_path)  # sensor stopped: no adapter yet
    r = record(c)
    assert r.status_code == 409 and "Start the sensor first" in r.text
    sensor(s).set_state(State.RUNNING, interface=IFACE)
    packets(s).can_record = False
    r = record(c)
    assert r.status_code == 409 and "dumpcap" in r.text
    assert packets(s).recorded == []


def test_a_stopped_or_restarting_sensor_does_not_lend_its_last_adapter(tmp_path: Path) -> None:
    c, s = make(tmp_path)
    for state in (State.STOPPED, State.STARTING, State.FAILED):
        sensor(s).set_state(state, interface=IFACE)  # the sensor remembers its last interface
        r = record(c)
        assert r.status_code == 409 and "Start the sensor first" in r.text, state
    assert packets(s).recorded == []


def test_the_lab_page_offers_the_form_only_when_recording_is_possible(tmp_path: Path) -> None:
    c, s = ready(tmp_path)
    html = c.get("/lab").text
    assert 'hx-post="/lab/capture"' in html and 'id="capture-status"' in html
    assert " style=" not in html
    packets(s).can_record = False
    off = c.get("/lab").text
    assert 'hx-post="/lab/capture"' not in off and "Recording needs Wireshark" in off


def test_a_silent_adapter_a_failing_tool_and_a_missing_tool_are_reported(tmp_path: Path) -> None:
    c, s = ready(tmp_path)
    with c:
        packets(s).record_result = Recorded(24)  # a header and no packets
        record(c)
        assert "No packets arrived in 10 s" in settled(c)
        packets(s).record_result = Failed("dumpcap failed: boom <b>x</b>")
        record(c)
        html = settled(c)
        assert "dumpcap failed: boom &lt;b&gt;x&lt;/b&gt;" in html and 'class="flash bad"' in html
        packets(s).record_result = Unavailable("no dumpcap")
        record(c)
        assert "no dumpcap" in settled(c)
    assert pcaps.list_pcaps(tmp_path / "pcaps") == []


def test_the_status_is_empty_before_any_capture(tmp_path: Path) -> None:
    c, _ = ready(tmp_path)
    r = c.get("/lab/capture/status")
    assert r.status_code == 200 and 'id="capture-status"' in r.text and "hx-get" not in r.text


def test_recording_needs_the_token_and_cannot_be_driven_with_get(tmp_path: Path) -> None:
    c, s = ready(tmp_path)
    assert c.post("/lab/capture", content="seconds=10").status_code in (400, 401, 403)
    assert c.get("/lab/capture").status_code == 405
    assert packets(s).recorded == []


def test_capture_names_never_overwrite_and_stale_temp_files_are_swept(tmp_path: Path) -> None:
    when = datetime(2026, 11, 16, 20, 30, 0, tzinfo=UTC)
    stale = tmp_path / ".snorty-capture-deadbeef.tmp"
    stale.write_bytes(b"x")
    temp = pcaps.capture_temp(tmp_path)
    assert not stale.exists() and temp.name.startswith(".snorty-capture-")
    names = []
    for _ in range(3):
        t = pcaps.capture_temp(tmp_path)
        t.write_bytes(b"data")
        names.append(pcaps.publish_capture(tmp_path, t, when))
    assert names == [
        "capture-20261116-203000.pcap",
        "capture-20261116-203000-2.pcap",
        "capture-20261116-203000-3.pcap",
    ]
    assert pcaps.list_pcaps(tmp_path) == sorted(names)


def test_nanosecond_pcaps_from_dumpcap_pass_the_upload_check(tmp_path: Path) -> None:
    nano = b"\x4d\x3c\xb2\xa1" + bytes(20)
    assert pcaps.save_pcap(tmp_path, "n.pcap", nano) == "n.pcap"


def test_old_recorded_captures_are_deleted_and_nothing_else(tmp_path: Path) -> None:
    import os

    now = time.time()
    old, fresh = (
        tmp_path / "capture-20260101-000000.pcap",
        tmp_path / "capture-20261115-000000.pcap",
    )
    mine, other = tmp_path / "upload.pcap", tmp_path / "capture-note.txt"
    for f in (old, fresh, mine, other):
        f.write_bytes(b"x")
    long_ago = now - 100 * 86400
    for f in (old, mine, other):
        os.utime(f, (long_ago, long_ago))
    assert pcaps.prune_captures(tmp_path, 90, now=now) == 1
    assert not old.exists() and fresh.exists() and mine.exists() and other.exists()
    assert pcaps.prune_captures(tmp_path, 0, now=now) == 0  # 0 keeps everything
    assert pcaps.prune_captures(tmp_path / "gone", 90, now=now) == 0


async def test_the_daily_prune_also_clears_old_captures(tmp_path: Path) -> None:
    import os

    from snorty.core.repository import AlertRepository
    from snorty.dashboard.__main__ import prune_old

    folder = tmp_path / "pcaps"
    folder.mkdir()
    old = folder / "capture-20260101-000000.pcap"
    old.write_bytes(b"x")
    long_ago = time.time() - 100 * 86400
    os.utime(old, (long_ago, long_ago))
    repo = AlertRepository(tmp_path / "t.db")
    try:
        await prune_old(repo, 90, folder)
        assert not old.exists()
        old.write_bytes(b"x")
        os.utime(old, (long_ago, long_ago))
        await prune_old(repo, 0, folder)  # retention off: nothing is deleted
        assert old.exists()
    finally:
        repo.close()
