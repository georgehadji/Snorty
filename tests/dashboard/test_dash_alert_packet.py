"""Dashboard: the packet behind an alert, its download, and opening it in Wireshark."""

from pathlib import Path

from dash_fakes import FakePackets, alert
from test_dash_routes import POST, make

from snorty.packets import AlertPacket, Decoded, Failed, Launched, NotFound, Unavailable
from snorty.services import Services


def packets(s: Services) -> FakePackets:
    assert isinstance(s.packets, FakePackets)
    return s.packets


def stored(tmp_path: Path):
    c, s = make(tmp_path)
    s.repo.add(alert(2000001))
    return c, s, s.repo.query()[0].id


def test_the_packet_fragment_shows_the_decoded_frame_and_how_sure_it_is(tmp_path: Path) -> None:
    c, s, aid = stored(tmp_path)
    r = c.get(f"/alerts/{aid}/packet")
    assert r.status_code == 200
    assert "The packet Snort logged for this alert." in r.text
    assert "ip.ttl" in r.text and "0000  45 00" in r.text
    assert f'href="/alerts/{aid}/packet.pcap"' in r.text and "Open in Wireshark" in r.text
    assert packets(s).alert_calls[0].id == aid


def test_the_open_button_is_left_out_when_wireshark_is_missing(tmp_path: Path) -> None:
    c, s, aid = stored(tmp_path)
    packets(s).can_open = False
    r = c.get(f"/alerts/{aid}/packet")
    assert "Open in Wireshark" not in r.text and "packet.pcap" in r.text


def test_a_near_or_ambiguous_match_says_so(tmp_path: Path) -> None:
    c, s, aid = stored(tmp_path)
    decoded = Decoded((), limit=1)
    packets(s).packet = AlertPacket("near", 2, b"x", decoded)
    assert (
        "Closest packet in the Snort log (2 candidates within 2 s)."
        in c.get(f"/alerts/{aid}/packet").text
    )
    packets(s).packet = AlertPacket("ambiguous", 3, b"x", decoded)
    assert "3 different packets share this moment" in c.get(f"/alerts/{aid}/packet").text


def test_without_a_decoder_the_packet_still_downloads_and_the_page_says_why(
    tmp_path: Path,
) -> None:
    c, s, aid = stored(tmp_path)
    packets(s).packet = AlertPacket("exact", 1, b"x", Unavailable("tshark is not installed"))
    html = c.get(f"/alerts/{aid}/packet").text
    assert "tshark is not installed" in html and "packet.pcap" in html


def test_not_found_and_failures_are_explained_with_no_download(tmp_path: Path) -> None:
    c, s, aid = stored(tmp_path)
    packets(s).packet = NotFound("This packet is not in the Snort log.")
    html = c.get(f"/alerts/{aid}/packet").text
    assert "not in the Snort log" in html and "packet.pcap" not in html
    packets(s).packet = Failed("bad <b>log</b>")
    html = c.get(f"/alerts/{aid}/packet").text
    assert "bad &lt;b&gt;log&lt;/b&gt;" in html and 'class="error"' in html


def test_an_unknown_or_out_of_range_alert_is_explained_not_decoded(tmp_path: Path) -> None:
    c, s, _ = stored(tmp_path)
    for bad in ("999", "0", "-1", str(2**70)):
        r = c.get(f"/alerts/{bad}/packet")
        assert "no longer stored" in r.text or r.status_code == 422
    assert packets(s).alert_calls == []


def test_the_download_is_a_pcap_attachment_named_for_the_alert(tmp_path: Path) -> None:
    c, _, aid = stored(tmp_path)
    r = c.get(f"/alerts/{aid}/packet.pcap")
    assert r.status_code == 200 and r.content == b"PCAPDATA"
    assert r.headers["content-type"] == "application/vnd.tcpdump.pcap"
    assert r.headers["content-disposition"] == f'attachment; filename="alert-{aid}.pcap"'


def test_there_is_nothing_to_download_without_a_packet_or_an_alert(tmp_path: Path) -> None:
    c, s, aid = stored(tmp_path)
    assert c.get("/alerts/999/packet.pcap").status_code == 404
    packets(s).packet = NotFound("no")
    assert c.get(f"/alerts/{aid}/packet.pcap").status_code == 404


def test_open_launches_wireshark_and_reports_each_outcome(tmp_path: Path) -> None:
    c, s, aid = stored(tmp_path)
    ok = c.post(f"/alerts/{aid}/open", headers=POST)
    assert ok.status_code == 200 and "Opened the packet in Wireshark" in ok.text
    assert packets(s).open_calls[0].id == aid
    packets(s).launch = Unavailable("Wireshark was not found.")
    off = c.post(f"/alerts/{aid}/open", headers=POST)
    assert off.status_code == 409 and "Wireshark was not found." in off.text
    packets(s).launch = Failed("Could not start Wireshark: boom")
    bad = c.post(f"/alerts/{aid}/open", headers=POST)
    assert bad.status_code == 500 and "boom" in bad.text
    assert c.post("/alerts/999/open", headers=POST).status_code == 404


def test_open_needs_the_token_and_cannot_be_driven_with_get(tmp_path: Path) -> None:
    c, s, aid = stored(tmp_path)
    assert c.post(f"/alerts/{aid}/open").status_code in (400, 401, 403)
    assert c.get(f"/alerts/{aid}/open").status_code == 405
    assert packets(s).open_calls == [] and packets(s).launch == Launched()


def test_each_alert_row_loads_its_packet_when_opened(tmp_path: Path) -> None:
    c, _, aid = stored(tmp_path)
    html = c.get("/alerts").text
    assert f'hx-get="/alerts/{aid}/packet"' in html and 'hx-trigger="toggle once"' in html
    assert "alert-packet" in html and " style=" not in html
