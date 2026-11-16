from pathlib import Path

from dash_fakes import make_services
from starlette.testclient import TestClient

from snorty.dashboard.app import build_app
from snorty.packets import Failed, Unavailable

TOKEN = "t" * 32


def client(tmp_path: Path):
    services = make_services(tmp_path)
    app = build_app(services, token=TOKEN, port=8765)
    return TestClient(app, base_url="http://127.0.0.1:8765"), services


def add_pcap(tmp_path: Path, name: str = "a.pcap") -> None:
    folder = tmp_path / "pcaps"
    folder.mkdir(exist_ok=True)
    (folder / name).write_bytes(b"x" * 24)


def test_inspect_renders_packets_layers_and_bytes(tmp_path: Path) -> None:
    c, s = client(tmp_path)
    add_pcap(tmp_path)
    r = c.get("/packets/pcap", params={"pcap": "a.pcap"})
    assert r.status_code == 200
    assert (
        "10.0.0.1" in r.text and "ICMP" in r.text and "ip.ttl" in r.text and "0000  45 00" in r.text
    )
    assert s.packets.calls[0][0].name == "a.pcap"  # type: ignore[attr-defined]


def test_inspect_only_accepts_pcaps_from_the_folder(tmp_path: Path) -> None:
    c, s = client(tmp_path)
    for bad in ("../x.pcap", "C:/Windows/win.ini", "missing.pcap", ""):
        r = c.get("/packets/pcap", params={"pcap": bad})
        assert r.status_code == 422 and 'class="error"' in r.text
    assert s.packets.calls == []  # type: ignore[attr-defined]


def test_inspect_explains_a_missing_tool_and_a_failed_decode(tmp_path: Path) -> None:
    c, s = client(tmp_path)
    add_pcap(tmp_path)
    s.packets.result = Unavailable("Wireshark (tshark) was not found.")  # type: ignore[attr-defined]
    assert "was not found" in c.get("/packets/pcap", params={"pcap": "a.pcap"}).text
    s.packets.result = Failed("not a capture file")  # type: ignore[attr-defined]
    html = c.get("/packets/pcap", params={"pcap": "a.pcap"}).text
    assert 'class="error"' in html and "not a capture file" in html


def test_the_lab_page_has_an_inspect_button_and_a_result_area(tmp_path: Path) -> None:
    c, _ = client(tmp_path)
    html = c.get("/lab").text
    assert 'hx-get="/packets/pcap"' in html and 'id="packets-result"' in html
