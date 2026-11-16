"""The dashboard with the real services and real Snort. Run with `pytest -m snort`."""

import hashlib
import socket
import subprocess
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from urllib.parse import urlencode

import pytest
from starlette.testclient import TestClient

from snorty.compose import compose
from snorty.dashboard.app import build_app
from snorty.sensor import State
from snorty.snort import Interface, SnortPaths

pytestmark = pytest.mark.snort

PATHS = SnortPaths()
ROOT = PATHS.conf.parent.parent  # C:\Snort
PORT = 8765
TOKEN = "t" * 64
POST = {"X-Snorty-Token": TOKEN}
FORM = {**POST, "Content-Type": "application/x-www-form-urlencoded"}
UID_RULE = (
    'alert tcp any any -> any any (msg:"dash lab uid root"; content:"uid=0|28|root|29|"; '
    "sid:9000101; rev:1;)"
)


def snapshot() -> dict[str, str]:
    """Hash of every file in the live Snort etc, rules and log folders (and their names)."""
    out: dict[str, str] = {}
    for folder in ("etc", "rules", "log"):
        for p in sorted((ROOT / folder).rglob("*")):
            rel = p.relative_to(ROOT).as_posix()
            out[rel] = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else "<dir>"
    return out


def snort_running() -> bool:
    out = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq snort.exe", "/FO", "CSV", "/NH"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    return "snort.exe" in out.lower()


def loopback(interfaces: list[Interface]) -> Interface | None:
    return next((i for i in interfaces if "Loopback" in i.device), None)


def send_attack_traffic() -> None:
    """A server answers a client with `uid=0(root)`: trips the 'id check returned root' rule."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    cli = socket.create_connection(srv.getsockname())
    conn, _ = srv.accept()
    cli.sendall(b"id\n")
    conn.recv(16)
    conn.sendall(b"uid=0(root) gid=0(root) groups=0(root)\n")
    cli.recv(100)
    for s in (cli, conn, srv):
        s.close()


def eventually(check: Callable[[], bool], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while not check():
        if time.monotonic() > deadline:
            raise AssertionError("condition not met in time")
        time.sleep(0.25)


@pytest.fixture
def live_untouched() -> Iterator[None]:
    if not PATHS.exe.exists():
        pytest.skip("Snort is not installed at C:\\Snort")
    before = snapshot()
    yield
    assert snapshot() == before, "the dashboard changed a live Snort file"
    assert list((ROOT / "etc").glob("snorty-lab-*.conf")) == []
    assert not snort_running()


def test_start_alert_lab_and_stop_through_http(tmp_path: Path, live_untouched: None) -> None:
    log_dir = tmp_path / "log"
    log_dir.mkdir()
    runtime = compose(
        tmp_path / "data", paths=SnortPaths(log_dir=log_dir), select_interface=loopback
    )
    services = runtime.services
    app = build_app(services, token=TOKEN, port=PORT)
    try:
        with TestClient(app, base_url=f"http://127.0.0.1:{PORT}") as c:
            assert c.post("/sensor/start", headers=POST).status_code == 200
            eventually(lambda: services.sensor.state is State.RUNNING, timeout=60)

            send_attack_traffic()
            eventually(lambda: "data-alert" in c.get("/alerts/rows").text, timeout=30)

            body = {
                "name": "uid.pcap", "proto": "tcp", "src": "10.0.0.1", "sport": "4444",
                "dst": "10.0.0.2", "dport": "80", "payload": "uid=0(root) gid=0(root)",
                "count": "1", "handshake": "on",
            }  # fmt: skip
            gen = c.post("/lab/pcaps/generate", content=urlencode(body), headers=FORM)
            assert gen.status_code == 200 and "Generated uid.pcap" in gen.text
            form = urlencode({"rules": UID_RULE, "pcap": "uid.pcap"})
            assert c.post("/lab/run", content=form, headers=FORM).status_code == 200

            def lab_done() -> bool:
                return "hx-get" not in c.get("/lab/status").text

            eventually(lab_done, timeout=60)
            html = c.get("/lab/status").text
            assert "9000101" in html and "no match" not in html and "Matches" in html

            assert c.post("/sensor/stop", headers=POST).status_code == 200
            eventually(lambda: services.sensor.state is State.STOPPED, timeout=30)
    finally:
        services.repo.close()
