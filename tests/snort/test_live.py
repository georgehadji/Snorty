import asyncio
import signal
import socket
import sys
import threading
from datetime import UTC
from pathlib import Path

import pytest

from snorty.core.parser import parse_line
from snorty.snort.interfaces import parse_interfaces
from snorty.snort.models import Interface, SnortError, SnortPaths
from snorty.snort.runner import SubprocessRunner
from snorty.snort.service import CTRL_C_EXIT, start_live, stop_live


class FakeProc:
    def __init__(self, *, exits_on_signal: bool, returncode: int | None = None) -> None:
        self.returncode = returncode
        self.exits_on_signal = exits_on_signal
        self.signals: list[int] = []
        self.killed = False
        self._done = asyncio.Event()

    def send_signal(self, sig: int) -> None:
        self.signals.append(sig)
        if self.exits_on_signal:
            self.returncode = CTRL_C_EXIT
            self._done.set()

    def kill(self) -> None:
        self.killed = True
        self.returncode = 1
        self._done.set()

    async def wait(self) -> int:
        await self._done.wait()
        assert self.returncode is not None
        return self.returncode


async def test_stop_clean_sends_ctrl_break() -> None:
    proc = FakeProc(exits_on_signal=True)
    result = await stop_live(proc, timeout=1)
    assert result.how == "clean" and result.returncode == CTRL_C_EXIT
    assert proc.signals == [signal.CTRL_BREAK_EVENT] and not proc.killed


async def test_stop_kills_only_after_timeout() -> None:
    proc = FakeProc(exits_on_signal=False)
    result = await stop_live(proc, timeout=0.05)
    assert result.how == "killed" and proc.killed


async def test_stop_already_exited_sends_nothing() -> None:
    proc = FakeProc(exits_on_signal=False, returncode=0)
    result = await stop_live(proc, timeout=1)
    assert result.how == "already_exited" and proc.signals == []


async def test_start_live_missing_exe_raises(tmp_path: Path) -> None:
    paths = SnortPaths(exe=tmp_path / "nope.exe", conf=tmp_path / "c", log_dir=tmp_path / "log")
    with pytest.raises(SnortError, match="cannot start"):
        await start_live(paths, Interface(1, "m", None, "d", "x"))


def _send_payload_over_loopback() -> None:
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def serve() -> None:
        conn, _ = srv.accept()
        conn.sendall(b"uid=0(root) gid=0(root)\n")
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    with socket.create_connection(srv.getsockname()) as cl:
        cl.recv(100)
    srv.close()


@pytest.mark.snort
async def test_real_snort_alert_survives_clean_stop(tmp_path: Path) -> None:
    base = SnortPaths()
    out = await SubprocessRunner()([str(base.exe), "-W"], timeout=30)
    loopback = next(i for i in parse_interfaces(out.stdout) if i.device.endswith("NPF_Loopback"))
    paths = SnortPaths(log_dir=tmp_path)  # never the real C:\Snort\log
    proc = await start_live(paths, loopback, ready_timeout=120)
    try:
        await asyncio.to_thread(_send_payload_over_loopback)
        await asyncio.sleep(1)
    finally:
        result = await stop_live(proc, timeout=20)
    assert result.how == "clean"
    sids = {
        a.sid
        for line in (tmp_path / "alert.ids").read_text().splitlines()
        if (a := parse_line(line, default_year=2026, tz=UTC)) is not None
    }
    assert 1000002 in sids


async def test_start_live_reports_early_exit(tmp_path: Path) -> None:
    # Stand-in "snort": python runs the "conf" as code and exits with 3 at once.
    paths = SnortPaths(Path(sys.executable), Path("raise SystemExit(3)"), tmp_path)
    with pytest.raises(SnortError, match=r"exited early \(code 3\)"):
        await start_live(paths, Interface(1, "m", None, "d", "x"), ready_timeout=20)


async def test_start_live_times_out_when_never_ready(tmp_path: Path) -> None:
    paths = SnortPaths(Path(sys.executable), Path("import time; time.sleep(60)"), tmp_path)
    with pytest.raises(SnortError, match="not ready"):
        await start_live(paths, Interface(1, "m", None, "d", "x"), ready_timeout=0.3)


async def test_start_live_returns_when_ready_marker_appears(tmp_path: Path) -> None:
    code = "print('Commencing packet processing', flush=True); import time; time.sleep(60)"
    paths = SnortPaths(Path(sys.executable), Path(code), tmp_path)
    proc = await start_live(paths, Interface(1, "m", None, "d", "x"), ready_timeout=20)
    result = await stop_live(proc, timeout=10)
    assert result.how in ("clean", "killed")
