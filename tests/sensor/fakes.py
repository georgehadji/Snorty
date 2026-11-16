"""Test doubles for the sensor: a fake Snort port/process and a fake clock."""

import asyncio
import itertools

from snorty.snort.models import Interface, SnortError, StopResult

WIFI = Interface(4, "48:45:E6:48:53:93", "192.168.10.230", r"\Device\NPF_{A}", "Wi-Fi")
ETH = Interface(7, "C8:53:09:FE:AD:27", "192.168.1.25", r"\Device\NPF_{B}", "Ethernet")
LOOP = Interface(9, "00:00:00:00:00:00", None, r"\Device\NPF_Loopback", "Loopback")


class FakeProc:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.returncode: int | None = None
        self._exited = asyncio.Event()

    def exit(self, code: int) -> None:
        self.returncode = code
        self._exited.set()

    def send_signal(self, sig: int) -> None:
        self.exit(0xC000013A)

    def kill(self) -> None:
        self.exit(1)

    async def wait(self) -> int:
        await self._exited.wait()
        assert self.returncode is not None
        return self.returncode


class FakePort:
    def __init__(self, *, ip: str | None = "192.168.10.230") -> None:
        self.interfaces = [WIFI, ETH, LOOP]
        self.ip = ip
        self.running_pids: set[int] = set()
        self.kills: list[int] = []  # pids passed to kill_snort
        self.unkillable = False  # kill_snort leaves the process running
        self.start_calls: list[Interface] = []
        self.stop_calls: list[FakeProc] = []
        self.procs: list[FakeProc] = []
        self.start_error: SnortError | None = None
        self.start_failures = 0  # fail this many start() calls, then succeed
        self.crash_on_start = False  # every started process exits at once with code 1
        self.start_gate: asyncio.Event | None = None  # set to hold start() until released
        self._pids = itertools.count(1000)

    async def list_interfaces(self) -> list[Interface]:
        return list(self.interfaces)

    async def start(self, iface: Interface) -> FakeProc:
        self.start_calls.append(iface)
        if self.start_gate is not None:
            await self.start_gate.wait()
        if self.start_error is not None:
            raise self.start_error
        if self.start_failures > 0:
            self.start_failures -= 1
            raise SnortError("snort exited early (code 1)")
        proc = FakeProc(next(self._pids))
        self.procs.append(proc)
        self.running_pids.add(proc.pid)
        if self.crash_on_start:
            asyncio.get_running_loop().call_later(0.005, proc.exit, 1)
        return proc

    async def stop(self, proc: FakeProc, timeout: float) -> StopResult:  # type: ignore[override]
        self.stop_calls.append(proc)
        proc.send_signal(0)
        self.running_pids.discard(proc.pid)
        return StopResult("clean", proc.returncode)

    def local_ip(self) -> str | None:
        return self.ip

    async def kill_snort(self, pid: int) -> None:
        self.kills.append(pid)
        if not self.unkillable:
            self.running_pids.discard(pid)

    async def is_snort_running(self, pid: int) -> bool:
        for proc in self.procs:
            if proc.pid == pid:
                return proc.returncode is None
        return pid in self.running_pids


class FakeClock:
    """Monotonic clock plus a sleep that advances it without waiting for real."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []
        self.block = False  # when True, sleep() waits until release() is called
        self._release = asyncio.Event()

    def __call__(self) -> float:
        return self.now

    def release(self) -> None:
        self._release.set()

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        if self.block:
            await self._release.wait()
            self._release.clear()
        else:
            await asyncio.sleep(0.001)  # yield to the loop, keep real time tiny
        self.now += seconds
