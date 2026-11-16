"""What the sensor needs from Snort, and the real implementation over `snorty.snort`."""

from typing import Protocol

from snorty.snort.interfaces import find_local_ip
from snorty.snort.models import Interface, SnortPaths, StopResult
from snorty.snort.runner import Runner, SubprocessRunner
from snorty.snort.service import (
    LiveProcess,
    is_snort_running,
    list_interfaces,
    start_live,
    stop_live,
)


class RunningSnort(LiveProcess, Protocol):
    @property
    def pid(self) -> int: ...


class SnortPort(Protocol):
    async def list_interfaces(self) -> list[Interface]: ...
    async def start(self, iface: Interface) -> RunningSnort: ...
    async def stop(self, proc: RunningSnort, timeout: float) -> StopResult: ...
    def local_ip(self) -> str | None: ...
    async def is_snort_running(self, pid: int) -> bool: ...


class SnortAdapter:
    def __init__(self, paths: SnortPaths, runner: Runner | None = None) -> None:
        self._paths = paths
        self._runner: Runner = runner or SubprocessRunner()

    async def list_interfaces(self) -> list[Interface]:
        return await list_interfaces(self._paths, self._runner)

    async def start(self, iface: Interface) -> RunningSnort:
        return await start_live(self._paths, iface)

    async def stop(self, proc: RunningSnort, timeout: float) -> StopResult:
        return await stop_live(proc, timeout=timeout)

    def local_ip(self) -> str | None:
        return find_local_ip()

    async def is_snort_running(self, pid: int) -> bool:
        return await is_snort_running(pid, self._runner)
