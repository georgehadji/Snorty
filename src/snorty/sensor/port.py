"""What the sensor needs from Snort, and the real implementation over `snorty.snort`."""

import asyncio
from typing import Protocol

from snorty.snort.interfaces import find_local_ip
from snorty.snort.models import Interface, SnortPaths, StopResult
from snorty.snort.runner import Runner, SubprocessRunner
from snorty.snort.service import (
    LiveProcess,
    enable_perfmon,
    is_snort_running,
    kill_snort,
    list_interfaces,
    start_live,
    stop_live,
)
from snorty.suricata import IMAGE as SURICATA_IMAGE
from snorty.suricata import SuricataPaths, local_interfaces
from snorty.suricata import start_live as start_suricata


class RunningSnort(LiveProcess, Protocol):
    @property
    def pid(self) -> int: ...


class EnginePort(Protocol):
    async def list_interfaces(self) -> list[Interface]: ...
    async def start(self, iface: Interface) -> RunningSnort: ...
    async def stop(self, proc: RunningSnort, timeout: float) -> StopResult: ...
    def local_ip(self) -> str | None: ...
    async def is_snort_running(self, pid: int) -> bool: ...
    async def kill_snort(self, pid: int) -> None: ...


class SnortAdapter:
    def __init__(self, paths: SnortPaths, runner: Runner | None = None) -> None:
        self._paths = paths
        self._runner: Runner = runner or SubprocessRunner()

    async def list_interfaces(self) -> list[Interface]:
        return await list_interfaces(self._paths, self._runner)

    async def start(self, iface: Interface) -> RunningSnort:
        await enable_perfmon(self._paths, iface, self._runner)  # best effort: drop statistics
        return await start_live(self._paths, iface)

    async def stop(self, proc: RunningSnort, timeout: float) -> StopResult:
        return await stop_live(proc, timeout=timeout)

    def local_ip(self) -> str | None:
        return find_local_ip()

    async def is_snort_running(self, pid: int) -> bool:
        return await is_snort_running(pid, self._runner)

    async def kill_snort(self, pid: int) -> None:
        await kill_snort(pid, self._runner)


class SuricataAdapter:
    """Same job as SnortAdapter, for Suricata. Stopping and killing are the Snort package's:
    Ctrl+Break and taskkill work on any console process."""

    def __init__(self, paths: SuricataPaths, runner: Runner | None = None) -> None:
        self._paths = paths
        self._runner: Runner = runner or SubprocessRunner()

    async def list_interfaces(self) -> list[Interface]:
        return await asyncio.to_thread(local_interfaces)

    async def start(self, iface: Interface) -> RunningSnort:
        return await start_suricata(self._paths, iface)

    async def stop(self, proc: RunningSnort, timeout: float) -> StopResult:
        return await stop_live(proc, timeout=timeout)

    def local_ip(self) -> str | None:
        return find_local_ip()

    async def is_snort_running(self, pid: int) -> bool:
        return await is_snort_running(pid, self._runner, SURICATA_IMAGE)

    async def kill_snort(self, pid: int) -> None:
        await kill_snort(pid, self._runner)
