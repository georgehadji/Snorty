"""The Viewer port, backed by the Wireshark program: start it on a file and let go of it."""

import asyncio
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from snorty.packets.models import Failed, Launched, LaunchResult

# Windows only: the program must outlive Snorty and must not share its console.
_DETACHED = (
    getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    if sys.platform == "win32"
    else 0
)

Launcher = Callable[..., Any]


class WiresharkViewer:
    def __init__(self, exe: Path, *, launch: Launcher = subprocess.Popen) -> None:
        self._exe = exe
        self._launch = launch

    async def open(self, pcap: Path) -> LaunchResult:
        # Fixed argv, no shell; the file is one the server wrote, never a client-supplied path.
        argv = [str(self._exe), "-r", str(pcap)]
        try:
            await asyncio.to_thread(
                self._launch,
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=_DETACHED,
            )
        except OSError as exc:
            return Failed(f"Could not start Wireshark: {exc.strerror or exc}")
        return Launched()
