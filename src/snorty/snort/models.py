from dataclasses import dataclass
from pathlib import Path
from typing import Literal


@dataclass(frozen=True, slots=True)
class SnortPaths:
    exe: Path = Path(r"C:\Snort\bin\snort.exe")
    conf: Path = Path(r"C:\Snort\etc\snort.conf")
    log_dir: Path = Path(r"C:\Snort\log")


@dataclass(frozen=True, slots=True)
class Interface:
    index: int
    mac: str
    ip: str | None  # IPv4 only; None when disabled or IPv6
    device: str  # \Device\NPF_{GUID}
    description: str


@dataclass(frozen=True, slots=True)
class ConfigCheck:
    ok: bool
    rule_count: int | None
    errors: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RunResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True, slots=True)
class StopResult:
    how: Literal["clean", "killed", "already_exited"]
    returncode: int | None


class SnortError(Exception):
    """Snort missing, input unreadable, run failed, or timeout."""
