"""Find the Wireshark tools: a configured folder, an environment variable, Program Files, PATH."""

import shutil
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Tools:
    tshark: Path | None = None
    wireshark: Path | None = None  # the program with a window, next to tshark
    dumpcap: Path | None = None  # records live traffic, next to tshark


def find_tools(
    *,
    configured: Path | None = None,
    env: Mapping[str, str],
    is_file: Callable[[Path], bool] = Path.is_file,
    which: Callable[[str], str | None] = shutil.which,
) -> Tools:
    """The first hit wins: configured folder, SNORTY_WIRESHARK_DIR, Program Files, then PATH."""
    folders: list[Path] = []
    if configured:
        folders.append(configured)
    if env.get("SNORTY_WIRESHARK_DIR"):
        folders.append(Path(env["SNORTY_WIRESHARK_DIR"]))
    for var, fallback in (("ProgramFiles", r"C:\Program Files"), ("ProgramFiles(x86)", "")):
        base = env.get(var, fallback)
        if base:
            folders.append(Path(base) / "Wireshark")
    for folder in folders:
        if is_file(folder / "tshark.exe"):
            return Tools(folder / "tshark.exe", *_beside(folder, is_file))
    found = which("tshark")
    if not found:
        return Tools()
    return Tools(Path(found), *_beside(Path(found).parent, is_file))


def _beside(folder: Path, is_file: Callable[[Path], bool]) -> tuple[Path | None, Path | None]:
    """The window program and the recorder, if they sit next to tshark."""
    found = [folder / name for name in ("Wireshark.exe", "dumpcap.exe")]
    return found[0] if is_file(found[0]) else None, found[1] if is_file(found[1]) else None
