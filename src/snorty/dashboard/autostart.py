"""Start the dashboard at logon: one hidden-launch script in the user's Startup folder.

`python -m snorty.dashboard.autostart install|remove|status`. No admin rights, no scheduler
service; `remove` deletes the one file. The script runs `pythonw` so no console window opens.
"""

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

SCRIPT_NAME = "Snorty dashboard.vbs"


def startup_dir() -> Path:
    base = os.environ.get("APPDATA")
    if not base:
        raise OSError("APPDATA is not set; this only works on Windows")
    return Path(base) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"


def pythonw(python: Path | None = None) -> Path:
    exe = Path(python or sys.executable)
    candidate = exe.with_name("pythonw.exe")
    return candidate if candidate.is_file() else exe


def script_text(python: Path, args: Sequence[str]) -> str:
    """VBScript that starts the dashboard hidden. `args` come from fixed flags, never free text."""
    command = " ".join([f'"{python}"', "-m", "snorty.dashboard", *args])
    quoted = command.replace('"', '""')
    return f'CreateObject("WScript.Shell").Run "{quoted}", 0, False\r\n'


def install(
    folder: Path, python: Path, *, port: int | None = None, start_sensor: bool = False
) -> Path:
    if port is not None and not 0 < port < 65536:
        raise ValueError("port must be 1 to 65535")
    args = (["--port", str(port)] if port is not None else []) + (
        ["--start-sensor"] if start_sensor else []
    )
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / SCRIPT_NAME
    target.write_text(script_text(python, args), encoding="utf-8")
    return target


def remove(folder: Path) -> bool:
    target = folder / SCRIPT_NAME
    if not target.is_file():
        return False
    target.unlink()
    return True


def status(folder: Path) -> str | None:
    """The script's command line when autostart is on, else None."""
    target = folder / SCRIPT_NAME
    return target.read_text(encoding="utf-8").strip() if target.is_file() else None


def main(argv: Sequence[str] | None = None, *, folder: Path | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m snorty.dashboard.autostart")
    sub = parser.add_subparsers(dest="action", required=True)
    add = sub.add_parser("install", help="start the dashboard when you log on")
    add.add_argument("--port", type=int)
    add.add_argument("--start-sensor", action="store_true", help="also start the sensor")
    sub.add_parser("remove", help="stop starting the dashboard at logon")
    sub.add_parser("status", help="show whether autostart is on")
    args = parser.parse_args(argv)
    try:
        where = folder or startup_dir()
        if args.action == "install":
            path = install(where, pythonw(), port=args.port, start_sensor=args.start_sensor)
            print(f"autostart on: {path}")
        elif args.action == "remove":
            print("autostart removed" if remove(where) else "autostart was not on")
        else:
            line = status(where)
            print(f"autostart on: {line}" if line else "autostart off")
    except (OSError, ValueError) as exc:
        print(f"snorty: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
