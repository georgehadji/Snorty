"""Run the sensor from a terminal: `python -m snorty.sensor [--db PATH] [--interface-ip IP]`."""

import argparse
import asyncio
import contextlib
import os
import time
from pathlib import Path

from snorty.core.bus import EventBus, Subscription
from snorty.core.events import AlertRaised, SensorStateChanged
from snorty.core.localtz import LocalTimezone
from snorty.core.repository import AlertRepository
from snorty.journal.ports import NoteStore, VaultNoteStore
from snorty.journal.service import JournalConfig, JournalService
from snorty.notify.ports import Notifier, WinotifyNotifier
from snorty.notify.service import NotifyService
from snorty.sensor import Sensor, SensorConfig, SnortAdapter
from snorty.snort.models import SnortPaths


async def _print_events(events: Subscription) -> None:
    async for ev in events:
        if isinstance(ev, SensorStateChanged):
            why = f" ({ev.reason})" if ev.reason else ""
            print(f"[sensor] {ev.old} -> {ev.new}{why}", flush=True)
        elif isinstance(ev, AlertRaised):
            a = ev.alert
            print(
                f"[alert] P{a.priority} {a.msg} {a.src_ip}:{a.src_port} -> {a.dst_ip}:{a.dst_port}",
                flush=True,
            )


async def run(
    db: Path,
    interface_ip: str | None,
    *,
    notify: bool = False,
    notifier: Notifier | None = None,
    journal: bool = False,
    journal_store: NoteStore | None = None,
) -> int:
    bus = EventBus()
    repo = AlertRepository(db)
    tz = LocalTimezone()
    config = SensorConfig(paths=SnortPaths(), interface_ip=interface_ip)
    sensor = Sensor(
        config,
        SnortAdapter(config.paths),
        repo,
        bus,
        clock=time.monotonic,
        sleep=asyncio.sleep,
        tz=tz,
    )
    toasts = NotifyService(bus, notifier or WinotifyNotifier()) if notify else None
    journals = None
    if journal:
        assert journal_store is not None
        journals = JournalService(bus, repo, journal_store, JournalConfig(tz=tz))
    printer = asyncio.create_task(_print_events(bus.subscribe()))
    try:
        if toasts:
            await toasts.start()
        if journals:
            await journals.start()
        await sensor.start()
        print("sensor running; Ctrl+C to stop", flush=True)
        while sensor.state.name not in ("FAILED", "STOPPED"):
            await asyncio.sleep(0.5)
        return 1 if sensor.state.name == "FAILED" else 0
    finally:
        await asyncio.shield(sensor.stop())
        if journals:
            await journals.stop()
        if toasts:
            await toasts.stop()
        await asyncio.sleep(0)  # let the printer show the final transitions
        printer.cancel()
        repo.close()


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m snorty.sensor")
    parser.add_argument("--db", type=Path, default=Path("snorty.db"))
    parser.add_argument("--interface-ip", default=None, help="pin the capture interface by IP")
    parser.add_argument("--notify", action="store_true", help="toast on priority-1 alerts")
    parser.add_argument("--journal", action="store_true", help="write a daily Obsidian note")
    parser.add_argument("--vault", help="vault folder for --journal, default $OBSIDIAN_VAULT_PATH")
    args = parser.parse_args()
    vault = args.vault or os.environ.get("OBSIDIAN_VAULT_PATH")
    if args.journal and not vault:
        parser.error("--journal needs a vault: pass --vault or set OBSIDIAN_VAULT_PATH")
    store = VaultNoteStore(vault) if args.journal and vault else None
    with contextlib.suppress(KeyboardInterrupt):
        return asyncio.run(
            run(
                args.db,
                args.interface_ip,
                notify=args.notify,
                journal=args.journal,
                journal_store=store,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
