"""Run the sensor from a terminal: `python -m snorty.sensor [--db PATH] [--interface-ip IP]`."""

import argparse
import asyncio
import contextlib
import time
from datetime import UTC, datetime
from pathlib import Path

from snorty.core.bus import EventBus, Subscription
from snorty.core.events import AlertRaised, SensorStateChanged
from snorty.core.repository import AlertRepository
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


async def run(db: Path, interface_ip: str | None) -> int:
    bus = EventBus()
    repo = AlertRepository(db)
    config = SensorConfig(paths=SnortPaths(), interface_ip=interface_ip)
    sensor = Sensor(
        config,
        SnortAdapter(config.paths),
        repo,
        bus,
        clock=time.monotonic,
        sleep=asyncio.sleep,
        tz=datetime.now().astimezone().tzinfo or UTC,
    )
    printer = asyncio.create_task(_print_events(bus.subscribe()))
    try:
        await sensor.start()
        print("sensor running; Ctrl+C to stop", flush=True)
        while sensor.state.name not in ("FAILED", "STOPPED"):
            await asyncio.sleep(0.5)
        return 1 if sensor.state.name == "FAILED" else 0
    finally:
        await asyncio.shield(sensor.stop())
        await asyncio.sleep(0)  # let the printer show the final transitions
        printer.cancel()
        repo.close()


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m snorty.sensor")
    parser.add_argument("--db", type=Path, default=Path("snorty.db"))
    parser.add_argument("--interface-ip", default=None, help="pin the capture interface by IP")
    args = parser.parse_args()
    with contextlib.suppress(KeyboardInterrupt):
        return asyncio.run(run(args.db, args.interface_ip))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
