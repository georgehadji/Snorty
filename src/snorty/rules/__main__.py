"""Command line for the rules module: `python -m snorty.rules <command>`."""

import argparse
import asyncio
from collections.abc import Sequence
from datetime import datetime

from snorty.core.bus import EventBus
from snorty.rules.config import RulesConfig
from snorty.rules.ports import UrllibDownloader, validator_for
from snorty.rules.service import EditReport, RulesService
from snorty.sensor.states import State

RESTART_HINT = "Restart the sensor (or Snort) to load the change."


class NoSensor:
    """The CLI runs outside the sensor's process, so it cannot restart it."""

    @property
    def state(self) -> State:
        return State.STOPPED

    async def restart(self) -> None:
        return None


def build_service() -> RulesService:
    config = RulesConfig()
    return RulesService(
        config,
        UrllibDownloader(),
        validator_for(config.paths),
        NoSensor(),
        EventBus(),
        clock=lambda: datetime.now().astimezone(),
    )


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m snorty.rules")
    sub = p.add_subparsers(dest="command", required=True)
    up = sub.add_parser("update", help="download, validate and swap in the ET Open rules")
    up.add_argument("--force", action="store_true", help="update even if the md5 is unchanged")
    sub.add_parser("status", help="show the last update")
    for name in ("mute", "unmute"):
        sp = sub.add_parser(name, help=f"{name} a rule by SID")
        sp.add_argument("sid", type=int)
        if name == "mute":
            sp.add_argument("--note", default="")
        sp.add_argument("--no-restart", action="store_true")
    sub.add_parser("muted", help="list muted rules")
    hn = sub.add_parser("home-net", help="show or set HOME_NET")
    hn.add_argument("--set", dest="value", metavar="VALUE", default=None)
    return p


def _report(r: EditReport) -> int:
    print(("ok: " if r.ok else "FAILED: ") + r.detail)
    if r.ok and r.changed:
        print(RESTART_HINT)
    return 0 if r.ok else 1


async def _run(args: argparse.Namespace, svc: RulesService) -> int:
    cmd = args.command
    if cmd == "update":
        print("updating (download, validate with snort -T, swap; this can take a few minutes)...")
        r = await svc.update(force=args.force)
        label = {"updated": "updated", "up_to_date": "up to date", "failed": "FAILED"}[r.outcome]
        print(
            f"{label}: {r.detail}"
            + (f" ({r.skipped} archive members skipped)" if r.skipped else "")
        )
        if r.outcome == "updated":
            print(RESTART_HINT)
        return 1 if r.outcome == "failed" else 0
    if cmd == "mute":
        return _report(await svc.mute(args.sid, args.note, restart=not args.no_restart))
    if cmd == "unmute":
        return _report(await svc.unmute(args.sid, restart=not args.no_restart))
    if cmd == "muted":
        muted = await svc.muted()
        for m in muted:
            print(f"{m.sid}  {m.note}".rstrip())
        if not muted:
            print("no muted rules")
        return 0
    if cmd == "home-net":
        if args.value is not None:
            return _report(await svc.set_home_net(args.value))
        current, default = await svc.home_net()
        print(f"current: {current}\ndefault:  {default}")
        return 0
    state = await svc.status()
    print(
        f"last update: {state.updated_at or 'never'}\nmd5: {state.last_md5}\n"
        f"rules: {state.rule_count}\nresult: {state.result}"
    )
    return 0


def main(argv: Sequence[str] | None = None, *, service: RulesService | None = None) -> int:
    args = _parser().parse_args(argv)
    return asyncio.run(_run(args, service or build_service()))


if __name__ == "__main__":
    raise SystemExit(main())
