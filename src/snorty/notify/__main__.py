"""`python -m snorty.notify test [--priority N] [--msg TEXT] [--dry-run]` shows a sample toast."""

import argparse
import asyncio
import sys
from datetime import UTC, datetime

from snorty.core.models import Alert
from snorty.notify.ports import ConsoleNotifier, Notifier, WinotifyNotifier
from snorty.notify.toast import build_toast


def sample_alert(priority: int, msg: str) -> Alert:
    return Alert(
        ts=datetime.now(UTC),
        gid=1,
        sid=1000002,
        rev=1,
        msg=msg,
        classification=None,
        priority=priority,
        proto="TCP",
        src_ip="127.0.0.1",
        src_port=4444,
        dst_ip="127.0.0.1",
        dst_port=80,
        raw="snorty notify test",
    )


def main(argv: list[str] | None = None, *, notifier: Notifier | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m snorty.notify")
    sub = parser.add_subparsers(dest="command", required=True)
    test = sub.add_parser("test", help="show one sample toast")
    test.add_argument("--priority", type=int, default=1)
    test.add_argument("--msg", default="Snorty test alert")
    test.add_argument("--dry-run", action="store_true", help="print instead of showing a toast")
    args = parser.parse_args(argv)

    chosen = notifier or (ConsoleNotifier() if args.dry_run else WinotifyNotifier())
    toast = build_toast(sample_alert(args.priority, args.msg))
    try:
        asyncio.run(chosen.show(toast))
    except Exception as exc:
        print(f"could not show the toast: {exc!r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
