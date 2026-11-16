"""`python -m snorty.journal write [--date D] [--db PATH] [--vault PATH] [--dry-run]`."""

import argparse
import os
import sys
from datetime import date, datetime
from pathlib import Path

from snorty.core.localtz import LocalTimezone
from snorty.core.repository import AlertRepository
from snorty.journal.merge import NoteConflict
from snorty.journal.ports import NoteStore, StoreError, VaultNoteStore
from snorty.journal.service import JournalConfig, build_note


def _print_safe(text: str) -> None:
    """print() that cannot crash on a console whose encoding lacks a character we use."""
    enc = sys.stdout.encoding or "utf-8"
    print(text.encode(enc, "replace").decode(enc))


def main(argv: list[str] | None = None, *, store: NoteStore | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m snorty.journal")
    sub = parser.add_subparsers(dest="command", required=True)
    write = sub.add_parser("write", help="write one day's note")
    write.add_argument("--date", type=date.fromisoformat, help="YYYY-MM-DD, default today")
    write.add_argument("--db", type=Path, default=Path("snorty.db"))
    write.add_argument("--vault", help="vault folder, default $OBSIDIAN_VAULT_PATH")
    write.add_argument("--dry-run", action="store_true", help="print the note, write nothing")
    args = parser.parse_args(argv)

    tz = LocalTimezone()
    day: date = args.date or datetime.now(tz).date()
    vault = args.vault or os.environ.get("OBSIDIAN_VAULT_PATH")
    if store is None and vault:
        store = VaultNoteStore(vault)
    if store is None and not args.dry_run:
        parser.error("no vault: pass --vault or set OBSIDIAN_VAULT_PATH")
    if not args.db.exists():
        print(f"database not found: {args.db}", file=sys.stderr)
        return 1

    repo = AlertRepository(args.db)
    try:
        existing = store.read(day) if store else None
        text = build_note(repo, existing, day, JournalConfig(tz=tz))
        if text is None:
            print(f"no alerts on {day}; nothing written")
        elif args.dry_run:
            _print_safe(text)
        elif text == existing:
            print(f"{day}: unchanged")
        else:
            assert store is not None
            store.write(day, text)
            print(f"{day}: wrote the note")
    except (StoreError, NoteConflict, OSError) as exc:
        print(f"could not write the note: {exc}", file=sys.stderr)
        return 1
    finally:
        repo.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
