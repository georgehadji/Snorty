"""Pure placement of the managed block into a day's note."""

from datetime import date

from snorty.journal.render import BEGIN, END


class NoteConflict(Exception):
    """The note's markers are not one begin followed by one end: do not touch the file."""


def _new_note(block: str, day: date) -> str:
    return (
        f"---\ndate: {day.isoformat()}\ntype: snort-journal\ntags:\n  - security\n  - snort\n"
        f"ai-first: true\n---\n\n# {day.isoformat()} Snort journal\n\n{block}"
    )


def merge(existing: str | None, block: str, day: date) -> str:
    """The note text after putting `block` in. Raises NoteConflict on broken markers.

    Text outside the markers, frontmatter included, is never changed."""
    if not (block.startswith(BEGIN) and block.rstrip("\n").endswith(END)):
        raise ValueError("block must be a rendered managed block")
    if existing is None:
        return _new_note(block, day)
    begins, ends = existing.count(BEGIN), existing.count(END)
    if begins == 0 and ends == 0:
        sep = "" if not existing else "\n" if existing.endswith("\n") else "\n\n"
        return existing + sep + block
    if begins != 1 or ends != 1 or existing.index(BEGIN) > existing.index(END):
        raise NoteConflict(f"the markers in the note for {day} are not one begin and one end")
    start = existing.index(BEGIN)
    stop = existing.index(END) + len(END)
    return existing[:start] + block.rstrip("\n") + existing[stop:]
