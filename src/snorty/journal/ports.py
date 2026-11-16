"""Where a day's note lives. The rest of the module only knows `NoteStore`."""

import contextlib
import os
import tempfile
from datetime import date
from pathlib import Path
from typing import Protocol


class StoreError(Exception):
    """The vault is missing or the target would be outside `Security/Snort/`."""


class NoteStore(Protocol):
    def read(self, day: date) -> str | None: ...

    def write(self, day: date, text: str) -> None: ...


class MemoryNoteStore:
    """For tests: keeps notes in a dict and records every write."""

    def __init__(self) -> None:
        self.notes: dict[date, str] = {}
        self.writes: list[tuple[date, str]] = []

    def read(self, day: date) -> str | None:
        return self.notes.get(day)

    def write(self, day: date, text: str) -> None:
        self.notes[day] = text
        self.writes.append((day, text))


class VaultNoteStore:
    """`<vault>/Security/Snort/YYYY-MM-DD.md`, confined to that folder.

    Writes go to a temp file in the same folder then `os.replace`, so a reader never
    sees half a note. The vault root must already exist; it is never created."""

    def __init__(self, vault_root: Path | str) -> None:
        self._root = Path(vault_root)

    def _folder(self, *, create: bool) -> Path | None:
        if not self._root.is_dir():
            raise StoreError(f"vault folder not found: {self._root}")
        base = self._root.resolve()
        folder = base / "Security" / "Snort"
        for part in (folder.parent, folder):  # check each level before creating anything in it
            if part.exists() and part.resolve() != part:  # a link or junction out of the vault
                raise StoreError(f"{part} resolves outside the vault")
            if not part.exists():
                if not create:
                    return None
                part.mkdir()
        return folder

    def _target(self, folder: Path, day: date) -> Path:
        target = folder / f"{day.isoformat()}.md"
        if target.is_symlink() or target.resolve().parent != folder:
            raise StoreError(f"{target} is a link, not a note")
        return target

    def read(self, day: date) -> str | None:
        folder = self._folder(create=False)
        if folder is None:
            return None
        target = self._target(folder, day)
        if not target.exists():
            return None
        return target.read_bytes().decode("utf-8")  # bytes: keep the file's own newlines

    def write(self, day: date, text: str) -> None:
        folder = self._folder(create=True)
        assert folder is not None
        target = self._target(folder, day)
        fd, tmp = tempfile.mkstemp(dir=folder, prefix=".snorty-", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(text.encode("utf-8"))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, target)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
