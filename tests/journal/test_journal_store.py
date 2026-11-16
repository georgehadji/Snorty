import os
import sys
from datetime import date
from pathlib import Path

import pytest

from snorty.journal.ports import MemoryNoteStore, StoreError, VaultNoteStore

DAY = date(2026, 11, 16)


def make_link(link: Path, target: Path) -> None:
    """A directory link without admin rights: a junction on Windows, a symlink elsewhere."""
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        os.symlink(target, link, target_is_directory=True)


@pytest.fixture
def vault(tmp_path: Path) -> Path:
    root = tmp_path / "vault"
    root.mkdir()
    return root


def test_read_of_a_missing_note_or_folder_is_none(vault: Path) -> None:
    assert VaultNoteStore(vault).read(DAY) is None


def test_write_creates_the_folder_and_round_trips(vault: Path) -> None:
    store = VaultNoteStore(vault)
    store.write(DAY, "héllo → world\n")
    assert (
        vault / "Security" / "Snort" / "2026-11-16.md"
    ).read_bytes() == "héllo → world\n".encode()
    assert store.read(DAY) == "héllo → world\n"


def test_newlines_are_kept_exactly(vault: Path) -> None:
    store = VaultNoteStore(vault)
    store.write(DAY, "a\r\nb\n")
    assert store.read(DAY) == "a\r\nb\n"


def test_write_replaces_and_leaves_no_temp_file(vault: Path) -> None:
    store = VaultNoteStore(vault)
    store.write(DAY, "one")
    store.write(DAY, "two")
    assert store.read(DAY) == "two"
    assert [p.name for p in (vault / "Security" / "Snort").iterdir()] == ["2026-11-16.md"]


def test_a_failed_replace_keeps_the_old_note_and_cleans_up(
    vault: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = VaultNoteStore(vault)
    store.write(DAY, "old")

    def boom(src: object, dst: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="disk full"):
        store.write(DAY, "new")
    monkeypatch.undo()
    assert store.read(DAY) == "old"
    assert [p.name for p in (vault / "Security" / "Snort").iterdir()] == ["2026-11-16.md"]


def test_a_missing_vault_root_is_an_error_and_is_not_created(tmp_path: Path) -> None:
    root = tmp_path / "nope"
    for op in (lambda s: s.read(DAY), lambda s: s.write(DAY, "x")):
        with pytest.raises(StoreError):
            op(VaultNoteStore(root))
    assert not root.exists()


def test_a_linked_security_folder_that_leaves_the_vault_is_refused(
    vault: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    make_link(vault / "Security", outside)
    store = VaultNoteStore(vault)
    with pytest.raises(StoreError):
        store.write(DAY, "x")
    with pytest.raises(StoreError):
        store.read(DAY)
    assert list(outside.rglob("*")) == []


def test_a_note_that_is_a_symlink_is_refused(vault: Path, tmp_path: Path) -> None:
    folder = vault / "Security" / "Snort"
    folder.mkdir(parents=True)
    secret = tmp_path / "secret.txt"
    secret.write_text("secret")
    try:
        os.symlink(secret, folder / "2026-11-16.md")
    except OSError:
        pytest.skip("symlinks need privileges here")
    with pytest.raises(StoreError):
        VaultNoteStore(vault).write(DAY, "x")
    assert secret.read_text() == "secret"


def test_other_notes_in_the_folder_are_never_touched(vault: Path) -> None:
    folder = vault / "Security" / "Snort"
    folder.mkdir(parents=True)
    (folder / "mine.md").write_text("mine")
    VaultNoteStore(vault).write(DAY, "x")
    assert (folder / "mine.md").read_text() == "mine"


def test_memory_store_records_writes() -> None:
    store = MemoryNoteStore()
    assert store.read(DAY) is None
    store.write(DAY, "a")
    store.write(DAY, "b")
    assert store.read(DAY) == "b" and [t for _, t in store.writes] == ["a", "b"]
