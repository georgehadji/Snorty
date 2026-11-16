from datetime import date
from pathlib import Path

from journal_fakes import NOW, Rig, make_alert

from snorty.core.bus import EventBus
from snorty.core.repository import AlertRepository
from snorty.journal.ports import MemoryNoteStore, VaultNoteStore
from snorty.journal.service import JournalConfig, JournalService, JournalStatus


class FlakyOnce(MemoryNoteStore):
    def __init__(self) -> None:
        super().__init__()
        self.fail = True

    def write(self, day: date, text: str) -> None:
        if self.fail:
            raise OSError("disk full")
        super().write(day, text)


async def test_a_new_service_reports_nothing_written(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    assert rig.service.status() == JournalStatus(MemoryNoteStore.label, None, 0, None)
    rig.repo.close()


async def test_status_counts_notes_and_remembers_when_the_last_one_was_written(
    tmp_path: Path,
) -> None:
    rig = Rig(tmp_path)
    rig.add(make_alert(1), announce=False)
    await rig.service.start()
    st = rig.service.status()
    assert st.notes_written == 1 and st.last_written == NOW and st.error is None
    await rig.service.stop()
    rig.repo.close()


async def test_a_failing_write_sets_the_error_and_a_later_success_clears_it(
    tmp_path: Path,
) -> None:
    repo = AlertRepository(tmp_path / "a.db")
    repo.add(make_alert(1))
    store = FlakyOnce()
    service = JournalService(EventBus(), repo, store, JournalConfig(), now=lambda: NOW)
    await service.start()
    assert service.status().error and "disk full" in service.status().error
    assert service.status().notes_written == 0 and service.status().last_written is None
    store.fail = False
    await service.flush()
    assert service.status().error is None and service.status().notes_written == 1
    await service.stop()
    repo.close()


def test_the_vault_store_labels_the_folder_it_writes_to(tmp_path: Path) -> None:
    label = VaultNoteStore(tmp_path).label
    assert label == str(tmp_path / "Security" / "Snort")
