from pathlib import Path

from dash_fakes import make_services

from snorty.compose import compose
from snorty.journal.ports import MemoryNoteStore
from snorty.notify.ports import ConsoleNotifier
from snorty.sensor import State
from snorty.snort import SnortPaths


async def test_compose_builds_every_service_and_starts_and_stops_without_snort(
    tmp_path: Path,
) -> None:
    rt = compose(
        tmp_path / "data",
        notify=True,
        notifier=ConsoleNotifier(),
        journal_store=MemoryNoteStore(),
        paths=SnortPaths(),
    )
    try:
        s = rt.services
        assert (tmp_path / "data" / "snorty.db").exists()
        assert s.sensor.state is State.STOPPED
        assert s.journal is not None and rt.notify is not None
        assert s.pcap_dir == tmp_path / "data" / "pcaps"
        await rt.start(sensor=False)
        await rt.stop()
        assert s.sensor.state is State.STOPPED
    finally:
        rt.services.repo.close()


async def test_compose_without_journal_or_notify(tmp_path: Path) -> None:
    rt = compose(tmp_path)
    try:
        assert rt.services.journal is None and rt.notify is None
        await rt.start()
        await rt.stop()
    finally:
        rt.services.repo.close()


def test_fake_services_have_the_pieces_the_pages_need(tmp_path: Path) -> None:
    s = make_services(tmp_path)
    assert s.sensor.state is State.STOPPED
    assert s.repo.query() == []
    s.repo.close()
