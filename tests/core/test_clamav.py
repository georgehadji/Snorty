"""ClamAV hash signatures, matched against the MD5s Suricata logs for files on alerted flows."""

import asyncio
import hashlib
import io
import tarfile
from pathlib import Path

from test_host_context import stored, with_ends
from test_repository import make_alert

from snorty.core.bus import EventBus
from snorty.core.events import AlertFlagged, FilesSeen
from snorty.core.models import FlowFact
from snorty.core.repository import AlertRepository
from snorty.enrich import EnrichService
from snorty.enrich.clamav import ClamHashes, read_database

BAD = hashlib.md5(b"bad file", usedforsecurity=False).hexdigest()
CLEAN = hashlib.md5(b"clean file", usedforsecurity=False).hexdigest()
SHA = hashlib.sha256(b"other file").hexdigest()
LABEL = "ClamAV signature Win.Trojan.Test-1"


def test_signatures_name_a_whole_file_hash_and_skip_known_clean_files() -> None:
    rows = [
        f"{BAD}:8:Win.Trojan.Test-1",
        f"{CLEAN.upper()}:10:Win.FP.Test-2",
        f"{SHA}:*:Doc.Bad-3",
        f"{'zz' * 16}:1:Broken",
        f"{BAD[:-1]}:1:Short",
        f"{BAD}:8:",
        "nocolons",
        "",
    ]
    table = ClamHashes.parse(rows, [f"{CLEAN}:10:Win.FP.Test-2"])
    assert len(table) == 2
    assert table.find(BAD) == LABEL and table.find(BAD.upper()) == LABEL
    assert table.find(SHA) == "ClamAV signature Doc.Bad-3"
    assert table.find(CLEAN) is None and ClamHashes().find(BAD) is None


def cvd(path: Path, members: dict[str, str], *, packed: bool = True) -> None:
    """A database file as freshclam leaves it: a 512-byte header, then a (gzipped) tar."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz" if packed else "w") as tar:
        for name, text in members.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    path.write_bytes(b"ClamAV-VDB:test".ljust(512, b" ") + buf.getvalue())


def test_the_database_folder_is_read_from_cvd_and_cld_files(tmp_path: Path) -> None:
    cvd(
        tmp_path / "main.cvd",
        {
            "main.hdb": f"{BAD}:8:Win.Trojan.Test-1\n",
            "main.mdb": "45056:3ea7d00dedd30bcdf46191358c36ffa4:Pe.Section-9\n",  # needs the file
            "main.fp": f"{CLEAN}:10:sid1\n",
        },
    )
    cvd(
        tmp_path / "daily.cld",
        {"daily.hsb": f"{SHA}:*:Doc.Bad-3\n{CLEAN}:10:Win.FP.Test-2\n"},
        packed=False,
    )
    (tmp_path / "broken.cvd").write_bytes(b"x" * 600)
    (tmp_path / "daily-1.cvd.sign").write_bytes(b"signature, not a database")
    table = read_database(tmp_path)
    assert len(table) == 2 and table.find(BAD) == LABEL and table.find(SHA) is not None
    assert table.find(CLEAN) is None and table.find("3ea7d00dedd30bcdf46191358c36ffa4") is None
    assert len(read_database(tmp_path / "missing")) == 0


def database(tmp_path: Path) -> Path:
    folder = tmp_path / "clamav"
    folder.mkdir()
    cvd(folder / "main.cvd", {"main.hdb": f"{BAD}:8:Win.Trojan.Test-1\n"})
    return folder


def test_a_file_matching_a_signature_flags_every_alert_on_its_flow(tmp_path: Path) -> None:
    repo = AlertRepository(tmp_path / "t.db")
    svc = EnrichService(EventBus(), repo, tmp_path / "enrich", clamav=database(tmp_path))
    svc.load()
    a = stored(repo, with_ends(make_alert(1), raw="eve:7:1000:t"))
    b = stored(repo, with_ends(make_alert(2), raw="eve:7:1001:t"))
    other = stored(repo, with_ends(make_alert(3), raw="eve:8:1002:t"))
    files = [
        FlowFact(7, "md5", BAD, a.ts),
        FlowFact(8, "md5", CLEAN, a.ts),
        FlowFact(7, "file", "setup.exe", a.ts),
    ]
    assert {(x.id, label) for x, label in svc.check_files(files)} == {(a.id, LABEL), (b.id, LABEL)}
    assert repo.annotations(a.id)["bad"] == LABEL and "bad" not in repo.annotations(other.id)
    assert svc.check_files(files) == []  # the same file logged again flags nothing twice
    repo.close()


async def test_files_seen_on_the_bus_raise_a_flag(tmp_path: Path) -> None:
    repo = AlertRepository(tmp_path / "t.db")
    bus = EventBus()
    flags = bus.subscribe(accept=lambda e: isinstance(e, AlertFlagged))
    svc = EnrichService(bus, repo, tmp_path / "enrich", clamav=database(tmp_path))
    await svc.start()
    a = stored(repo, with_ends(make_alert(1), raw="eve:7:1000:t"))
    bus.publish(FilesSeen((FlowFact(7, "md5", BAD, a.ts),)))
    event = await asyncio.wait_for(anext(aiter(flags)), 2)
    assert isinstance(event, AlertFlagged) and event.alert.id == a.id and event.reason == LABEL
    await svc.stop()
    repo.close()
