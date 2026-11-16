import asyncio
import hashlib
import os
import tempfile
import time
from pathlib import Path

import pytest
from lab_fakes import FakeSnort, alert_line, make_paths, rule

from snorty.lab.models import LabJob
from snorty.lab.service import LabService
from snorty.snort.models import RunResult, SnortError, SnortPaths


def snapshot(root: Path) -> dict[str, str]:
    """Every file under root (and every folder) with a content hash."""
    out: dict[str, str] = {}
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        out[rel] = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else "<dir>"
    return out


@pytest.fixture
def paths(tmp_path: Path) -> SnortPaths:
    return make_paths(tmp_path / "snort")


@pytest.fixture
def pcap(tmp_path: Path) -> Path:
    path = tmp_path / "t.pcap"
    path.write_bytes(b"pcap")
    return path


def gone(fake: FakeSnort) -> bool:
    """The sandbox config and its temp folder no longer exist."""
    conf = fake.conf_paths[0]
    return not conf.exists() and not (Path(tempfile.gettempdir()) / conf.stem).exists()


class Timeout:
    """A Runner whose -r call times out, like the real runner does."""

    def __init__(self, inner: FakeSnort) -> None:
        self.inner = inner

    async def __call__(self, argv: list[str], *, timeout: float) -> RunResult:
        if "-r" in argv:
            self.inner.conf_paths.append(Path(argv[argv.index("-c") + 1]))
            raise SnortError("snort timed out")
        return await self.inner(argv, timeout=timeout)


SCENARIOS = {
    "success": (FakeSnort(alert_text=alert_line(9000001)), rule(9000001)),
    "snort -T fails": (
        FakeSnort(check_output="ERROR: x/lab.rules(1) bad.\n", check_code=1),
        rule(9000001),
    ),
    "snort -r fails": (FakeSnort(run_code=1, run_stderr="Fatal Error"), rule(9000001)),
}


@pytest.mark.parametrize("name", list(SCENARIOS))
async def test_live_files_untouched_and_sandbox_removed(
    name: str, paths: SnortPaths, pcap: Path
) -> None:
    template, text = SCENARIOS[name]
    fake = FakeSnort(
        check_output=template.check_output,
        check_code=template.check_code,
        alert_text=template.alert_text,
        run_code=template.run_code,
        run_stderr=template.run_stderr,
    )
    before = snapshot(paths.conf.parent.parent)
    await LabService(paths, fake).run(LabJob(text, pcap))
    assert snapshot(paths.conf.parent.parent) == before  # includes "no extra file appeared"
    assert gone(fake)


async def test_lint_failure_touches_nothing(paths: SnortPaths, pcap: Path) -> None:
    before = snapshot(paths.conf.parent.parent)
    await LabService(paths, FakeSnort()).run(LabJob("config x\n", pcap))
    assert snapshot(paths.conf.parent.parent) == before


async def test_a_timeout_cleans_up(paths: SnortPaths, pcap: Path) -> None:
    fake = FakeSnort()
    before = snapshot(paths.conf.parent.parent)
    result = await LabService(paths, Timeout(fake)).run(LabJob(rule(9000001), pcap))  # type: ignore[arg-type]
    assert not result.ok and "timed out" in (result.error or "")
    assert snapshot(paths.conf.parent.parent) == before and gone(fake)


async def test_cancellation_cleans_up(paths: SnortPaths, pcap: Path) -> None:
    gate = asyncio.Event()  # never set: snort "hangs"
    fake = FakeSnort(run_gate=gate)
    before = snapshot(paths.conf.parent.parent)
    task = asyncio.create_task(LabService(paths, fake).run(LabJob(rule(9000001), pcap)))
    for _ in range(200):
        if fake.active:
            break
        await asyncio.sleep(0.005)
    assert fake.active == 1
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert snapshot(paths.conf.parent.parent) == before and gone(fake)


def age(path: Path, seconds: float) -> None:
    t = time.time() - seconds
    os.utime(path, (t, t))


async def test_stale_lab_configs_are_swept_and_nothing_else(paths: SnortPaths, pcap: Path) -> None:
    etc = paths.conf.parent
    old = etc / "snorty-lab-old1.conf"
    old_other = etc / "other-old.conf"
    young = etc / "snorty-lab-young.conf"
    for f in (old, old_other, young):
        f.write_text("x")
    age(old, 7200)
    age(old_other, 7200)
    age(young, 600)
    await LabService(paths, FakeSnort()).run(LabJob(rule(9000001), pcap))
    assert not old.exists()
    assert old_other.exists() and young.exists()


async def test_two_jobs_run_one_after_the_other(paths: SnortPaths, pcap: Path) -> None:
    fake = FakeSnort(run_delay=0.03)
    service = LabService(paths, fake)
    job = LabJob(rule(9000001), pcap)
    results = await asyncio.gather(service.run(job), service.run(job), service.run(job))
    assert all(r.ok for r in results)
    assert fake.max_active == 1
    assert fake.flags().count("r") == 3


async def test_a_cancelled_waiter_does_not_block_later_jobs(paths: SnortPaths, pcap: Path) -> None:
    gate = asyncio.Event()
    fake = FakeSnort(run_gate=gate)
    service = LabService(paths, fake)
    job = LabJob(rule(9000001), pcap)
    first = asyncio.create_task(service.run(job))
    for _ in range(200):
        if fake.active:
            break
        await asyncio.sleep(0.005)
    waiter = asyncio.create_task(service.run(job))
    await asyncio.sleep(0.02)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    gate.set()
    assert (await first).ok
    assert (await service.run(job)).ok


async def test_a_temp_path_with_spaces_is_an_error_not_a_snort_run(
    paths: SnortPaths, pcap: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spaced = tmp_path / "my temp"
    spaced.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(spaced))
    fake = FakeSnort()
    before = snapshot(paths.conf.parent.parent)
    result = await LabService(paths, fake).run(LabJob(rule(9000001), pcap))
    assert not result.ok and "whitespace" in (result.error or "")
    assert fake.calls == []
    assert list(spaced.iterdir()) == []  # the half-made sandbox was removed
    assert snapshot(paths.conf.parent.parent) == before
