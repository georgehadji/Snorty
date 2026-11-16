"""Real Snort at C:\\Snort. Run with `pytest tests/lab -m snort`."""

import hashlib
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from snorty.lab.models import LabJob
from snorty.lab.pcapgen import build_pcap, make_frames
from snorty.lab.service import LabService
from snorty.snort import SnortPaths, SubprocessRunner

pytestmark = pytest.mark.snort

PATHS = SnortPaths()
ROOT = PATHS.conf.parent.parent  # C:\Snort

UID_RULE = (
    'alert tcp any any -> any any (msg:"lab uid root"; content:"uid=0|28|root|29|"; '
    "sid:9000001; rev:1;)"
)
OTHER_RULE = 'alert tcp any any -> any any (msg:"lab other"; content:"nothing-here"; sid:9000002; rev:1;)'
EST_RULE = (
    'alert tcp any any -> any 80 (msg:"lab established"; flow:established,to_server; '
    'content:"hello"; sid:9000003; rev:1;)'
)
BAD_RULE = 'alert tcp any any -> any 80 (msg:"lab bad"; nosuchoption:1; sid:9000004; rev:1;)'


def snapshot() -> dict[str, str]:
    """Hash of every file in the live Snort etc, rules and log folders (and their names)."""
    out: dict[str, str] = {}
    for folder in ("etc", "rules", "log"):
        for p in sorted((ROOT / folder).rglob("*")):
            rel = p.relative_to(ROOT).as_posix()
            out[rel] = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else "<dir>"
    return out


def snort_running() -> bool:
    out = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq snort.exe", "/FO", "CSV", "/NH"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    return "snort.exe" in out.lower()


@pytest.fixture
def live_untouched() -> Iterator[None]:
    if not PATHS.exe.exists():
        pytest.skip("Snort is not installed at C:\\Snort")
    before = snapshot()
    yield
    assert snapshot() == before, "the lab changed a live Snort file"
    assert list((ROOT / "etc").glob("snorty-lab-*.conf")) == []
    assert not snort_running()


@pytest.fixture
def service() -> LabService:
    return LabService(PATHS, SubprocessRunner())


def make_pcap(tmp_path: Path, payload: bytes, *, handshake: bool = False) -> Path:
    frames = make_frames("tcp", "10.0.0.1", 4444, "10.0.0.2", 80, payload, handshake=handshake)
    path = tmp_path / "t.pcap"
    path.write_bytes(build_pcap(frames, start=time.time()))
    return path


async def test_the_lab_config_built_from_the_real_snort_conf_loads(
    service: LabService, live_untouched: None
) -> None:
    result = await service.check(f"{UID_RULE}\n")
    assert result.ok, (result.problems, result.error)


async def test_a_generated_packet_triggers_a_rule_and_an_unrelated_rule_shows_zero(
    service: LabService, tmp_path: Path, live_untouched: None
) -> None:
    pcap = make_pcap(tmp_path, b"uid=0(root) gid=0(root)")
    result = await service.run(LabJob(f"{UID_RULE}\n{OTHER_RULE}\n", pcap))
    assert result.ok, (result.problems, result.error)
    assert [(h.sid, h.count) for h in result.hits] == [(9000001, 1), (9000002, 0)]
    assert [a.sid for a in result.matches] == [9000001]


async def test_a_handshake_makes_a_flow_established_rule_match(
    service: LabService, tmp_path: Path, live_untouched: None
) -> None:
    pcap = make_pcap(tmp_path, b"hello world", handshake=True)
    result = await service.run(LabJob(f"{EST_RULE}\n", pcap))
    assert result.ok, (result.problems, result.error)
    assert result.hits[0].count >= 1


async def test_a_broken_rule_is_reported_on_its_line_and_the_pcap_is_not_run(
    service: LabService, tmp_path: Path, live_untouched: None
) -> None:
    pcap = make_pcap(tmp_path, b"x")
    result = await service.run(LabJob(f"{UID_RULE}\n{BAD_RULE}\n", pcap))
    assert not result.ok
    assert result.problems and result.problems[0].line == 2, (result.problems, result.error)
    assert result.hits == () and result.matches == ()
