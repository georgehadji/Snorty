from collections.abc import Sequence
from datetime import UTC
from pathlib import Path

import pytest
from pcap import tcp_frame, write_pcap  # helper next to this file (pytest adds the dir to sys.path)

from snorty.snort.models import RunResult, SnortError, SnortPaths
from snorty.snort.runner import SubprocessRunner
from snorty.snort.service import run_pcap

ALERT = (
    "11/15/26-23:30:13.875248  [**] [1:1000002:1] NIDS test - uid=0(root) response [**] "
    "[Priority: 0] {TCP} 127.0.0.1:18080 -> 127.0.0.1:60998"
)


class WritingRunner:
    """Fake Runner: pretends to be Snort and writes `alert_text` into the -l directory."""

    def __init__(self, alert_text: str, returncode: int = 0, stderr: str = "") -> None:
        self.alert_text, self.returncode, self.stderr = alert_text, returncode, stderr
        self.calls: list[list[str]] = []

    async def __call__(self, argv: Sequence[str], *, timeout: float) -> RunResult:
        self.calls.append(list(argv))
        log_dir = Path(argv[list(argv).index("-l") + 1])
        (log_dir / "alert.ids").write_text(self.alert_text)
        return RunResult(self.returncode, "", self.stderr)

    @property
    def log_dir(self) -> Path:
        argv = self.calls[0]
        return Path(argv[argv.index("-l") + 1])


def make_pcap(tmp_path: Path) -> Path:
    path = tmp_path / "t.pcap"
    path.write_bytes(b"pcap")
    return path


async def test_returns_parsed_alerts_and_skips_junk_lines(tmp_path: Path) -> None:
    runner = WritingRunner(f"{ALERT}\nnot an alert\n\n")
    alerts = await run_pcap(SnortPaths(), make_pcap(tmp_path), runner, year=2026, tz=UTC)
    assert [a.sid for a in alerts] == [1000002]


async def test_missing_pcap_raises_before_running(tmp_path: Path) -> None:
    runner = WritingRunner("")
    with pytest.raises(SnortError, match="not found"):
        await run_pcap(SnortPaths(), tmp_path / "nope.pcap", runner, year=2026, tz=UTC)
    assert runner.calls == []


async def test_nonzero_exit_raises_with_stderr_tail(tmp_path: Path) -> None:
    runner = WritingRunner("", returncode=1, stderr="line1\nFatal Error, Quitting..")
    with pytest.raises(SnortError, match="Fatal Error"):
        await run_pcap(SnortPaths(), make_pcap(tmp_path), runner, year=2026, tz=UTC)


async def test_temp_dir_removed_when_no_log_dir_given(tmp_path: Path) -> None:
    runner = WritingRunner(ALERT)
    await run_pcap(SnortPaths(), make_pcap(tmp_path), runner, year=2026, tz=UTC)
    assert not runner.log_dir.exists()


async def test_given_log_dir_is_kept_and_conf_is_passed(tmp_path: Path) -> None:
    runner = WritingRunner(ALERT)
    log_dir = tmp_path / "lab-log"
    conf = tmp_path / "lab.conf"
    await run_pcap(
        SnortPaths(), make_pcap(tmp_path), runner, conf=conf, log_dir=log_dir, year=2026, tz=UTC
    )
    assert (log_dir / "alert.ids").exists()
    assert str(conf) in runner.calls[0]


@pytest.mark.snort
async def test_real_snort_finds_alert_in_handmade_pcap(tmp_path: Path) -> None:
    pcap = tmp_path / "attack.pcap"
    write_pcap(
        pcap,
        [tcp_frame("10.0.0.5", "10.0.0.9", 8080, 51000, b"uid=0(root) gid=0(root)\n")],
    )
    alerts = await run_pcap(SnortPaths(), pcap, SubprocessRunner(), year=2026, tz=UTC)
    assert 1000002 in {a.sid for a in alerts}
