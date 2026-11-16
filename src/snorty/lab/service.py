"""The lab pipeline: lint, sandbox, `snort -T`, `snort -r`, summarize."""

import re
import shutil
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime, tzinfo
from pathlib import Path
from types import TracebackType

from snorty.core.models import Alert
from snorty.lab.conf import build_lab_conf
from snorty.lab.lint import LabRule, Problem, lint
from snorty.lab.models import LabJob, LabResult, RuleHit
from snorty.snort import Runner, SnortError, SnortPaths, check_config, list_interfaces, run_pcap

LAB_RULES_NAME = "lab.rules"
MAX_PCAP_BYTES = 50 * 1024 * 1024

_RULE_ERROR = re.compile(r"lab\.rules\((\d+)\)\s*(.*)")


def summarize(
    rules: Sequence[LabRule], alerts: Sequence[Alert]
) -> tuple[tuple[RuleHit, ...], tuple[Alert, ...]]:
    """A hit count per lab rule (zeros included, rule order) and the lab rules' alerts by time."""
    wanted = {r.sid for r in rules}
    matches = sorted(
        (a for a in alerts if a.gid == 1 and a.sid in wanted), key=lambda a: (a.ts, a.sid)
    )
    counts: dict[int, int] = {}
    for a in matches:
        counts[a.sid] = counts.get(a.sid, 0) + 1
    hits = tuple(RuleHit(r.sid, r.msg, r.line, counts.get(r.sid, 0)) for r in rules)
    return hits, tuple(matches)


class LabSandbox:
    """A temp folder (rules file, log folder) plus one temp config beside the live `snort.conf`.

    Everything it creates is removed on exit, also after an error or a cancel. It never
    writes to any live Snort file."""

    dir: Path
    log_dir: Path
    rules: Path
    conf: Path

    def __init__(self, paths: SnortPaths, rules_text: str) -> None:
        self._paths = paths
        self._rules_text = rules_text

    def __enter__(self) -> "LabSandbox":
        self.dir = Path(tempfile.mkdtemp(prefix="snorty-lab-"))
        self.conf = self._paths.conf.with_name(f"{self.dir.name}.conf")
        try:
            self.log_dir = self.dir / "log"
            self.log_dir.mkdir()
            self.rules = self.dir / LAB_RULES_NAME
            self.rules.write_bytes(self._rules_text.replace("\r\n", "\n").encode("utf-8"))
            live = self._paths.conf.read_bytes().decode("utf-8", errors="replace")
            self.conf.write_bytes(build_lab_conf(live, str(self.rules)).encode("utf-8"))
        except BaseException:
            self.close()
            raise
        return self

    def close(self) -> None:
        self.conf.unlink(missing_ok=True)
        shutil.rmtree(self.dir, ignore_errors=True)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def _pcap_problem(pcap: Path) -> str | None:
    if not pcap.is_file():
        return f"pcap not found: {pcap}"
    if pcap.stat().st_size > MAX_PCAP_BYTES:
        return f"pcap is larger than {MAX_PCAP_BYTES // (1024 * 1024)} MB: {pcap}"
    return None


class LabService:
    def __init__(
        self,
        paths: SnortPaths,
        runner: Runner,
        *,
        tz: tzinfo = UTC,
        year: int | None = None,
    ) -> None:
        self._paths = paths
        self._runner = runner
        self._tz = tz
        self._year = year

    async def run(self, job: LabJob) -> LabResult:
        """Run the rules against the pcap. User mistakes come back as data in the result."""
        checked = lint(job.rules_text)
        if not checked.ok:
            return LabResult(False, problems=checked.problems)
        if (problem := _pcap_problem(job.pcap)) is not None:
            return LabResult(False, error=problem)
        try:
            with LabSandbox(self._paths, job.rules_text) as box:
                return await self._run_in(box, checked.rules, job.pcap)
        except (OSError, ValueError, SnortError) as exc:
            return LabResult(False, error=f"could not run the lab: {exc}")

    async def _run_in(self, box: LabSandbox, rules: Sequence[LabRule], pcap: Path) -> LabResult:
        interfaces = await list_interfaces(self._paths, self._runner)
        if not interfaces:
            return LabResult(False, error="no network interface found for snort -T")
        iface = next((i for i in interfaces if "Loopback" in i.device), interfaces[0])
        check = await check_config(self._paths, iface, self._runner, conf=box.conf)
        if not check.ok:
            problems: list[Problem] = []
            other: list[str] = []
            for err in check.errors:
                m = _RULE_ERROR.search(err)
                if m:
                    problems.append(Problem(int(m[1]), m[2].strip() or err))
                else:
                    other.append(err)
            if problems:  # Snort's generic "Fatal Error, Quitting" line adds nothing
                other = [e for e in other if not e.startswith("Fatal Error, Quitting")]
            return LabResult(False, tuple(problems), "; ".join(other) or None)
        alerts = await run_pcap(
            self._paths,
            pcap,
            self._runner,
            year=self._year or datetime.now().year,
            tz=self._tz,
            conf=box.conf,
            log_dir=box.log_dir,
        )
        hits, matches = summarize(rules, alerts)
        return LabResult(True, hits=hits, matches=matches)
