"""The two engine-specific steps of a lab run, behind one port: check that a sandbox config
loads, and run it over a pcap. Chosen when the service is built (Strategy)."""

import re
from datetime import datetime, tzinfo
from pathlib import Path
from typing import Protocol

from snorty import suricata
from snorty.core.models import Alert
from snorty.lab.conf import build_lab_conf, build_suricata_lab_conf
from snorty.lab.lint import Problem
from snorty.lab.models import LabResult
from snorty.snort import Runner, SnortPaths, check_config, list_interfaces, run_pcap

_RULE_ERROR = re.compile(r"lab\.rules\((\d+)\)\s*(.*)")
_SURICATA_RULE_ERROR = re.compile(
    r"error parsing signature .* from file .*lab\.rules at line (\d+)"
)


class LabEngine(Protocol):
    @property
    def live_conf(self) -> Path:
        """The live config; the sandbox config is written beside it."""
        ...

    def build_conf(self, live_text: str, rules_path: str) -> str: ...

    async def validate(self, conf: Path) -> LabResult | None:
        """None if the config loads, else the failure as a result."""
        ...

    async def alerts(self, conf: Path, pcap: Path, log_dir: Path) -> list[Alert]: ...


class SnortLabEngine:
    def __init__(
        self, paths: SnortPaths, runner: Runner, *, tz: tzinfo, year: int | None = None
    ) -> None:
        self._paths = paths
        self._runner = runner
        self._tz = tz
        self._year = year

    @property
    def live_conf(self) -> Path:
        return self._paths.conf

    def build_conf(self, live_text: str, rules_path: str) -> str:
        return build_lab_conf(live_text, rules_path)

    async def validate(self, conf: Path) -> LabResult | None:
        """`snort -T` on the sandbox config."""
        interfaces = await list_interfaces(self._paths, self._runner)
        if not interfaces:
            return LabResult(False, error="no network interface found for snort -T")
        iface = next((i for i in interfaces if "Loopback" in i.device), interfaces[0])
        check = await check_config(self._paths, iface, self._runner, conf=conf)
        if check.ok:
            return None
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

    async def alerts(self, conf: Path, pcap: Path, log_dir: Path) -> list[Alert]:
        return await run_pcap(
            self._paths,
            pcap,
            self._runner,
            year=self._year or datetime.now().year,
            tz=self._tz,
            conf=conf,
            log_dir=log_dir,
        )


class SuricataLabEngine:
    def __init__(
        self, paths: suricata.SuricataPaths, runner: Runner, *, year: int | None = None
    ) -> None:
        self._paths = paths
        self._runner = runner
        self._year = year

    @property
    def live_conf(self) -> Path:
        return self._paths.conf

    def build_conf(self, live_text: str, rules_path: str) -> str:
        return build_suricata_lab_conf(live_text, rules_path)

    async def validate(self, conf: Path) -> LabResult | None:
        """`suricata -T` on the sandbox config. Suricata stops at the first bad rule, so at most
        one problem comes back."""
        check = await suricata.check_config(self._paths, self._runner, conf=conf)
        if check.ok:
            return None
        for i, err in enumerate(check.errors):
            m = _SURICATA_RULE_ERROR.search(err)
            if m:  # the line before it says what is wrong with the rule
                detail = check.errors[i - 1] if i else err
                detail = re.sub(r"^E:\s*(?:[\w-]+:\s*)?", "", detail).strip()
                return LabResult(False, (Problem(int(m[1]), detail or err),))
        return LabResult(False, error="; ".join(check.errors) or None)

    async def alerts(self, conf: Path, pcap: Path, log_dir: Path) -> list[Alert]:
        return await suricata.run_pcap(
            self._paths,
            pcap,
            self._runner,
            year=self._year or datetime.now().year,
            conf=conf,
            log_dir=log_dir,
        )
