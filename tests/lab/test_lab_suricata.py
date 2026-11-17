import json
from collections.abc import Sequence
from pathlib import Path

import pytest
from lab_fakes import rule

from snorty.lab.conf import build_suricata_lab_conf
from snorty.lab.engines import SuricataLabEngine
from snorty.lab.models import LabJob
from snorty.lab.service import LabService
from snorty.snort.models import RunResult
from snorty.suricata import SuricataPaths

YAML = (
    "default-log-dir: C:\\log\r\n"
    "default-rule-path: C:\\live\\rules\r\n"
    "rule-files:\r\n"
    " - botcc.rules\r\n"
    " # - skipped.rules\r\n"
    " - emerging-dns.rules\r\n"
    "classification-file: C:\\c.config\r\n"
)
RULES = "C:\\tmp\\snorty-lab-x\\lab.rules"


def test_lab_conf_swaps_the_rule_list_and_path_and_keeps_the_rest() -> None:
    out = build_suricata_lab_conf(YAML, RULES)
    assert out == (
        "default-log-dir: C:\\log\r\n"
        "default-rule-path: C:\\tmp\\snorty-lab-x\r\n"
        "rule-files:\r\n"
        " - lab.rules\r\n"
        "classification-file: C:\\c.config\r\n"
    )


def test_lab_conf_needs_a_rule_list() -> None:
    with pytest.raises(ValueError, match="rule-files"):
        build_suricata_lab_conf("outputs:\n", RULES)


EVE = {
    "timestamp": "2026-11-17T10:15:30.000001+0000",
    "flow_id": 5,
    "event_type": "alert",
    "src_ip": "10.0.0.1",
    "dest_ip": "10.0.0.2",
    "src_port": 4444,
    "dest_port": 80,
    "proto": "TCP",
    "alert": {"signature_id": 9000001, "signature": "lab rule", "severity": 1},
}


class FakeSuricata:
    def __init__(self, check_errors: str = "", check_code: int = 0, eve: str = "") -> None:
        self.check_errors, self.check_code, self.eve = check_errors, check_code, eve
        self.confs: list[Path] = []

    async def __call__(self, argv: Sequence[str], *, timeout: float) -> RunResult:
        conf = Path(argv[argv.index("-c") + 1])
        self.confs.append(conf)
        assert "lab.rules" in conf.read_text()
        if "-T" in argv:
            return RunResult(self.check_code, "", self.check_errors)
        log_dir = Path(argv[argv.index("-l") + 1])
        (log_dir / "eve.json").write_text(self.eve)
        return RunResult(0, "", "")


def setup(tmp_path: Path) -> tuple[SuricataPaths, Path]:
    conf = tmp_path / "suricata.yaml"
    conf.write_bytes(YAML.encode())
    pcap = tmp_path / "t.pcap"
    pcap.write_bytes(b"x")
    paths = SuricataPaths(exe=tmp_path / "suricata.exe", conf=conf, log_dir=tmp_path / "log")
    return paths, pcap


def service(paths: SuricataPaths, runner: FakeSuricata) -> LabService:
    engine = SuricataLabEngine(paths, runner, year=2026)
    return LabService(None, runner, engine=engine)  # type: ignore[arg-type]


async def test_run_counts_hits_from_eve_json(tmp_path: Path) -> None:
    paths, pcap = setup(tmp_path)
    fake = FakeSuricata(eve=json.dumps(EVE) + "\n" + json.dumps({"event_type": "dns"}) + "\n")

    result = await service(paths, fake).run(LabJob(rule(9000001), pcap))

    assert result.ok and result.error is None
    assert [(h.sid, h.count) for h in result.hits] == [(9000001, 1)]
    assert [a.sid for a in result.matches] == [9000001]
    # the sandbox config and folder are gone, and the live config is untouched
    assert not any(p.name.startswith("snorty-lab-") for p in tmp_path.iterdir())
    assert paths.conf.read_bytes() == YAML.encode()


async def test_unloadable_rule_comes_back_as_a_problem_on_its_line(tmp_path: Path) -> None:
    paths, pcap = setup(tmp_path)
    err = (
        "E: detect-parse: unknown rule keyword 'file.magic'.\n"
        'E: detect: error parsing signature "alert x" from file C:\\t\\lab.rules at line 1\n'
    )
    fake = FakeSuricata(check_errors=err, check_code=1)

    result = await service(paths, fake).run(LabJob(rule(9000001), pcap))

    assert not result.ok
    (problem,) = result.problems
    assert problem.line == 1 and "unknown rule keyword 'file.magic'" in problem.message


async def test_a_refusal_without_a_rule_is_reported_as_an_error(tmp_path: Path) -> None:
    paths, pcap = setup(tmp_path)
    fake = FakeSuricata(check_errors="E: runmodes: output module failed\n", check_code=1)

    result = await service(paths, fake).check(rule(9000001))

    assert not result.ok and not result.problems
    assert result.error is not None and "output module failed" in result.error
