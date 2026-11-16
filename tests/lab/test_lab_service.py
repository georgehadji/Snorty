from datetime import UTC, datetime
from pathlib import Path

import pytest
from lab_fakes import FakeSnort, alert_line, make_paths, rule

import snorty.lab.service as service_module
from snorty.core.models import Alert
from snorty.lab.lint import LabRule, Problem
from snorty.lab.models import LabJob, RuleHit
from snorty.lab.service import LabService, summarize
from snorty.snort.models import SnortError


def make_alert(sid: int, minute: int = 0, gid: int = 1) -> Alert:
    return Alert(
        ts=datetime(2026, 11, 15, 12, minute, tzinfo=UTC),
        gid=gid,
        sid=sid,
        rev=1,
        msg=f"m{sid}",
        classification=None,
        priority=1,
        proto="TCP",
        src_ip="10.0.0.1",
        src_port=1,
        dst_ip="10.0.0.2",
        dst_port=2,
        raw=f"{gid}:{sid}:{minute}",
    )


# --- summarize -------------------------------------------------------------------------


def test_summarize_counts_every_rule_zeros_included_in_rule_order() -> None:
    rules = [LabRule(1, 20, "b"), LabRule(2, 10, "a"), LabRule(3, 30, "c")]
    alerts = [make_alert(10, 5), make_alert(10, 1), make_alert(30, 3)]
    hits, matches = summarize(rules, alerts)
    assert hits == (RuleHit(20, "b", 1, 0), RuleHit(10, "a", 2, 2), RuleHit(30, "c", 3, 1))
    assert [(a.sid, a.ts.minute) for a in matches] == [(10, 1), (30, 3), (10, 5)]


def test_summarize_ignores_other_sids_and_other_generators() -> None:
    hits, matches = summarize([LabRule(1, 10, "a")], [make_alert(99), make_alert(10, gid=116)])
    assert hits[0].count == 0 and matches == ()


# --- pipeline --------------------------------------------------------------------------


@pytest.fixture
def paths(tmp_path: Path):  # type: ignore[no-untyped-def]
    return make_paths(tmp_path / "snort")


@pytest.fixture
def pcap(tmp_path: Path) -> Path:
    path = tmp_path / "t.pcap"
    path.write_bytes(b"pcap")
    return path


async def test_bad_rules_stop_at_lint_with_no_snort_call(paths, pcap: Path) -> None:  # type: ignore[no-untyped-def]
    fake = FakeSnort()
    result = await LabService(paths, fake).run(LabJob("include /etc/passwd\n", pcap))
    assert not result.ok and [p.line for p in result.problems] == [1]
    assert fake.calls == []


async def test_a_missing_pcap_stops_before_snort(paths, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    fake = FakeSnort()
    result = await LabService(paths, fake).run(LabJob(rule(9000001), tmp_path / "nope.pcap"))
    assert not result.ok and "not found" in (result.error or "") and fake.calls == []


async def test_a_directory_is_not_a_pcap(paths, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    fake = FakeSnort()
    result = await LabService(paths, fake).run(LabJob(rule(9000001), tmp_path))
    assert not result.ok and "not found" in (result.error or "") and fake.calls == []


async def test_an_oversized_pcap_stops_before_snort(
    paths,
    pcap: Path,
    monkeypatch: pytest.MonkeyPatch,  # type: ignore[no-untyped-def]
) -> None:
    monkeypatch.setattr(service_module, "MAX_PCAP_BYTES", 2)
    fake = FakeSnort()
    result = await LabService(paths, fake).run(LabJob(rule(9000001), pcap))
    assert not result.ok and "larger than" in (result.error or "") and fake.calls == []


async def test_a_snort_rule_error_is_mapped_to_the_users_line_and_the_pcap_is_not_run(
    paths,
    pcap: Path,  # type: ignore[no-untyped-def]
) -> None:
    out = (
        "ERROR: C:/Temp/snorty-lab-x/lab.rules(2) Unknown ruleoption: 'foo'.\n"
        "Fatal Error, Quitting..\n"
    )
    fake = FakeSnort(check_output=out, check_code=1)
    text = f"{rule(9000001)}\n{rule(9000002)}\n"
    result = await LabService(paths, fake).run(LabJob(text, pcap))
    assert not result.ok
    assert result.problems == (Problem(2, "Unknown ruleoption: 'foo'."),)
    assert result.error is None
    assert fake.flags() == ["W", "T"]


async def test_another_check_failure_becomes_an_error(paths, pcap: Path) -> None:  # type: ignore[no-untyped-def]
    fake = FakeSnort(check_output="ERROR: snort.conf(10) something else\n", check_code=1)
    result = await LabService(paths, fake).run(LabJob(rule(9000001), pcap))
    assert not result.ok and result.problems == () and "something else" in (result.error or "")


async def test_a_failing_pcap_run_becomes_an_error_with_snorts_last_lines(
    paths,
    pcap: Path,  # type: ignore[no-untyped-def]
) -> None:
    fake = FakeSnort(run_code=1, run_stderr="boom\nFatal Error: bad pcap")
    result = await LabService(paths, fake).run(LabJob(rule(9000001), pcap))
    assert not result.ok and "bad pcap" in (result.error or "")


async def test_matches_and_hit_counts_for_a_valid_run(paths, pcap: Path) -> None:  # type: ignore[no-untyped-def]
    alerts = "\n".join(
        [
            alert_line(9000001, "rule a", "11/15-23:30:14.000000"),
            alert_line(9000001, "rule a", "11/15-23:30:13.000000"),
            alert_line(555, "not ours"),
        ]
    )
    fake = FakeSnort(alert_text=alerts)
    text = f"{rule(9000001, 'rule a')}\n{rule(9000002, 'rule b')}\n"
    result = await LabService(paths, fake, year=2026).run(LabJob(text, pcap))
    assert result.ok and result.error is None and result.problems == ()
    assert [(h.sid, h.msg, h.line, h.count) for h in result.hits] == [
        (9000001, "rule a", 1, 2),
        (9000002, "rule b", 2, 0),
    ]
    assert [a.ts.second for a in result.matches] == [13, 14]


async def test_snort_gets_the_sandbox_config_and_the_live_files_are_untouched(
    paths,
    pcap: Path,  # type: ignore[no-untyped-def]
) -> None:
    before = paths.conf.read_bytes()
    fake = FakeSnort()
    await LabService(paths, fake).run(LabJob(rule(9000001), pcap))
    assert fake.flags() == ["W", "T", "r"]
    sandbox_conf = fake.conf_paths[0]
    assert sandbox_conf != paths.conf and sandbox_conf.parent == paths.conf.parent
    assert sandbox_conf.name.startswith("snorty-lab-") and sandbox_conf.suffix == ".conf"
    seen = fake.conf_seen[0]
    assert "emerging-dns" not in seen and "local.rules" not in seen
    assert "threshold.conf" not in seen and "lab.rules" in seen
    assert "preprocessor stream5_global" in seen
    assert paths.conf.read_bytes() == before


async def test_t_uses_the_loopback_interface(paths, pcap: Path) -> None:  # type: ignore[no-untyped-def]
    fake = FakeSnort()
    await LabService(paths, fake).run(LabJob(rule(9000001), pcap))
    argv = next(c for c in fake.calls if "-T" in c)
    assert argv[argv.index("-i") + 1] == "2"


async def test_no_interface_is_an_error(paths, pcap: Path) -> None:  # type: ignore[no-untyped-def]
    fake = FakeSnort(interfaces="nothing useful\n")
    result = await LabService(paths, fake).run(LabJob(rule(9000001), pcap))
    assert not result.ok and "interface" in (result.error or "")


async def test_a_snort_error_from_the_runner_becomes_an_error(paths, pcap: Path) -> None:  # type: ignore[no-untyped-def]
    class Broken:
        async def __call__(self, argv: object, *, timeout: float) -> None:
            raise SnortError("snort.exe not found")

    result = await LabService(paths, Broken()).run(LabJob(rule(9000001), pcap))  # type: ignore[arg-type]
    assert not result.ok and "snort.exe not found" in (result.error or "")
