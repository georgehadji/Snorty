import base64
import re
from collections.abc import Sequence

import pytest

from snorty.respond.ports import FirewallError, NeedsAdmin
from snorty.snort.models import RunResult
from snorty.winfw import PowerShellFirewall
from snorty.winfw.firewall import elevated


class FakeRunner:
    def __init__(self, result: RunResult | None = None) -> None:
        self.result = result or RunResult(0, "", "")
        self.scripts: list[str] = []
        self.timeouts: list[float] = []

    async def __call__(self, argv: Sequence[str], *, timeout: float) -> RunResult:
        assert argv[0] == "powershell.exe" and "-NonInteractive" in argv
        self.scripts.append(argv[-1])
        self.timeouts.append(timeout)
        return self.result


def inner(wrapper: str) -> str:
    """The script an elevated PowerShell would run, decoded from the wrapper."""
    match = re.search(r"'-EncodedCommand','([^']+)'", wrapper)
    assert match, wrapper
    return base64.b64decode(match[1]).decode("utf-16-le")


async def test_writes_run_elevated_and_reads_do_not() -> None:
    runner = FakeRunner()
    fw = PowerShellFirewall(runner)
    await fw.block("8.8.4.4")
    await fw.unblock("8.8.4.4")
    await fw.blocked()
    await fw.protected()
    assert ["-Verb RunAs" in s for s in runner.scripts] == [True, True, False, False]
    assert runner.timeouts[0] > 60  # the user has to click the permission prompt


async def test_the_inner_script_cannot_be_altered_by_quoting() -> None:
    wrapper = elevated("Write-Output 'it''s \"fine\"'; $x = 1")
    assert inner(wrapper).startswith("try { Write-Output 'it''s \"fine\"'; $x = 1 }")
    assert "fine" not in wrapper  # only base64 reaches the command line


async def test_block_adds_an_inbound_and_an_outbound_rule_in_the_snorty_group() -> None:
    runner = FakeRunner()
    await PowerShellFirewall(runner).block("8.8.4.4")
    (wrapper,) = runner.scripts
    script = inner(wrapper)
    assert script.count("New-NetFirewallRule") == 2
    assert "-Direction Inbound" in script and "-Direction Outbound" in script
    assert "-Group Snorty" in script and "-RemoteAddress 8.8.4.4" in script
    assert "-Action Block" in script


async def test_unblock_removes_the_rules_by_name_in_one_elevated_call() -> None:
    runner = FakeRunner()
    await PowerShellFirewall(runner).unblock("8.8.4.4", "8.8.8.4")
    (wrapper,) = runner.scripts
    script = inner(wrapper)
    assert "Remove-NetFirewallRule -DisplayName 'Snorty block 8.8.4.4'" in script
    assert "Remove-NetFirewallRule -DisplayName 'Snorty block 8.8.8.4'" in script


async def test_unblock_of_nothing_asks_for_nothing() -> None:
    runner = FakeRunner()
    await PowerShellFirewall(runner).unblock()
    assert runner.scripts == []


@pytest.mark.parametrize("bad", ["8.8.8.8; calc", "$(calc)", "8.8.8.8' -Foo '", "", "any"])
async def test_only_a_real_address_reaches_the_command_line(bad: str) -> None:
    runner = FakeRunner()
    fw = PowerShellFirewall(runner)
    with pytest.raises(FirewallError):
        await fw.block(bad)
    with pytest.raises(FirewallError):
        await fw.unblock(bad)
    assert runner.scripts == []


async def test_an_address_is_written_in_canonical_form() -> None:
    runner = FakeRunner()
    await PowerShellFirewall(runner).block("2001:0DB8:0:0:0:0:0:1")
    assert "-RemoteAddress 2001:db8::1" in inner(runner.scripts[0])


@pytest.mark.parametrize(
    "stderr",
    [
        "Start-Process : This command cannot be run due to the error: "
        "The operation was canceled by the user.",
        "New-NetFirewallRule : Access is denied.",
    ],
)
async def test_a_declined_prompt_or_denied_access_becomes_needs_admin(stderr: str) -> None:
    runner = FakeRunner(RunResult(1, "", stderr))
    with pytest.raises(NeedsAdmin, match="approval"):
        await PowerShellFirewall(runner).block("8.8.4.4")


async def test_other_failures_carry_the_first_line() -> None:
    runner = FakeRunner(RunResult(1, "", "something broke\nsecond line"))
    with pytest.raises(FirewallError, match="something broke") as info:
        await PowerShellFirewall(runner).block("8.8.4.4")
    assert not isinstance(info.value, NeedsAdmin)


async def test_blocked_and_protected_keep_single_addresses_only() -> None:
    out = "8.8.4.4\r\n1.2.3.0/24\r\nAny\r\n8.8.8.4\r\n8.8.4.4\r\n"
    fw = PowerShellFirewall(FakeRunner(RunResult(0, out, "")))
    assert await fw.blocked() == ["8.8.4.4", "8.8.8.4"]
    assert await fw.protected() == frozenset({"8.8.4.4", "8.8.8.4"})


def test_a_scope_id_is_rejected_before_any_script_is_built() -> None:
    from snorty.winfw.firewall import block_script, unblock_script

    for bad in ("2606:4700::1%x';Start-Process calc;'", "fe80::1%eth0"):
        with pytest.raises(FirewallError):
            block_script(bad)
        with pytest.raises(FirewallError):
            unblock_script(bad)
