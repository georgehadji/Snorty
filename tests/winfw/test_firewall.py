from collections.abc import Sequence

import pytest

from snorty.respond.ports import FirewallError, NeedsAdmin
from snorty.snort.models import RunResult
from snorty.winfw import PowerShellFirewall


class FakeRunner:
    def __init__(self, result: RunResult | None = None) -> None:
        self.result = result or RunResult(0, "", "")
        self.scripts: list[str] = []

    async def __call__(self, argv: Sequence[str], *, timeout: float) -> RunResult:
        assert argv[0] == "powershell.exe" and "-NonInteractive" in argv
        self.scripts.append(argv[-1])
        return self.result


async def test_block_adds_an_inbound_and_an_outbound_rule_in_the_snorty_group() -> None:
    runner = FakeRunner()
    await PowerShellFirewall(runner).block("8.8.4.4")
    (script,) = runner.scripts
    assert script.count("New-NetFirewallRule") == 2
    assert "-Direction Inbound" in script and "-Direction Outbound" in script
    assert "-Group Snorty" in script and "-RemoteAddress 8.8.4.4" in script
    assert "-Action Block" in script


async def test_unblock_removes_the_rules_by_name() -> None:
    runner = FakeRunner()
    await PowerShellFirewall(runner).unblock("8.8.4.4")
    assert "Remove-NetFirewallRule -DisplayName 'Snorty block 8.8.4.4'" in runner.scripts[0]


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
    assert "-RemoteAddress 2001:db8::1" in runner.scripts[0]


async def test_access_denied_becomes_needs_admin() -> None:
    runner = FakeRunner(RunResult(1, "", "New-NetFirewallRule : Access is denied."))
    with pytest.raises(NeedsAdmin, match="administrator"):
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
