"""Windows Firewall through PowerShell. Every rule is in the `Snorty` group, so Snorty can list
and remove exactly its own rules and nothing else.

Snorty runs unelevated and never raises its own rights. Reading rules works unelevated, writing
them does not, so a refused write is reported as `NeedsAdmin` and the user decides what to do."""

import ipaddress
from collections.abc import Sequence

from snorty.respond.ports import FirewallError, NeedsAdmin
from snorty.snort.models import SnortError
from snorty.snort.runner import Runner

GROUP = "Snorty"
_DENIED = ("access is denied", "requires elevation", "administrator", "0x5")


def _clean(ip: str) -> str:
    """The address in canonical form. Anything else never reaches the PowerShell command line."""
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError as exc:
        raise FirewallError(f"not an IP address: {ip[:45]!r}") from exc


def _name(ip: str) -> str:
    return f"Snorty block {ip}"


def block_script(ip: str) -> str:
    ip = _clean(ip)
    base = f"-DisplayName '{_name(ip)}' -Group {GROUP} -Action Block -RemoteAddress {ip}"
    return (
        "$ErrorActionPreference='Stop'; "
        f"New-NetFirewallRule {base} -Direction Inbound | Out-Null; "
        f"New-NetFirewallRule {base} -Direction Outbound | Out-Null"
    )


def unblock_script(ip: str) -> str:
    return (
        "$ErrorActionPreference='Stop'; "
        f"Remove-NetFirewallRule -DisplayName '{_name(_clean(ip))}' -ErrorAction SilentlyContinue"
    )


LIST_SCRIPT = (
    "$ErrorActionPreference='Stop'; "
    f"(Get-NetFirewallRule -Group {GROUP} -ErrorAction SilentlyContinue "
    "| Get-NetFirewallAddressFilter).RemoteAddress | Sort-Object -Unique"
)
# The gateway and DNS servers of every adapter: blocking one would cut the PC off.
PROTECTED_SCRIPT = (
    "$ErrorActionPreference='Stop'; Get-NetIPConfiguration | ForEach-Object { "
    "$_.IPv4DefaultGateway.NextHop; $_.IPv6DefaultGateway.NextHop; $_.DNSServer.ServerAddresses }"
)


class PowerShellFirewall:
    def __init__(self, runner: Runner, *, timeout: float = 30.0) -> None:
        self._runner = runner
        self._timeout = timeout

    async def _run(self, script: str) -> str:
        argv = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script]
        try:
            result = await self._runner(argv, timeout=self._timeout)
        except SnortError as exc:
            raise FirewallError(str(exc)) from exc
        if result.returncode != 0:
            text = f"{result.stderr}\n{result.stdout}".strip()
            if any(marker in text.lower() for marker in _DENIED):
                raise NeedsAdmin("blocking needs an administrator: start Snorty as administrator")
            raise FirewallError(text.splitlines()[0][:200] if text else "firewall command failed")
        return result.stdout

    @staticmethod
    def _addresses(text: str) -> list[str]:
        found: list[str] = []
        for line in text.split():
            try:
                found.append(str(ipaddress.ip_address(line.strip())))
            except ValueError:  # ranges, "Any" and blanks are not single addresses
                continue
        return found

    async def block(self, ip: str) -> None:
        await self._run(block_script(ip))

    async def unblock(self, ip: str) -> None:
        await self._run(unblock_script(ip))

    async def blocked(self) -> Sequence[str]:
        """Single addresses that Snorty's rules block now."""
        return sorted(set(self._addresses(await self._run(LIST_SCRIPT))))

    async def protected(self) -> frozenset[str]:
        return frozenset(self._addresses(await self._run(PROTECTED_SCRIPT)))
