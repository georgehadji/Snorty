"""Windows Firewall through PowerShell. Every rule is in the `Snorty` group, so Snorty can list
and remove exactly its own rules and nothing else.

Snorty itself runs unelevated: the engine stalls when the dashboard is elevated. Reading rules
works unelevated. Each write runs in a short-lived elevated PowerShell, so Windows shows its
permission prompt (UAC) and the user approves every change. Declining it is `NeedsAdmin`."""

import base64
import ipaddress
from collections.abc import Sequence

from snorty.respond.ports import FirewallError, NeedsAdmin
from snorty.snort.models import SnortError
from snorty.snort.runner import Runner

GROUP = "Snorty"
_DENIED = ("access is denied", "requires elevation", "canceled by the user")
_APPROVAL = "blocking needs your approval: accept the Windows permission prompt"
WRITE_TIMEOUT = 120.0  # the user has to find and click the permission prompt


def elevated(script: str) -> str:
    """`script` wrapped so a hidden, elevated PowerShell runs it; the exit code comes back.
    The inner script travels base64-encoded, so no quoting can change what it says."""
    inner = f"try {{ {script} }} catch {{ exit 1 }}"
    encoded = base64.b64encode(inner.encode("utf-16-le")).decode("ascii")
    return (
        "$ErrorActionPreference='Stop'; "
        "$p = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -WindowStyle Hidden "
        f"-ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand','{encoded}'; "
        "exit $p.ExitCode"
    )


def _clean(ip: str) -> str:
    """The address in canonical form. Anything else never reaches the PowerShell command line."""
    try:
        if "%" in ip:  # an IPv6 scope id would carry free text into the elevated script
            raise ValueError(ip)
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


def unblock_script(*ips: str) -> str:
    return "$ErrorActionPreference='Stop'; " + "; ".join(
        f"Remove-NetFirewallRule -DisplayName '{_name(_clean(ip))}' -ErrorAction SilentlyContinue"
        for ip in ips
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

    async def _run(self, script: str, *, write: bool = False) -> str:
        if write:
            script = elevated(script)
        argv = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script]
        try:
            result = await self._runner(argv, timeout=WRITE_TIMEOUT if write else self._timeout)
        except SnortError as exc:
            raise FirewallError(str(exc)) from exc
        if result.returncode != 0:
            text = f"{result.stderr}\n{result.stdout}".strip()
            if any(marker in text.lower() for marker in _DENIED):
                raise NeedsAdmin(_APPROVAL)
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
        await self._run(block_script(ip), write=True)

    async def unblock(self, *ips: str) -> None:
        """Remove the rules of every address in one go: one permission prompt, not one each."""
        if ips:
            await self._run(unblock_script(*ips), write=True)

    async def blocked(self) -> Sequence[str]:
        """Single addresses that Snorty's rules block now."""
        return sorted(set(self._addresses(await self._run(LIST_SCRIPT))))

    async def protected(self) -> frozenset[str]:
        return frozenset(self._addresses(await self._run(PROTECTED_SCRIPT)))
