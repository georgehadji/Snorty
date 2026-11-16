"""Test doubles for the lab tests: a fake Snort that answers -W, -T and -r."""

from collections.abc import Sequence
from pathlib import Path

from snorty.snort.models import RunResult, SnortPaths

LOOPBACK = "\\Device\\NPF_Loopback"
INTERFACES = (
    "Index\tPhysical Address\tIP Address\tDevice Name\tDescription\n"
    "-----\t----------------\t----------\t-----------\t-----------\n"
    f"1\t00:11:22:33:44:55\t192.168.1.5\t\\Device\\NPF_{{ABC}}\tEthernet\n"
    f"2\t00:00:00:00:00:00\t127.0.0.1\t{LOOPBACK}\tLoopback\n"
)
OK_CHECK = "Snort successfully validated the configuration!\n"

LIVE_CONF = (
    "# live conf\r\n"
    "var RULE_PATH C:/Snort/rules\r\n"
    "include classification.config\r\n"
    "include $RULE_PATH/local.rules\r\n"
    "include $RULE_PATH/emerging-dns.rules\r\n"
    "preprocessor stream5_global: max_tcp 1\r\n"
    "include threshold.conf\r\n"
)


def alert_line(sid: int, msg: str = "lab rule", stamp: str = "11/15-23:30:13.875248") -> str:
    return (
        f"{stamp}  [**] [1:{sid}:1] {msg} [**] [Priority: 1] {{TCP}} 10.0.0.1:4444 -> 10.0.0.2:80"
    )


def rule(sid: int, msg: str = "lab rule") -> str:
    return f'alert tcp any any -> any 80 (msg:"{msg}"; content:"abc"; sid:{sid}; rev:1;)'


def make_paths(root: Path) -> SnortPaths:
    """A fake Snort install: etc/snort.conf with includes, rules/, log/."""
    (root / "etc").mkdir(parents=True)
    (root / "rules").mkdir()
    (root / "log").mkdir()
    conf = root / "etc" / "snort.conf"
    conf.write_bytes(LIVE_CONF.encode())
    (root / "etc" / "threshold.conf").write_text("suppress gen_id 1, sig_id 5\n")
    (root / "rules" / "local.rules").write_text("alert ip any any -> any any (sid:1;)\n")
    return SnortPaths(exe=root / "snort.exe", conf=conf, log_dir=root / "log")


class FakeSnort:
    """A Runner that pretends to be Snort. Records every call and what the config looked like."""

    def __init__(
        self,
        *,
        interfaces: str = INTERFACES,
        check_output: str = OK_CHECK,
        check_code: int = 0,
        alert_text: str = "",
        run_code: int = 0,
        run_stderr: str = "",
    ) -> None:
        self.interfaces = interfaces
        self.check_output = check_output
        self.check_code = check_code
        self.alert_text = alert_text
        self.run_code = run_code
        self.run_stderr = run_stderr
        self.calls: list[list[str]] = []
        self.conf_seen: list[str] = []  # the sandbox config's text at each -T / -r call
        self.conf_paths: list[Path] = []

    def _note_conf(self, argv: Sequence[str]) -> None:
        conf = Path(argv[list(argv).index("-c") + 1])
        self.conf_paths.append(conf)
        self.conf_seen.append(conf.read_bytes().decode())

    async def __call__(self, argv: Sequence[str], *, timeout: float) -> RunResult:
        argv = list(argv)
        self.calls.append(argv)
        if "-W" in argv:
            return RunResult(0, self.interfaces, "")
        if "-T" in argv:
            self._note_conf(argv)
            return RunResult(self.check_code, "", self.check_output)
        if "-r" in argv:
            self._note_conf(argv)
            log_dir = Path(argv[argv.index("-l") + 1])
            (log_dir / "alert.ids").write_text(self.alert_text)
            return RunResult(self.run_code, "", self.run_stderr)
        raise AssertionError(f"unexpected snort call: {argv}")

    def flags(self) -> list[str]:
        """Which kinds of call were made, in order: W, T, r."""
        return [("W" if "-W" in c else "T" if "-T" in c else "r") for c in self.calls]
