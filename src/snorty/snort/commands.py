"""Pure builders for Snort command lines. Always argv lists, never shell strings."""

from pathlib import Path

from snorty.snort.models import Interface, SnortPaths


def interfaces_command(paths: SnortPaths) -> list[str]:
    return [str(paths.exe), "-W"]


def tasklist_command(pid: int) -> list[str]:
    return ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"]


def taskkill_command(pid: int) -> list[str]:
    return ["taskkill", "/PID", str(pid), "/T", "/F"]


def check_command(paths: SnortPaths, iface: Interface, *, conf: Path | None = None) -> list[str]:
    # -T fails without -i on this Snort build ("Active response: can't open ip!").
    return [str(paths.exe), "-T", "-i", str(iface.index), "-c", str(conf or paths.conf)]


def live_command(paths: SnortPaths, iface: Interface) -> list[str]:
    return [
        str(paths.exe), "-c", str(paths.conf), "-i", str(iface.index),
        "-l", str(paths.log_dir), "-A", "fast", "-y",
    ]  # fmt: skip


def pcap_command(
    paths: SnortPaths, pcap: Path, *, conf: Path | None = None, log_dir: Path | None = None
) -> list[str]:
    # -k none: hand-made and captured pcaps often carry bad checksums; do not drop them.
    return [
        str(paths.exe), "-r", str(pcap), "-c", str(conf or paths.conf),
        "-l", str(log_dir or paths.log_dir), "-A", "fast", "-y", "-k", "none", "-q",
    ]  # fmt: skip
