from pathlib import Path

from snorty.snort.commands import check_command, interfaces_command, live_command, pcap_command
from snorty.snort.models import Interface, SnortPaths

PATHS = SnortPaths(Path("C:/s/snort.exe"), Path("C:/s/snort.conf"), Path("C:/s/log"))
IFACE = Interface(4, "aa", "1.2.3.4", "dev", "desc")


def test_interfaces_command() -> None:
    assert interfaces_command(PATHS) == [str(PATHS.exe), "-W"]


def test_test_command_always_has_interface() -> None:
    assert check_command(PATHS, IFACE) == [str(PATHS.exe), "-T", "-i", "4", "-c", str(PATHS.conf)]


def test_test_command_conf_override() -> None:
    cmd = check_command(PATHS, IFACE, conf=Path("C:/x/other.conf"))
    assert cmd[-2:] == ["-c", str(Path("C:/x/other.conf"))]


def test_live_command() -> None:
    assert live_command(PATHS, IFACE) == [
        str(PATHS.exe), "-c", str(PATHS.conf), "-i", "4",
        "-l", str(PATHS.log_dir), "-A", "fast", "-y",
    ]  # fmt: skip


def test_pcap_command_defaults_and_overrides() -> None:
    pcap = Path("C:/t/a.pcap")
    assert pcap_command(PATHS, pcap) == [
        str(PATHS.exe), "-r", str(pcap), "-c", str(PATHS.conf), "-l", str(PATHS.log_dir),
        "-A", "fast", "-y", "-k", "none", "-q",
    ]  # fmt: skip
    cmd = pcap_command(PATHS, pcap, conf=Path("C:/lab/lab.conf"), log_dir=Path("C:/lab/log"))
    assert str(Path("C:/lab/lab.conf")) in cmd and str(Path("C:/lab/log")) in cmd


def test_all_items_are_strings() -> None:
    assert all(isinstance(a, str) for a in live_command(PATHS, IFACE))
