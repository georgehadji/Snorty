"""Command lines for the Wireshark tools, as lists (never a shell string)."""

from pathlib import Path


def decode_command(tshark: Path, pcap: Path, limit: int) -> list[str]:
    # -n: no name lookups (they would send what you inspect to DNS); -c: packet cap;
    # -x: include the raw bytes so the view can show a hex dump.
    return [str(tshark), "-r", str(pcap), "-n", "-c", str(limit), "-T", "json", "-x"]


def summary_command(tshark: Path, pcap: Path) -> list[str]:
    # -q: statistics only, no packet lines; one pass over the file gives all five tables.
    zs = ("io,phs", "conv,ip", "conv,ipv6", "conv,tcp", "conv,udp")
    return [str(tshark), "-r", str(pcap), "-n", "-q", *(a for z in zs for a in ("-z", z))]
