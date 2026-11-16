"""Command lines for the Wireshark tools, as lists (never a shell string)."""

from pathlib import Path


def decode_command(tshark: Path, pcap: Path, limit: int) -> list[str]:
    # -n: no name lookups (they would send what you inspect to DNS); -c: packet cap;
    # -x: include the raw bytes so the view can show a hex dump.
    return [str(tshark), "-r", str(pcap), "-n", "-c", str(limit), "-T", "json", "-x"]
