"""Parse tshark's text statistics (-z io,phs and -z conv,*) into a Summary.

Pure and bounded: the text comes from a tool that reads hostile files, so every list is capped
and lines that do not match are skipped, never trusted.
"""

import re

from snorty.packets.models import Conversation, ProtocolRow, Summary

MAX_PROTOCOLS = 60
MAX_PER_KIND = 50
MAX_NAME = 40
MAX_ADDR = 64

_KINDS = {
    "IPv4 Conversations": "IPv4",
    "IPv6 Conversations": "IPv6",
    "TCP Conversations": "TCP",
    "UDP Conversations": "UDP",
}
_PROTO = re.compile(r"^( *)(\S+)\s+frames:(\d+)\s+bytes:(\d+)\s*$")
_AMOUNT = r"[\d.,]+ \w+"  # "73 bytes", "31 kB"
_CONV = re.compile(
    rf"^(\S+)\s+<->\s+(\S+)\s+\d+\s+{_AMOUNT}\s+\d+\s+{_AMOUNT}\s+(\d+)\s+({_AMOUNT})"
    r"\s+[\d.]+\s+([\d.]+)\s*$"
)


def parse_summary(text: str) -> Summary:
    protocols: list[ProtocolRow] = []
    found: dict[str, list[Conversation]] = {kind: [] for kind in _KINDS.values()}
    kind = ""
    for line in text.splitlines():
        if line.strip() in _KINDS:
            kind = _KINDS[line.strip()]
        elif (m := _PROTO.match(line)) and len(protocols) < MAX_PROTOCOLS:
            indent, name, frames, size = m.groups()
            protocols.append(ProtocolRow(name[:MAX_NAME], len(indent) // 2, int(frames), int(size)))
        elif kind and (m := _CONV.match(line)):
            a, b, frames, size, duration = m.groups()
            found[kind].append(
                Conversation(kind, a[:MAX_ADDR], b[:MAX_ADDR], int(frames), size, duration)
            )
    busiest = (sorted(rows, key=lambda c: -c.frames)[:MAX_PER_KIND] for rows in found.values())
    return Summary(tuple(protocols), tuple(c for rows in busiest for c in rows))
