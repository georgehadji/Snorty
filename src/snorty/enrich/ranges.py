"""Address ranges with a label each, looked up by bisection: country and network owner tables and
the known-bad lists all use this one structure."""

import csv
import ipaddress
from bisect import bisect_right
from collections.abc import Iterable
from typing import NamedTuple


class _Span(NamedTuple):
    version: int
    start: int
    end: int
    label: str


class RangeTable:
    """Sorted, non-overlapping ranges. shortcut: where ranges do overlap, a lookup may miss the
    wider one; the sources used here (DB-IP, DROP, Feodo) do not overlap."""

    def __init__(self, spans: Iterable[tuple[int, int, int, str]] = ()) -> None:
        self._spans = sorted(_Span(*s) for s in spans)
        self._keys = [(s.version, s.start) for s in self._spans]

    def __len__(self) -> int:
        return len(self._spans)

    def find(self, address: str) -> str | None:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return None
        i = bisect_right(self._keys, (ip.version, int(ip))) - 1
        if i < 0:
            return None
        span = self._spans[i]
        return span.label if span.version == ip.version and int(ip) <= span.end else None

    @classmethod
    def from_networks(cls, items: Iterable[tuple[str, str]]) -> "RangeTable":
        """(network or address, label) pairs; lines that are not valid are skipped."""
        spans: list[tuple[int, int, int, str]] = []
        for text, label in items:
            try:
                net = ipaddress.ip_network(text.strip(), strict=False)
            except ValueError:
                continue
            spans.append((net.version, int(net.network_address), int(net.broadcast_address), label))
        return cls(spans)

    @classmethod
    def from_csv(cls, lines: Iterable[str], label_columns: slice) -> "RangeTable":
        """DB-IP rows: first address, last address, then the columns joined into the label."""
        spans: list[tuple[int, int, int, str]] = []
        for row in csv.reader(lines):
            try:
                first, last = ipaddress.ip_address(row[0]), ipaddress.ip_address(row[1])
            except (ValueError, IndexError):
                continue
            label = " ".join(row[2:][label_columns]).strip()
            spans.append((first.version, int(first), int(last), label))
        return cls(spans)


def parse_feodo(text: str) -> RangeTable:
    """Feodo Tracker's blocklist: one address per line, `#` comments."""
    lines = (ln.strip() for ln in text.splitlines())
    return RangeTable.from_networks(
        (ln, "Feodo Tracker botnet C2") for ln in lines if ln and not ln.startswith("#")
    )


def parse_drop(text: str) -> RangeTable:
    """Spamhaus DROP: `network ; SBLnnn`, `;` comments."""
    items: list[tuple[str, str]] = []
    for ln in text.splitlines():
        if not ln.strip() or ln.startswith(";"):
            continue
        net, _, ref = ln.partition(";")
        items.append((net, f"Spamhaus DROP {ref.strip()}".strip()))
    return RangeTable.from_networks(items)
