"""Address ranges with a label each, looked up by bisection: country and network owner tables and
the known-bad lists all use this one structure."""

import csv
import ipaddress
from array import array
from bisect import bisect_right
from collections.abc import Iterable, Iterator


class _Packed:
    """Fixed-width big-endian addresses in one buffer, read as a sequence of bytes. Bytes of one
    width compare in the same order as the numbers, so `bisect` works on it directly."""

    def __init__(self, width: int) -> None:
        self.data = bytearray()
        self.width = width

    def __len__(self) -> int:
        return len(self.data) // self.width

    def __getitem__(self, i: int) -> bytes:
        return bytes(self.data[i * self.width : (i + 1) * self.width])


class _Family:
    """One address family's rows as three columns: a row costs 2 addresses and a label number
    instead of a tuple of Python ints and a string (a full DB-IP load went from about 325 MB to
    about 30 MB)."""

    def __init__(self, width: int) -> None:
        self.starts = _Packed(width)
        self.ends = _Packed(width)
        self.labels = array("I")
        self.ordered = True
        self._last: tuple[bytes, bytes, str] | None = None

    def add(self, start: bytes, end: bytes, label: int, names: list[str]) -> None:
        key = (start, end, names[label])
        if self._last is not None and key < self._last:
            self.ordered = False
        self._last = key
        self.starts.data += start
        self.ends.data += end
        self.labels.append(label)

    def sort(self, names: list[str]) -> None:
        """Only for input that was not already in order (the downloaded lists are): by start, then
        end, then label, as the sorted tuples were."""
        if self.ordered:
            return
        starts, ends, labels = self.starts, self.ends, self.labels
        order = sorted(range(len(labels)), key=lambda i: (starts[i], ends[i], names[labels[i]]))
        self.starts, self.ends = _Packed(starts.width), _Packed(ends.width)
        self.starts.data = bytearray(b"".join(starts[i] for i in order))
        self.ends.data = bytearray(b"".join(ends[i] for i in order))
        self.labels = array("I", (labels[i] for i in order))
        self.ordered = True


class RangeTable:
    """Sorted, non-overlapping ranges. shortcut: where ranges do overlap, a lookup may miss the
    wider one; the sources used here (DB-IP, DROP, Feodo) do not overlap."""

    def __init__(self, spans: Iterable[tuple[int, int, int, str]] = ()) -> None:
        self._names: list[str] = []  # each distinct label once; rows hold its index
        self._families = {4: _Family(4), 6: _Family(16)}
        ids: dict[str, int] = {}
        for version, start, end, label in spans:
            family = self._families[version]
            if label not in ids:
                ids[label] = len(self._names)
                self._names.append(label)
            width = family.starts.width
            family.add(start.to_bytes(width), end.to_bytes(width), ids[label], self._names)
        for family in self._families.values():
            family.sort(self._names)

    def __len__(self) -> int:
        return sum(len(f.labels) for f in self._families.values())

    def find(self, address: str) -> str | None:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return None
        family, key = self._families[ip.version], ip.packed
        i = bisect_right(family.starts, key) - 1
        if i < 0 or key > family.ends[i]:
            return None
        return self._names[family.labels[i]]

    @classmethod
    def from_networks(cls, items: Iterable[tuple[str, str]]) -> "RangeTable":
        """(network or address, label) pairs; lines that are not valid are skipped."""

        def spans() -> Iterator[tuple[int, int, int, str]]:
            for text, label in items:
                try:
                    net = ipaddress.ip_network(text.strip(), strict=False)
                except ValueError:
                    continue
                yield net.version, int(net.network_address), int(net.broadcast_address), label

        return cls(spans())

    @classmethod
    def from_csv(cls, lines: Iterable[str], label_columns: slice) -> "RangeTable":
        """DB-IP rows: first address, last address, then the columns joined into the label."""

        def spans() -> Iterator[tuple[int, int, int, str]]:
            for row in csv.reader(lines):
                try:
                    first, last = ipaddress.ip_address(row[0]), ipaddress.ip_address(row[1])
                except (ValueError, IndexError):
                    continue
                label = " ".join(row[2:][label_columns]).strip()
                yield first.version, int(first), int(last), label

        return cls(spans())


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
