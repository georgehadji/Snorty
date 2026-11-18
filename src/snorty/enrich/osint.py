"""Two pulled feeds, no account and no MISP server: CIRCL's MISP OSINT feed and the CERT Polska
warning list. Nothing from an alert is ever sent anywhere; the whole feed is downloaded and
looked up here.

CIRCL's `hashes.csv` holds `md5(value),event-uuid` for every value in every OSINT report, with no
type: a match says the value was *mentioned* in a public report (8.8.8.8 is, in several), not that
it is bad. So it is a neutral note. CERT Polska lists phishing domains, which are bad."""

import hashlib
import json
from array import array
from bisect import bisect_left
from collections.abc import Iterable

DIGEST = 16  # bytes in an md5
SHARED = {"tlp:white", "tlp:clear"}  # only reports marked shareable with anyone are used
INFO_CHARS = 120


class Digests:
    """The sorted digests as a sequence of 16-byte slices, for bisect."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def __len__(self) -> int:
        return len(self._data) // DIGEST

    def __getitem__(self, i: int) -> bytes:
        return self._data[i * DIGEST : (i + 1) * DIGEST]


class OsintIndex:
    """Which CIRCL OSINT reports mention a value. About 18 bytes per value in memory."""

    def __init__(
        self,
        digests: bytes = b"",
        events: Iterable[int] = (),
        reports: Iterable[tuple[str, str]] = (),
    ) -> None:
        self._digests = Digests(digests)
        self._events = array("H", events)  # report index of each digest
        self._reports = list(reports)  # (date, title)

    def __len__(self) -> int:
        return len(self._digests)

    @classmethod
    def parse(cls, manifest: str, hashes: Iterable[str]) -> "OsintIndex":
        """The feed's `manifest.json` text and `hashes.csv` lines; anything broken is skipped."""
        try:
            events = json.loads(manifest) if manifest else {}
        except ValueError:
            return cls()
        index: dict[str, int] = {}
        reports: list[tuple[str, str]] = []
        for uuid, event in events.items() if isinstance(events, dict) else ():
            if not isinstance(event, dict) or len(reports) >= 65535:  # fits array("H")
                continue
            tags = {t.get("name") for t in event.get("Tag") or () if isinstance(t, dict)}
            if tags & SHARED:
                index[uuid] = len(reports)
                title = " ".join(str(event.get("info") or "untitled").split())[:INFO_CHARS]
                reports.append((str(event.get("date") or ""), title))
        rows: list[tuple[bytes, int]] = []
        for line in hashes:
            digest, _, uuid = line.strip().partition(",")
            n = index.get(uuid)
            if n is None or len(digest) != 2 * DIGEST:
                continue
            try:
                rows.append((bytes.fromhex(digest), n))
            except ValueError:
                continue
        rows.sort()
        return cls(b"".join(d for d, _ in rows), (n for _, n in rows), reports)

    def find(self, value: str) -> str | None:
        """A note naming how many reports mention `value` and the newest, or None."""
        key = hashlib.md5(value.encode(), usedforsecurity=False).digest()
        i = bisect_left(self._digests, key)
        found: set[int] = set()
        while i < len(self._digests) and self._digests[i] == key:
            found.add(self._events[i])
            i += 1
        if not found:
            return None
        date, title = max(self._reports[n] for n in found)
        count = "1 report" if len(found) == 1 else f"{len(found)} reports"
        return f"{value} is mentioned in {count}; newest: {title} ({date})"


class DomainList:
    """A list of domains; a name matches when it or a parent domain is listed."""

    def __init__(self, domains: Iterable[str] = (), label: str = "") -> None:
        self._domains = {d.strip().lower().rstrip(".") for d in domains} - {""}
        self._label = label

    def __len__(self) -> int:
        return len(self._domains)

    def find(self, name: str) -> str | None:
        parts = name.strip().lower().rstrip(".").split(".")
        for i in range(len(parts) - 1):  # never the bare top-level domain
            domain = ".".join(parts[i:])
            if domain in self._domains:
                return f"{self._label}: {domain}"
        return None


def parse_cert_pl(text: str) -> DomainList:
    """CERT Polska's warning list: one domain per line."""
    return DomainList(
        (ln for ln in text.splitlines() if ln.strip() and not ln.startswith("#")),
        "CERT Polska phishing warning list",
    )
