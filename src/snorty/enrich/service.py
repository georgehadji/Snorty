"""Adds what public data says about an alert's remote address, and flags known-bad ones."""

import asyncio
import ipaddress
import logging
import os
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from snorty.core.bus import EventBus, Subscription
from snorty.core.events import AlertFlagged, AlertRaised, Event
from snorty.core.models import Alert
from snorty.core.repository import AlertRepository
from snorty.enrich.fetch import Fetch, gunzip
from snorty.enrich.osint import DomainList, OsintIndex, parse_cert_pl
from snorty.enrich.ranges import RangeTable, parse_drop, parse_feodo
from snorty.enrich.rdns import ReverseDns

log = logging.getLogger("snorty.enrich")

DAY = 86400.0
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
CIRCL_FEED = "https://www.circl.lu/doc/misp/feed-osint/"  # manifest.json 1.4 MB, hashes.csv 42 MB
CERT_PL_URL = "https://hole.cert.pl/domains/v2/domains.txt"  # 2.6 MB
NAMED_FACTS = ("dns", "tls", "http")  # flow facts that carry a host name


def remote_address(alert: Alert) -> str | None:
    """The end of the flow that is not on this network, or None when both ends are private."""
    for text in (alert.src_ip, alert.dst_ip):
        try:
            if ipaddress.ip_address(text).is_global:
                return text
        except ValueError:
            continue
    return None


def flow_names(facts: list[tuple[str, str]]) -> list[str]:
    """The host names among an alert's flow facts (a web request's host, without its path)."""
    names = (v.split("/", 1)[0] for k, v in facts if k in NAMED_FACTS)
    return list(dict.fromkeys(n.lower().rstrip(".") for n in names if n))


class EnrichService:
    """Pipeline: each step reads the loaded tables and adds a `kind: value` note. The tables come
    from files in `folder`; with a `fetch` they are refreshed (lists daily, DB-IP monthly, the
    CIRCL OSINT feed weekly), and without one only the files already there are used. The remote
    address and, for Suricata, the host names seen on the alert's flow are what is looked up."""

    def __init__(
        self,
        bus: EventBus,
        repo: AlertRepository,
        folder: Path,
        *,
        fetch: Fetch | None = None,
        rdns: ReverseDns | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._bus = bus
        self._repo = repo
        self._folder = folder
        self._fetch = fetch
        self._rdns = rdns
        self._now = now
        self._clock = clock
        self._bad: list[RangeTable] = []
        self._country = RangeTable()
        self._asn = RangeTable()
        self._osint = OsintIndex()
        self._phishing = DomainList()
        self._sub: Subscription | None = None
        self._tasks: list[asyncio.Task[None]] = []

    # --- life cycle -------------------------------------------------------------------

    async def start(self) -> None:
        if self._tasks:
            return
        await asyncio.to_thread(self.load)
        self._sub = self._bus.subscribe(maxsize=500, accept=_wants, keep_oldest=True)
        self._tasks = [
            asyncio.create_task(self._consume(self._sub), name="enrich"),
            asyncio.create_task(self._refresh_loop(), name="enrich-refresh"),
        ]

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        if self._sub is not None:
            self._sub.close()
        self._tasks, self._sub = [], None

    async def _consume(self, sub: Subscription) -> None:
        async for event in sub:
            if not isinstance(event, AlertRaised):
                continue
            try:
                notes = await asyncio.to_thread(self.enrich, event.alert)
            except Exception:  # one bad alert must not end the consumer
                log.exception("could not enrich alert %s", event.alert.id)
                continue
            if "bad" in notes:
                self._bus.publish(AlertFlagged(event.alert, notes["bad"]))

    async def _refresh_loop(self) -> None:
        while self._fetch is not None:
            try:
                if await asyncio.to_thread(self.refresh):
                    await asyncio.to_thread(self.load)
            except Exception:  # offline or a changed address: try again tomorrow
                log.exception("could not refresh the enrichment data")
            await asyncio.sleep(DAY)

    # --- the pipeline -----------------------------------------------------------------

    def enrich(self, alert: Alert) -> dict[str, str]:
        """Blocking: store and return the notes for `alert` (empty when it has neither a public
        address nor a host name)."""
        ip = remote_address(alert)
        flow = alert.flow_id
        names = flow_names(self._repo.flow_facts(flow)) if flow is not None else []
        if (ip is None and not names) or not alert.id:
            return {}

        def first(values: list[str], find: Callable[[str], str | None]) -> str | None:
            return next((m for v in values if (m := find(v))), None)

        def bad_ip(a: str) -> str | None:
            return next((m for t in self._bad if (m := t.find(a))), None)

        ips = [ip] if ip else []
        rdns = self._rdns.name if self._rdns else (lambda _: None)
        steps: list[tuple[str, Callable[[], str | None]]] = [
            ("bad", lambda: first(ips, bad_ip) or first(names, self._phishing.find)),
            ("osint", lambda: first(ips + names, self._osint.find)),  # a mention, not a verdict
            ("country", lambda: first(ips, self._country.find)),
            ("asn", lambda: first(ips, self._asn.find)),
            ("rdns", lambda: first(ips, rdns)),
        ]
        notes: dict[str, str] = {}
        for kind, step in steps:
            value = step()
            if value:
                notes[kind] = value
                self._repo.annotate(alert.id, kind, value)
        if "country" in notes:
            self._repo.note_seen("country", [notes["country"]], alert.ts)
        return notes

    # --- data -------------------------------------------------------------------------

    def load(self) -> None:
        """Read the tables from the files in the folder; a missing or broken file is skipped."""

        def read(name: str) -> str:
            try:
                return (self._folder / name).read_text(encoding="utf-8", errors="replace")
            except OSError:
                return ""

        self._bad = [parse_feodo(read("feodo.txt")), parse_drop(read("drop.txt"))]
        self._country = RangeTable.from_csv(read("dbip-country.csv").splitlines(), slice(0, 1))
        self._asn = RangeTable.from_csv(read("dbip-asn.csv").splitlines(), slice(0, 2))
        self._osint = OsintIndex.parse(
            read("circl-manifest.json"), read("circl-hashes.csv").splitlines()
        )
        self._phishing = parse_cert_pl(read("cert-pl-domains.txt"))

    def refresh(self) -> bool:
        """Download whatever is out of date; True if any file changed."""
        month = self._now().strftime("%Y-%m")
        base = "https://download.db-ip.com/free/dbip-"
        sources = [
            ("feodo.txt", FEODO_URL, DAY, False),
            ("drop.txt", DROP_URL, DAY, False),
            ("dbip-country.csv", f"{base}country-lite-{month}.csv.gz", 30 * DAY, True),
            ("dbip-asn.csv", f"{base}asn-lite-{month}.csv.gz", 30 * DAY, True),
            ("cert-pl-domains.txt", CERT_PL_URL, DAY, False),
            ("circl-manifest.json", f"{CIRCL_FEED}manifest.json", 7 * DAY, False),
            ("circl-hashes.csv", f"{CIRCL_FEED}hashes.csv", 7 * DAY, False),
        ]
        changed = False
        self._folder.mkdir(parents=True, exist_ok=True)
        for name, url, max_age, packed in sources:
            target = self._folder / name
            if target.exists() and self._clock() - target.stat().st_mtime < max_age:
                continue
            try:
                assert self._fetch is not None
                data = self._fetch(url)
                if packed:
                    data = gunzip(data)
            except OSError:
                log.warning("could not download %s", url)
                continue
            part = target.with_suffix(target.suffix + ".part")
            part.write_bytes(data)
            os.replace(part, target)  # a half-written file is never read
            changed = True
        return changed


def _wants(event: Event) -> bool:
    return isinstance(event, AlertRaised)
