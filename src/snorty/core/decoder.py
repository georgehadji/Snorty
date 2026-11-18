"""Turning the lines an engine writes into alerts. Pure: no I/O, no clock of its own.

Snort's fast format has no year and no zone, so its decoder keeps a little state (the repeated hour
of a clock change). Suricata's EVE JSON carries a full timestamp with its offset and needs none.
"""

import json
import logging
import re
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import datetime, timedelta, tzinfo
from typing import Any, Protocol
from urllib.parse import unquote

from snorty.core.models import Alert, Anomaly, Conn, FactKind, FlowFact, Lookup
from snorty.core.parser import parse_line

log = logging.getLogger("snorty.core")


class AlertDecoder(Protocol):
    def decode(
        self, lines: Sequence[str], year: int, ties: Sequence[int], now: datetime
    ) -> tuple[list[Alert], int]:
        """Returns (alerts, number of lines that could not be read). `ties[i]` says which of
        several identical lines `lines[i]` is; the decoder may ignore it."""
        ...

    def reset(self) -> None:
        """The alert file was replaced: forget anything learned from the old one."""
        ...

    @property
    def drop_pct(self) -> float | None:
        """Packets the engine dropped so far, as a percentage, if its output says (else None)."""
        ...

    def take_flows(self) -> list[FlowFact]:
        """What was seen on the flows of the alerts decoded since the last call, then forgotten."""
        ...

    def take_names(self) -> list[str]:
        """DNS names answered since the last call (alert or not), then forgotten."""
        ...

    def take_context(self) -> tuple[list[Conn], list[Lookup]]:
        """Connections that ended and DNS answers seen since the last call (alert or not), then
        forgotten. They are the context shown around an alert."""
        ...

    def take_anomalies(self) -> list[Anomaly]:
        """Protocol anomalies the engine logged since the last call (alert or not), then
        forgotten."""
        ...


def _settle_fold(ts: datetime, last: float | None, second: bool) -> tuple[datetime, float, bool]:
    """Snort writes local wall time. When the clocks go back, that hour is written twice and both
    passes parse to the first. A time that steps back inside such an hour starts the second pass;
    its lines get fold=1 until a time outside the repeated hour shows up.
    `last` is the newest instant read so far. Returns the time, the new `last` and `second`."""
    if ts.utcoffset() == ts.replace(fold=1).utcoffset():
        second = False
    elif not second and last is not None and ts.timestamp() < last - 1:
        second = True
    if second:
        ts = ts.replace(fold=1)
    instant = ts.timestamp()
    return ts, instant if last is None else max(instant, last), second


class FastDecoder:
    """Snort's `alert_fast` lines."""

    def __init__(self, tz: tzinfo, drop_source: Callable[[], float | None] | None = None) -> None:
        self._tz = tz
        self._drop_source = drop_source
        self._last: float | None = None  # newest alert time read so far, for _settle_fold
        self._second = False  # reading the repeated hour of a clock change a second time

    @property
    def drop_pct(self) -> float | None:
        """Snort's fast alerts carry no drop statistics; its perfmonitor file does, if read."""
        return self._drop_source() if self._drop_source else None

    def reset(self) -> None:
        self._last, self._second = None, False

    def take_flows(self) -> list[FlowFact]:
        return []  # Snort's fast alerts say nothing about the flow

    def take_names(self) -> list[str]:
        return []  # nor about DNS

    def take_context(self) -> tuple[list[Conn], list[Lookup]]:
        return [], []  # nor about other connections

    def take_anomalies(self) -> list[Anomaly]:
        return []  # nor about protocol anomalies

    def decode(
        self, lines: Sequence[str], year: int, ties: Sequence[int], now: datetime
    ) -> tuple[list[Alert], int]:
        alerts: list[Alert] = []
        bad = 0
        last, second = self._last, self._second
        for i, text in enumerate(lines):
            alert = parse_line(text, default_year=year, tz=self._tz)
            if alert is not None and alert.ts > now + timedelta(days=1):
                # Snort writes no year: a December line read in January is from last year.
                alert = parse_line(text, default_year=year - 1, tz=self._tz)
            if alert is None:
                bad += 1
                log.warning("unparsed alert line: %.120s", text)
            else:
                ts, last, second = _settle_fold(alert.ts, last, second)
                alert = replace(alert, ts=ts)
                alerts.append(replace(alert, dup=ties[i]) if i < len(ties) else alert)
        self._last, self._second = last, second
        return alerts, bad


def _port(value: object) -> int | None:
    return value if isinstance(value, int) and 0 <= value <= 65535 else None


def _int(value: object, default: int) -> int | None:
    """`default` when absent, None when present but not a whole number."""
    if value is None:
        return default
    return value if isinstance(value, int) and not isinstance(value, bool) else None


_REMEMBERED = 4096  # how many addresses, flows and alerted flows an EveDecoder keeps in mind
_PER_FLOW = 6
_VALUE_CHARS = 200
_FINGERPRINT = {
    "ja3": re.compile(r"[0-9a-f]{32}"),
    "ja4": re.compile(r"[a-z0-9_]{1,64}"),
    "md5": re.compile(r"[0-9a-f]{32}"),
}


def _remember(table: "OrderedDict[Any, Any]", key: object, value: object) -> None:
    table[key] = value
    table.move_to_end(key)
    if len(table) > _REMEMBERED:
        table.popitem(last=False)


def _text(value: object) -> str | None:
    """`value` as short, printable text, or None. It comes off the network."""
    if not isinstance(value, str):
        return None
    cleaned = "".join(ch for ch in value if ch.isprintable())[:_VALUE_CHARS].strip()
    return cleaned or None


def _file_name(info: dict[str, object], data: dict[str, object]) -> object:
    """The file's name. Suricata writes a downloaded file's name as its decoded URL path with
    each character it cannot map in one byte as "?" (Greek "Ημερήσιες" as "??e??s?e?"); the
    event's own percent-encoded URL still has the real name, so it is decoded from there when
    it lines up character for character. A name from a Content-Disposition header differs in
    length and is kept as written."""
    name, http = info.get("filename"), data.get("http")
    if isinstance(name, str) and "?" in name and isinstance(http, dict):
        url = http.get("url")
        if isinstance(url, str):
            path = unquote(url.split("?")[0], errors="replace")
            if len(path) == len(name):
                return path
    return name


def _stamp(value: object) -> datetime | None:
    """An EVE timestamp, or None when it is missing, broken or has no offset."""
    if not isinstance(value, str):
        return None
    try:
        ts = datetime.fromisoformat(value)
    except ValueError:
        return None
    return ts if ts.tzinfo is not None else None


def _dns_name(value: str) -> str:
    return value.lower().rstrip(".")


def _asked(info: dict[str, object]) -> str | None:
    """The name a DNS answer was for: `rrname` (EVE dns v2) or the first query (v3)."""
    queries = info.get("queries")
    first = queries[0] if isinstance(queries, list) and queries else None
    name = _text(info.get("rrname")) or _text(
        first.get("rrname") if isinstance(first, dict) else None
    )
    return _dns_name(name) if name else None


def _count(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _conn(data: dict[str, object]) -> Conn | None:
    """A `flow` event as a Conn, or None when it lacks what places it."""
    info, flow = data.get("flow"), data.get("flow_id")
    src, dst = _text(data.get("src_ip")), _text(data.get("dest_ip"))
    if not isinstance(info, dict) or type(flow) is not int or not src or not dst:
        return None
    start, end = _stamp(info.get("start")), _stamp(info.get("end"))
    if start is None or end is None:
        return None
    return Conn(
        flow_id=flow,
        start=start,
        end=end,
        proto=_text(data.get("proto")) or "",
        app_proto=_text(data.get("app_proto")),
        src_ip=src,
        src_port=_port(data.get("src_port")),
        dst_ip=dst,
        dst_port=_port(data.get("dest_port")),
        pkts_out=_count(info.get("pkts_toserver")),
        pkts_in=_count(info.get("pkts_toclient")),
        bytes_out=_count(info.get("bytes_toserver")),
        bytes_in=_count(info.get("bytes_toclient")),
        state=_text(info.get("state")),
    )


def _anomaly(data: dict[str, object]) -> Anomaly | None:
    """Suricata's `anomaly` event, or None when it lacks its time, ends or event name."""
    info, ts = data.get("anomaly"), _stamp(data.get("timestamp"))
    src, dst = _text(data.get("src_ip")), _text(data.get("dest_ip"))
    if not isinstance(info, dict) or ts is None or not src or not dst:
        return None
    kind, event = _text(info.get("type")), _text(info.get("event"))
    if not kind or not event:
        return None
    flow = data.get("flow_id")
    return Anomaly(
        ts=ts,
        flow_id=flow if type(flow) is int else None,
        kind=kind,
        event=event,
        app_proto=_text(info.get("app_proto")),
        src_ip=src,
        dst_ip=dst,
        dst_port=_port(data.get("dest_port")),
        proto=_text(data.get("proto")) or "",
    )


class EveDecoder:
    """Suricata's EVE JSON, one object per line. Only `alert` events become alerts. TLS, HTTP,
    file and anomaly events and DNS answers are not alerts, but what they say about an alert's
    flow is kept for its detail (`take_flows`); a stats event feeds `drop_pct`. Every ended flow
    and DNS answer is also kept as context (`take_context`), and every anomaly
    (`take_anomalies`). Everything else is skipped without counting as a failure."""

    def __init__(self) -> None:
        self.drop_pct: float | None = None
        self._names: OrderedDict[str, str] = OrderedDict()  # address -> name looked up for it
        self._pending: OrderedDict[int, list[FlowFact]] = OrderedDict()  # flows with no alert yet
        self._alerted: OrderedDict[int, None] = OrderedDict()
        self._out: list[FlowFact] = []
        self._answered: dict[str, None] = {}  # DNS names answered since take_names, in order
        self._conns: list[Conn] = []  # since take_context; one decode call's worth at most
        self._lookups: list[Lookup] = []
        self._anomalies: list[Anomaly] = []  # since take_anomalies, one decode call's worth

    def reset(self) -> None:
        self.drop_pct = None
        self._names.clear()
        self._pending.clear()
        self._alerted.clear()
        self._out.clear()
        self._answered.clear()
        self._conns.clear()
        self._lookups.clear()
        self._anomalies.clear()

    def take_flows(self) -> list[FlowFact]:
        out, self._out = self._out, []
        return out

    def take_names(self) -> list[str]:
        out, self._answered = list(self._answered), {}
        return out

    def take_anomalies(self) -> list[Anomaly]:
        out, self._anomalies = self._anomalies, []
        return out

    def take_context(self) -> tuple[list[Conn], list[Lookup]]:
        out = self._conns, self._lookups
        self._conns, self._lookups = [], []
        return out

    def decode(
        self, lines: Sequence[str], year: int, ties: Sequence[int], now: datetime
    ) -> tuple[list[Alert], int]:
        alerts: list[Alert] = []
        bad = 0
        for text in lines:
            try:
                data = json.loads(text)
            except ValueError:
                data = None
            if isinstance(data, dict) and data.get("event_type") != "alert":
                kind = data.get("event_type")
                if kind == "stats":
                    self._note_stats(data)
                elif kind == "flow":
                    if conn := _conn(data):
                        self._conns.append(conn)
                elif kind in ("dns", "tls", "http", "fileinfo"):
                    self._note_event(kind, data)
                elif kind == "anomaly":
                    if anomaly := _anomaly(data):
                        self._anomalies.append(anomaly)
                        self._note_event(kind, data)
                continue
            alert = self._alert(data, text) if isinstance(data, dict) else None
            if alert is None:
                bad += 1
                log.warning("unparsed alert line: %.120s", text)
            else:
                alerts.append(alert)
                self._note_alert(alert)
        return alerts, bad

    def _note_alert(self, alert: Alert) -> None:
        flow = alert.flow_id
        if flow is None:
            return
        _remember(self._alerted, flow, None)
        self._out.extend(self._pending.pop(flow, ()))
        for ip in (alert.src_ip, alert.dst_ip):  # a name the PC looked up for this address
            if name := self._names.get(ip):
                self._out.append(FlowFact(flow, "dns", name, alert.ts))

    def _note_event(self, kind: str, data: dict[str, object]) -> None:
        if kind == "dns":
            self._note_dns(data)
            return
        for fact in self._flow_facts(kind, data):
            if fact.flow_id in self._alerted:  # the alert came first
                self._out.append(fact)
                continue
            facts = self._pending.setdefault(fact.flow_id, [])
            # a repeated fact (one anomaly logged many times) must not crowd out the others
            if len(facts) < _PER_FLOW and all(
                (f.kind, f.value) != (fact.kind, fact.value) for f in facts
            ):
                facts.append(fact)
            _remember(self._pending, fact.flow_id, facts)

    def _note_dns(self, data: dict[str, object]) -> None:
        """Which name each address was looked up as: A and AAAA answers say so. Each answer is
        also kept as a Lookup by the client that asked (the event's source)."""
        info = data.get("dns")
        answers = info.get("answers") if isinstance(info, dict) else None
        if not isinstance(info, dict) or not isinstance(answers, list):
            return
        client, ts = _text(data.get("src_ip")), _stamp(data.get("timestamp"))
        asked = _asked(info)
        for answer in answers:
            if isinstance(answer, dict) and answer.get("rrtype") in ("A", "AAAA"):
                name, address = _text(answer.get("rrname")), _text(answer.get("rdata"))
                if name and address:
                    _remember(self._names, address, name)
                    if len(self._answered) < _REMEMBERED:  # bounded between two takes
                        self._answered[name] = None
                    if client and ts:  # the name asked for, not the alias that answered
                        self._lookups.append(Lookup(ts, client, asked or _dns_name(name), address))

    @staticmethod
    def _flow_facts(kind: str, data: dict[str, object]) -> list[FlowFact]:
        flow, ts, info = data.get("flow_id"), _stamp(data.get("timestamp")), data.get(kind)
        if type(flow) is not int or ts is None or not isinstance(info, dict):
            return []
        if (
            kind == "http"
        ):  # a web request: the host and path, never the query (it may hold secrets)
            host, url = _text(info.get("hostname")), _text(info.get("url"))
            value = _text(f"{host or ''}{url.split('?')[0] if url else ''}")
            return [FlowFact(flow, "http", value, ts)] if value else []
        found: list[tuple[FactKind, object]]
        if kind == "anomaly":  # e.g. "http INVALID_GAP"
            parts = (_text(info.get("app_proto")), _text(info.get("event")))
            found = [("anomaly", " ".join(p for p in parts if p))]
        elif kind == "fileinfo":  # its MD5 only when the config forces hashing (home_conf does)
            found = [("file", _file_name(info, data)), ("md5", info.get("md5"))]
        else:
            ja3 = info.get("ja3")
            found = [
                ("tls", info.get("sni")),
                ("ja3", ja3.get("hash") if isinstance(ja3, dict) else None),
                ("ja4", info.get("ja4")),
            ]
        return [
            FlowFact(flow, k, v, ts)
            for k, raw in found
            if (v := _text(raw)) and (k not in _FINGERPRINT or _FINGERPRINT[k].fullmatch(v))
        ]

    def _note_stats(self, data: dict[str, object]) -> None:
        """Totals since the engine started: kernel_drops out of kernel_packets."""
        stats = data.get("stats")
        capture = stats.get("capture") if isinstance(stats, dict) else None
        if not isinstance(capture, dict):
            return
        packets, drops = capture.get("kernel_packets"), capture.get("kernel_drops")
        if isinstance(packets, int) and isinstance(drops, int) and packets > 0:
            self.drop_pct = round(100 * drops / packets, 2)

    @staticmethod
    def _alert(data: dict[str, object], text: str) -> Alert | None:
        info = data.get("alert")
        stamp = data.get("timestamp")
        src, dst = data.get("src_ip"), data.get("dest_ip")
        if not isinstance(info, dict) or not isinstance(stamp, str):
            return None
        if not isinstance(src, str) or not isinstance(dst, str):
            return None
        sid = _int(info.get("signature_id"), -1)
        gid, rev, severity = (
            _int(info.get("gid"), 1),
            _int(info.get("rev"), 0),
            _int(info.get("severity"), 3),
        )
        msg = info.get("signature")
        if sid is None or sid < 0 or gid is None or rev is None or severity is None:
            return None
        if not isinstance(msg, str):
            return None
        try:
            ts = datetime.fromisoformat(stamp)
        except ValueError:
            return None
        if ts.tzinfo is None:  # a time without an offset cannot be placed
            return None
        category = info.get("category")
        flow = data.get("flow_id")
        # The same event read twice gives the same key, and two events never share one.
        raw = f"eve:{flow}:{sid}:{stamp}" if flow is not None else text
        return Alert(
            ts=ts,
            gid=gid,
            sid=sid,
            rev=rev,
            msg=msg,
            classification=category if isinstance(category, str) and category else None,
            priority=severity,
            proto=str(data.get("proto", "")).upper(),
            src_ip=src,
            src_port=_port(data.get("src_port")),
            dst_ip=dst,
            dst_port=_port(data.get("dest_port")),
            raw=raw,
        )
