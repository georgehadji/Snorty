"""Turning the lines an engine writes into alerts. Pure: no I/O, no clock of its own.

Snort's fast format has no year and no zone, so its decoder keeps a little state (the repeated hour
of a clock change). Suricata's EVE JSON carries a full timestamp with its offset and needs none.
"""

import json
import logging
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime, timedelta, tzinfo
from typing import Protocol

from snorty.core.models import Alert
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

    def __init__(self, tz: tzinfo) -> None:
        self._tz = tz
        self._last: float | None = None  # newest alert time read so far, for _settle_fold
        self._second = False  # reading the repeated hour of a clock change a second time
        self.drop_pct: float | None = None  # Snort's fast alerts carry no drop statistics

    def reset(self) -> None:
        self._last, self._second = None, False

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


class EveDecoder:
    """Suricata's EVE JSON, one object per line. Only `alert` events become alerts; every other
    event type is skipped without counting as a failure."""

    def __init__(self) -> None:
        self.drop_pct: float | None = None

    def reset(self) -> None:
        self.drop_pct = None

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
                if data.get("event_type") == "stats":
                    self._note_stats(data)
                continue
            alert = self._alert(data, text) if isinstance(data, dict) else None
            if alert is None:
                bad += 1
                log.warning("unparsed alert line: %.120s", text)
            else:
                alerts.append(alert)
        return alerts, bad

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
