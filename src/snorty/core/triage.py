"""Triage: whether someone has dealt with an alert, and the rules that deal with some for them."""

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from snorty.core.query import AlertQuery, like_escape

type TriageState = Literal["new", "ack", "starred"]  # no stored row means "new"
STATES: tuple[TriageState, ...] = ("new", "ack", "starred")
INBOX: tuple[TriageState, ...] = ("new", "starred")  # what still needs a look
HOST_KINDS = ("dns", "tls")  # flow facts that name the remote host
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


@dataclass(frozen=True, slots=True)
class ArchiveRule:
    """Alerts matching `spec` are acknowledged as they arrive. They stay stored and detected;
    they only leave the inbox. Time bounds in `spec` are ignored. With `host`, only alerts whose
    flow named that host (or a subdomain of it) match."""

    spec: AlertQuery
    note: str
    created: datetime
    id: int = 0
    host: str | None = None  # lowercase


def host_matches(value: str, host: str) -> bool:
    """`value` is `host` or a subdomain of it; ASCII case is ignored, as in SQLite."""
    v = value.translate(_ASCII_LOWER)
    return v == host or v.endswith("." + host)


def host_sql(host: str) -> tuple[str, list[str]]:
    """The SQL form of host_matches over the alert's flow facts, for a WHERE on `alerts`."""
    clause = (
        "EXISTS (SELECT 1 FROM flows f WHERE f.flow_id = alerts.flow_id "
        f"AND f.kind IN ({', '.join(repr(k) for k in HOST_KINDS)}) "
        "AND (lower(f.value) = ? OR f.value LIKE ? ESCAPE '\\'))"
    )
    return clause, [host, "%." + like_escape(host)]


def spec_to_json(spec: AlertQuery, host: str | None = None) -> str:
    fields = {
        "sid": spec.sid,
        "min_priority": spec.min_priority,
        "src_ip": spec.src_ip,
        "dst_ip": spec.dst_ip,
        "host": host,
    }
    return json.dumps({k: v for k, v in fields.items() if v is not None})


def host_from_json(text: str) -> str | None:
    host = json.loads(text).get("host")
    return host if isinstance(host, str) else None


def spec_from_json(text: str) -> AlertQuery:
    d = json.loads(text)
    return AlertQuery(
        sid=d.get("sid"),
        min_priority=d.get("min_priority"),
        src_ip=d.get("src_ip"),
        dst_ip=d.get("dst_ip"),
    )
