"""Triage: whether someone has dealt with an alert, and the rules that deal with some for them."""

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from snorty.core.query import AlertQuery

type TriageState = Literal["new", "ack", "starred"]  # no stored row means "new"
STATES: tuple[TriageState, ...] = ("new", "ack", "starred")
INBOX: tuple[TriageState, ...] = ("new", "starred")  # what still needs a look


@dataclass(frozen=True, slots=True)
class ArchiveRule:
    """Alerts matching `spec` are acknowledged as they arrive. They stay stored and detected;
    they only leave the inbox. Time bounds in `spec` are ignored."""

    spec: AlertQuery
    note: str
    created: datetime
    id: int = 0


def spec_to_json(spec: AlertQuery) -> str:
    fields = {
        "sid": spec.sid,
        "min_priority": spec.min_priority,
        "src_ip": spec.src_ip,
        "dst_ip": spec.dst_ip,
    }
    return json.dumps({k: v for k, v in fields.items() if v is not None})


def spec_from_json(text: str) -> AlertQuery:
    d = json.loads(text)
    return AlertQuery(
        sid=d.get("sid"),
        min_priority=d.get("min_priority"),
        src_ip=d.get("src_ip"),
        dst_ip=d.get("dst_ip"),
    )
