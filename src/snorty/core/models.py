from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal


@dataclass(frozen=True, slots=True)
class Alert:
    ts: datetime  # timezone-aware
    gid: int
    sid: int
    rev: int
    msg: str
    classification: str | None
    priority: int  # 1 = highest
    proto: str
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    raw: str  # original line, the idempotency key
    id: int = field(default=0, compare=False)  # database row id; 0 until the alert is stored
    # Which of several identical lines this is (0 for the first). Snort prints only microseconds,
    # so two alerts can read exactly alike; `raw` plus `dup` is what tells them apart.
    dup: int = field(default=0, compare=False)

    @property
    def flow_id(self) -> int | None:
        """The engine's flow id, when the alert line carries one (Suricata's do, Snort's do not)."""
        parts = self.raw.split(":", 2)
        return (
            int(parts[1]) if len(parts) == 3 and parts[0] == "eve" and parts[1].isdigit() else None
        )


@dataclass(frozen=True, slots=True)
class Block:
    """An address Snorty asked the firewall to block. `until` None means until unblocked."""

    ip: str
    created: datetime
    until: datetime | None
    alert_id: int | None
    state: Literal["active", "released", "expired"]


@dataclass(frozen=True, slots=True)
class Suppression:
    gid: int
    sid: int
    track: Literal["by_src", "by_dst"] | None = None
    ip: str | None = None

    def __post_init__(self) -> None:
        if (self.track is None) != (self.ip is None):
            raise ValueError("track and ip must be given together")

    def to_threshold_line(self) -> str:
        line = f"suppress gen_id {self.gid}, sig_id {self.sid}"
        if self.track is not None:
            line += f", track {self.track}, ip {self.ip}"
        return line


type FactKind = Literal["dns", "tls", "http", "ja3", "ja4"]


@dataclass(frozen=True, slots=True)
class FlowFact:
    """Something the engine saw on the flow of an alert: a name looked up, a TLS server name, a
    web request, the client's TLS fingerprint (JA3 hash, JA4). Shown in the alert's detail."""

    flow_id: int
    kind: FactKind
    value: str
    ts: datetime


@dataclass(frozen=True, slots=True)
class Conn:
    """One connection the engine saw end (Suricata's `flow` event), alert or not. `src` is the
    side that opened it; `out` counts what it sent, `in_` what it got back."""

    flow_id: int
    start: datetime
    end: datetime
    proto: str
    app_proto: str | None  # what the engine recognised it as (tls, dns, http...), if anything
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    pkts_out: int
    pkts_in: int
    bytes_out: int
    bytes_in: int
    state: str | None  # new, established, closed...


@dataclass(frozen=True, slots=True)
class Lookup:
    """One DNS answer: `client` looked up `name` and was told `address`."""

    ts: datetime
    client: str
    name: str
    address: str
