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


@dataclass(frozen=True, slots=True)
class FlowFact:
    """Something the engine saw on the flow of an alert: a name looked up, a TLS server name, a
    web request. Shown in the alert's detail."""

    flow_id: int
    kind: Literal["dns", "tls", "http"]
    value: str
    ts: datetime
