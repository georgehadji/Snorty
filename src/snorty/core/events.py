from dataclasses import dataclass
from datetime import datetime

from snorty.core.models import Alert, FlowFact


@dataclass(frozen=True, slots=True)
class AlertRaised:
    alert: Alert


@dataclass(frozen=True, slots=True)
class SensorStateChanged:
    # Plain strings: this module must not depend on the sensor's state enum.
    old: str
    new: str
    reason: str | None


@dataclass(frozen=True, slots=True)
class RulesUpdated:
    ok: bool
    rule_count: int
    detail: str


@dataclass(frozen=True, slots=True)
class AlertsBackfilled:
    """Alerts stored without being announced one by one (those Snort wrote while Snorty was
    down). The span tells the journal which days changed."""

    first: datetime
    last: datetime


@dataclass(frozen=True, slots=True)
class AlertFlagged:
    """An alert that deserves attention whatever its priority (its address is on a known-bad
    list). Carries the stored alert so a consumer need not look it up."""

    alert: Alert
    reason: str


@dataclass(frozen=True, slots=True)
class SensorHealth:
    """How much traffic the engine missed since it started, as a percentage of what it saw."""

    drop_pct: float


@dataclass(frozen=True, slots=True)
class FilesSeen:
    """Files the engine logged on flows that have an alert, as `md5` flow facts. Published after
    the alerts of the same read, so a file that finished after its alert is still checked."""

    files: tuple[FlowFact, ...]


type Event = (
    AlertRaised
    | AlertsBackfilled
    | AlertFlagged
    | SensorStateChanged
    | RulesUpdated
    | SensorHealth
    | FilesSeen
)
