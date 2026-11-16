from dataclasses import dataclass
from datetime import datetime

from snorty.core.models import Alert


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


type Event = AlertRaised | AlertsBackfilled | SensorStateChanged | RulesUpdated
