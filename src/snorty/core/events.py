from dataclasses import dataclass

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


type Event = AlertRaised | SensorStateChanged | RulesUpdated
