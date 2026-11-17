"""Attribution: which program on this PC made or received an alert's connection."""

from snorty.attribution.ports import ConnectionLookup, Owner
from snorty.attribution.service import AttributionService

__all__ = ["AttributionService", "ConnectionLookup", "Owner"]
