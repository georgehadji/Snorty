from dataclasses import dataclass

from snorty.snort.models import SnortPaths
from snorty.suricata.models import SuricataPaths


@dataclass(frozen=True, slots=True)
class SensorConfig:
    paths: SnortPaths | SuricataPaths = SnortPaths()
    interface_ip: str | None = None
    poll_interval: float = 0.5
    network_check_interval: float = 30.0
    max_restarts: int = 5
    stable_after: float = 60.0
    stop_timeout: float = 15.0
