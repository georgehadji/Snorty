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
    # Engine logs in the log dir kept from growing without end (nothing else trims them): once
    # one is bigger than rotate_bytes the engine is restarted, and before each start such a
    # file becomes <name>.1, replacing the one before. Empty: never rotated.
    rotate_logs: tuple[str, ...] = ()
    rotate_bytes: int = 256 * 1024 * 1024
    rotate_check_interval: float = 60.0
