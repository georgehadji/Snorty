from dataclasses import dataclass
from pathlib import Path

from snorty.snort.models import SnortPaths

ET_URL = "https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz"
ALL_PRIVATE = "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"


@dataclass(frozen=True, slots=True)
class RulesConfig:
    paths: SnortPaths = SnortPaths()
    rules_dir: Path = Path(r"C:\Snort\rules")
    url: str = ET_URL
    min_ratio: float = 0.5
    health_timeout: float = 60.0
    max_download: int = 100 * 1024 * 1024
    home_net_default: str = ALL_PRIVATE

    @property
    def threshold_conf(self) -> Path:
        return self.paths.conf.with_name("threshold.conf")

    @property
    def state_path(self) -> Path:
        return self.rules_dir.with_name("rules-state.json")
