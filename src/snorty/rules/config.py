from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from snorty.rules.dialects import ConfDialect, SnortDialect, SuricataDialect
from snorty.snort.models import SnortPaths
from snorty.suricata.models import SuricataPaths

ET_URL = "https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz"
# Emerging Threats Open for Suricata 7 and 8 (ET serves the same archive under suricata-8.0.0);
# pass it as `url` with engine="suricata".
SURICATA_ET_URL = "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz"
ALL_PRIVATE = "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"


@dataclass(frozen=True, slots=True)
class RulesConfig:
    paths: SnortPaths | SuricataPaths = SnortPaths()
    engine: Literal["snort", "suricata"] = "snort"
    rules_dir: Path = Path(r"C:\Snort\rules")
    url: str = ET_URL
    min_ratio: float = 0.5
    health_timeout: float = 60.0
    max_download: int = 100 * 1024 * 1024
    home_net_default: str = ALL_PRIVATE

    @property
    def dialect(self) -> ConfDialect:
        return SuricataDialect() if self.engine == "suricata" else SnortDialect()

    @property
    def threshold_conf(self) -> Path:
        return self.paths.conf.with_name(self.dialect.threshold_name)

    @property
    def state_path(self) -> Path:
        return self.rules_dir.with_name("rules-state.json")
