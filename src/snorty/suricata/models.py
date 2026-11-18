import os
from dataclasses import dataclass
from pathlib import Path

# The files Suricata appends to in its log dir for as long as it runs, and never trims.
LOGS = ("eve.json", "stats.log", "fast.log", "suricata.log")


@dataclass(frozen=True, slots=True)
class SuricataPaths:
    exe: Path = Path(r"C:\Program Files\Suricata\suricata.exe")
    conf: Path = Path(r"C:\Program Files\Suricata\suricata.yaml")
    # Program Files is read-only without admin rights, so logs go to the user's own folder.
    log_dir: Path = Path(os.environ.get("LOCALAPPDATA", ".")) / "Snorty" / "suricata-log"

    # Suricata writes its alerts as EVE JSON into the log directory.
    @property
    def alert_file(self) -> str:
        return "eve.json"
