"""A copy of Suricata's config and rules that Snorty may edit.

The stock install lives in Program Files, which is read-only without admin rights, and Snorty
must rewrite the rule list and threshold file and swap whole rule folders. So it works on its own
copy in the data folder, made once from the install and then left alone."""

import re
import shutil
from pathlib import Path

from snorty.rules.dialects import SuricataDialect
from snorty.suricata import SuricataPaths

_LISTED = re.compile(r"^[ \t]*-[ \t]*(\S+\.rules)[ \t]*$")


def _set_key(text: str, key: str, value: object) -> str:
    out, n = re.subn(rf"^{key}:[^\r\n]*", lambda _: f"{key}: {value}", text, count=1, flags=re.M)
    if n == 0:
        raise ValueError(f"line not found: {key}")
    return out


def _listed_rule_files(text: str) -> list[str]:
    names: list[str] = []
    in_list = False
    for line in text.splitlines():
        if line.startswith("rule-files:"):
            in_list = True
        elif in_list:
            m = _LISTED.match(line)
            if m:
                names.append(m[1])
            elif line.strip() and not line.lstrip().startswith(("-", "#")):
                break
    return names


def prepare_suricata_home(install: Path, home: Path) -> SuricataPaths:
    """Make `home` from the install on first use; an existing `suricata.yaml` there is kept.

    Rule files the config lists but the install does not ship get an empty placeholder, so the
    engine can start before the first rules update; that update fills them in."""
    paths = SuricataPaths(
        exe=install / "suricata.exe", conf=home / "suricata.yaml", log_dir=home / "log"
    )
    rules = home / "rules"
    rules.mkdir(parents=True, exist_ok=True)
    paths.log_dir.mkdir(parents=True, exist_ok=True)
    if paths.conf.exists():
        return paths
    for name in ("classification.config", "reference.config"):
        shutil.copy2(install / name, home / name)
    for rule_file in (install / "rules").glob("*.rules"):
        shutil.copy2(rule_file, rules / rule_file.name)
    threshold = home / SuricataDialect.threshold_name
    threshold.touch()
    text = (install / "suricata.yaml").read_bytes().decode("utf-8", "surrogateescape")
    for name in _listed_rule_files(text):
        (rules / name).touch()
    text = _set_key(text, "default-log-dir", paths.log_dir)
    text = _set_key(text, "classification-file", home / "classification.config")
    text = _set_key(text, "reference-config-file", home / "reference.config")
    text = SuricataDialect().rewrite_rule_path(text, str(rules))
    text = SuricataDialect().rewrite_threshold(text, str(threshold))
    paths.conf.write_bytes(text.encode("utf-8", "surrogateescape"))
    return paths
