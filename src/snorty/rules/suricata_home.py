"""A copy of Suricata's config and rules that Snorty may edit.

The stock install lives in Program Files, which is read-only without admin rights, and Snorty
must rewrite the rule list and threshold file and swap whole rule folders. So it works on its own
copy in the data folder, made from the install and left alone until the install's own config
changes (an engine upgrade), when the config is made again from the new one."""

import hashlib
import logging
import re
import shutil
from pathlib import Path

from snorty.rules.dialects import SuricataDialect
from snorty.suricata import SuricataPaths

log = logging.getLogger("snorty.rules")

_LISTED = re.compile(r"^[ \t]*-[ \t]*(\S+\.rules)[ \t]*$")
SOURCE = ".snorty-source"  # SHA-256 of the install's suricata.yaml, then RECIPE
BEFORE = "suricata.yaml.before-rebuild"  # the config a rebuild replaced
RECIPE = 2  # raise when home_conf changes, so existing copies are made again once
# Commented-out lines of the stock config that the copy switches on, first occurrence each:
# the client TLS fingerprints, and logging JA4 in EVE `tls` records (the first `# ja4:`).
_TURN_ON = (("ja3-fingerprints", "yes"), ("ja4-fingerprints", "yes"), ("ja4", "on"))


def _uncomment(text: str, key: str, value: str) -> str:
    """`#key: x` becomes `key: value` at the same indent; a config without the line is kept."""
    pattern = rf"^([ \t]*)#[ \t]*{re.escape(key)}:[^\r\n]*"
    return re.sub(pattern, lambda m: f"{m[1]}{key}: {value}", text, count=1, flags=re.M)


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


def home_conf(stock: str, home: Path, previous: str | None = None) -> str:
    """The install's config pointed at `home`. HOME_NET set in the `previous` copy is kept."""
    dialect = SuricataDialect()
    text = _set_key(stock, "default-log-dir", home / "log")
    text = _set_key(text, "classification-file", home / "classification.config")
    text = _set_key(text, "reference-config-file", home / "reference.config")
    text = dialect.rewrite_rule_path(text, str(home / "rules"))
    text = dialect.rewrite_threshold(text, str(home / dialect.threshold_name))
    for key, value in _TURN_ON:
        text = _uncomment(text, key, value)
    if previous is not None:
        try:
            text = dialect.set_home_net(text, dialect.get_home_net(previous))
        except ValueError:  # one of the two has no HOME_NET line: keep the install's
            pass
    return text


def prepare_suricata_home(install: Path, home: Path) -> SuricataPaths:
    """Make `home` from the install, and make its config again when the install's config is not
    the one it was made from (an engine upgrade, a copy older than this record, or a new RECIPE).

    A rebuild keeps the rules, the threshold list and HOME_NET, refreshes the rule files the
    install ships, and keeps the replaced config as `suricata.yaml.before-rebuild`. Rule files the
    config lists but the install does not ship get an empty placeholder, so the engine can start
    before the first rules update; that update fills them in."""
    paths = SuricataPaths(
        exe=install / "suricata.exe", conf=home / "suricata.yaml", log_dir=home / "log"
    )
    rules = home / "rules"
    rules.mkdir(parents=True, exist_ok=True)
    paths.log_dir.mkdir(parents=True, exist_ok=True)
    raw = (install / "suricata.yaml").read_bytes()
    source = f"{hashlib.sha256(raw).hexdigest()} {RECIPE}"
    record = home / SOURCE
    previous: str | None = None
    if paths.conf.exists():
        if record.is_file() and record.read_text(encoding="ascii").strip() == source:
            return paths
        previous = paths.conf.read_bytes().decode("utf-8", "surrogateescape")
        shutil.copy2(paths.conf, home / BEFORE)
        log.warning("the Suricata install changed: remaking %s (old copy: %s)", paths.conf, BEFORE)
    for name in ("classification.config", "reference.config"):
        shutil.copy2(install / name, home / name)
    for rule_file in (install / "rules").glob("*.rules"):
        shutil.copy2(rule_file, rules / rule_file.name)
    (home / SuricataDialect.threshold_name).touch()
    stock = raw.decode("utf-8", "surrogateescape")
    for name in _listed_rule_files(stock):
        (rules / name).touch()  # never truncates a rule file the updates filled
    text = home_conf(stock, home, previous)
    paths.conf.write_bytes(text.encode("utf-8", "surrogateescape"))
    record.write_text(source, encoding="ascii")
    return paths
