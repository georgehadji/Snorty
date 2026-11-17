"""Builds the sandbox Snort config from the live one. Pure: text in, text out."""

import re
from pathlib import Path

_DROP = re.compile(
    r"^\s*include\s+(?:\$(?:RULE_PATH|PREPROC_RULE_PATH)/\S+\.rules|threshold\.conf)\s*$",
    re.IGNORECASE,
)


def build_lab_conf(live_conf_text: str, rules_path: str) -> str:
    """The live config minus every rules, preprocessor-rules and threshold include, plus one
    include of the lab rules. Everything else, line endings included, is kept.

    Snort's `include` takes an unquoted path, so a path with whitespace is refused."""
    if any(c.isspace() for c in rules_path):
        raise ValueError(f"the lab rules path must not contain whitespace: {rules_path!r}")
    eol = "\r\n" if "\r\n" in live_conf_text else "\n"
    kept = [
        ln for ln in live_conf_text.splitlines(keepends=True) if not _DROP.match(ln.rstrip("\r\n"))
    ]
    out = "".join(kept)
    if out and not out.endswith("\n"):
        out += eol
    return f"{out}include {rules_path}{eol}"


def build_suricata_lab_conf(live_conf_text: str, rules_path: str) -> str:
    """The live suricata.yaml with its rule list replaced by one file, the lab rules, which is
    looked up in the lab rules' own folder. Everything else, line endings included, is kept."""
    rules = Path(rules_path)
    eol = "\r\n" if "\r\n" in live_conf_text else "\n"
    out: list[str] = []
    in_list = found = False
    for line in live_conf_text.splitlines(keepends=True):
        bare = line.rstrip("\r\n")
        if bare.startswith("rule-files:"):
            in_list = found = True
            out.append(bare + eol + f" - {rules.name}" + eol)
            continue
        if in_list:
            if bare.strip() == "" or bare.lstrip().startswith(("-", "#")):
                continue  # an entry or a comment of the old list
            in_list = False
        if bare.startswith("default-rule-path:"):
            line = f"default-rule-path: {rules.parent}{eol}"
        out.append(line)
    if not found:
        raise ValueError("the live suricata.yaml has no rule-files list")
    return "".join(out)
