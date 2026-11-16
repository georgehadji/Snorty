"""Builds the sandbox Snort config from the live one. Pure: text in, text out."""

import re

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
