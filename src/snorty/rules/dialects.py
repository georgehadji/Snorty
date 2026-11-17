"""The few edits the rules service makes to an engine's main config file, one class per file
format. Pure text in, text out. Read files with `newline=""` so line endings survive; every edit
touches only the line it owns."""

import re
from collections.abc import Collection, Sequence
from pathlib import Path
from typing import Protocol

from snorty.rules import blocks


class ConfDialect(Protocol):
    @property
    def threshold_name(self) -> str:
        """File name of the threshold/suppress list next to the main config."""
        ...

    def get_home_net(self, text: str) -> str: ...
    def set_home_net(self, text: str, value: str) -> str: ...
    def rewrite_rule_path(self, text: str, path: str) -> str: ...
    def rewrite_threshold(self, text: str, path: str) -> str:
        """Point the config at another threshold file (used to check a candidate)."""
        ...

    def rewrite_rule_files(self, text: str, present: Collection[str]) -> str:
        """Drop rule files the config lists but the ruleset no longer has (a missing one stops
        the engine from loading). Engines that include rules by pattern change nothing."""
        ...


class SnortDialect:
    threshold_name = "threshold.conf"

    def get_home_net(self, text: str) -> str:
        return blocks.get_home_net(text)

    def set_home_net(self, text: str, value: str) -> str:
        return blocks.set_home_net(text, value)

    def rewrite_rule_path(self, text: str, path: str) -> str:
        return blocks.rewrite_rule_path(text, path)

    def rewrite_threshold(self, text: str, path: str) -> str:
        return blocks.rewrite_include(text, self.threshold_name, path)

    def rewrite_rule_files(self, text: str, present: Collection[str]) -> str:
        return text


_HOME_NET = re.compile(r"^([ \t]+)HOME_NET:[ \t]*([^\r\n]*)", re.M)


def _replace(text: str, pattern: str, new: str) -> str:
    out, n = re.subn(pattern, lambda _: new, text, count=1, flags=re.M)
    if n == 0:
        raise ValueError(f"line not found: {pattern}")
    return out


class SuricataDialect:
    """suricata.yaml. HOME_NET sits under `vars: address-groups:`; the rule directory and the
    threshold file are top-level keys."""

    threshold_name = "threshold.config"

    def get_home_net(self, text: str) -> str:
        m = _HOME_NET.search(text)
        if m is None:
            raise ValueError("line not found: HOME_NET")
        return m[2].strip().strip("\"'")

    def set_home_net(self, text: str, value: str) -> str:
        m = _HOME_NET.search(text)
        if m is None:
            raise ValueError("line not found: HOME_NET")
        return text[: m.start()] + f'{m[1]}HOME_NET: "{value}"' + text[m.end() :]

    def rewrite_rule_files(self, text: str, present: Collection[str]) -> str:
        out: list[str] = []
        in_list = False
        for line in text.splitlines(keepends=True):
            if line.startswith("rule-files:"):
                in_list = True
            elif in_list:
                entry = re.match(r"^[ \t]*-[ \t]*(\S+\.rules)[ \t]*$", line.rstrip("\r\n"))
                if entry is None and line.strip() and not line.lstrip().startswith(("-", "#")):
                    in_list = False
                elif entry is not None and entry[1] not in present:
                    continue
            out.append(line)
        return "".join(out)

    def rewrite_rule_path(self, text: str, path: str) -> str:
        return _replace(text, r"^default-rule-path:[ \t]*[^\r\n]*", f"default-rule-path: {path}")

    def rewrite_threshold(self, text: str, path: str) -> str:
        # The stock suricata.yaml has no threshold-file key at all: add it when it is missing.
        if re.search(r"^threshold-file:", text, re.M) is None:
            eol = "\r\n" if "\r\n" in text else "\n"
            return text + ("" if text.endswith("\n") else eol) + f"threshold-file: {path}{eol}"
        return _replace(text, r"^threshold-file:[ \t]*[^\r\n]*", f"threshold-file: {path}")


_FAILED_RULE = re.compile(r"error parsing signature .* from file (.+?) at line (\d+)\s*$")


def failed_rule(errors: Sequence[str]) -> tuple[Path, int] | None:
    """The rule file and 1-based line of the first rule Suricata refused to load, if the check's
    error lines name one. Suricata stops at the first such rule, so callers disable it and check
    again. Snort's errors never match."""
    for line in errors:
        m = _FAILED_RULE.search(line)
        if m:
            return Path(m[1]), int(m[2])
    return None
