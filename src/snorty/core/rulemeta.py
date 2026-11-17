"""What a rule's `metadata:` option says, and the MITRE ATT&CK tags in it. Pure text parsing; the
rule text comes from whoever found the rule."""

import re
from dataclasses import dataclass
from itertools import zip_longest

_METADATA = re.compile(r"[(;]\s*metadata\s*:\s*([^;]*);")
_TACTIC = re.compile(r"TA\d{4}")
_TECHNIQUE = re.compile(r"T\d{4}(?:\.\d{3})?")


def rule_metadata(rule_text: str) -> dict[str, tuple[str, ...]]:
    """`metadata: key value, key value;` as {key: values}, keys repeated in order. ET writes
    each pair as a key, a space and a value; a part without a value is skipped."""
    found: dict[str, list[str]] = {}
    for option in _METADATA.finditer(rule_text):
        for part in option.group(1).split(","):
            key, _, value = part.strip().partition(" ")
            if key and value.strip():
                found.setdefault(key, []).append(value.strip())
    return {k: tuple(v) for k, v in found.items()}


@dataclass(frozen=True, slots=True)
class Tag:
    id: str  # TA0001, T1190 or T1059.001
    name: str

    @property
    def url(self) -> str:
        kind = "tactics" if self.id.startswith("TA") else "techniques"
        return f"https://attack.mitre.org/{kind}/{self.id.replace('.', '/')}/"


@dataclass(frozen=True, slots=True)
class Attack:
    tactics: tuple[Tag, ...]
    techniques: tuple[Tag, ...]


def _tags(meta: dict[str, tuple[str, ...]], kind: str, valid: re.Pattern[str]) -> tuple[Tag, ...]:
    ids, names = meta.get(f"mitre_{kind}_id", ()), meta.get(f"mitre_{kind}_name", ())
    return tuple(
        Tag(i, n.replace("_", " "))
        for i, n in zip_longest(ids, names, fillvalue="")
        if valid.fullmatch(i)  # the id goes into a link, so only the documented shapes
    )


def attack_of(meta: dict[str, tuple[str, ...]]) -> Attack | None:
    """The rule's ATT&CK tactics and techniques, or None when it has neither."""
    tactics = _tags(meta, "tactic", _TACTIC)
    techniques = _tags(meta, "technique", _TECHNIQUE)
    return Attack(tactics, techniques) if tactics or techniques else None
