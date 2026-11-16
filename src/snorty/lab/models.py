"""Plain data for one lab run."""

from dataclasses import dataclass
from pathlib import Path

from snorty.core.models import Alert
from snorty.lab.lint import Problem


@dataclass(frozen=True, slots=True)
class LabJob:
    rules_text: str
    pcap: Path


@dataclass(frozen=True, slots=True)
class RuleHit:
    sid: int
    msg: str
    line: int  # the rule's first line in the user's text
    count: int


@dataclass(frozen=True, slots=True)
class LabResult:
    """User mistakes (bad rules, bad pcap, a Snort failure) are data here, never raised."""

    ok: bool
    problems: tuple[Problem, ...] = ()  # lint and Snort rule errors, with the user's line numbers
    error: str | None = None  # a failure that is not about one rule
    hits: tuple[RuleHit, ...] = ()  # one per lab rule, zero counts included
    matches: tuple[Alert, ...] = ()  # alerts of the lab rules, in time order
