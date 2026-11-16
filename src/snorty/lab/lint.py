"""Checks a user's rules text before Snort ever sees it. Pure: text in, problems out."""

import re
from dataclasses import dataclass

MAX_BYTES = 64 * 1024
MAX_RULES = 200
ALLOWED_ACTIONS = ("alert", "log", "pass")

_SID = re.compile(r"\bsid\s*:\s*(\d+)\s*;")
_MSG = re.compile(r'\bmsg\s*:\s*"((?:[^"\\]|\\.)*)"')


@dataclass(frozen=True, slots=True)
class LabRule:
    line: int  # first line of the rule in the user's text, 1-based
    sid: int
    msg: str


@dataclass(frozen=True, slots=True)
class Problem:
    line: int  # 1-based line in the user's text; 0 means the text as a whole
    message: str


@dataclass(frozen=True, slots=True)
class LintResult:
    rules: tuple[LabRule, ...]
    problems: tuple[Problem, ...]

    @property
    def ok(self) -> bool:
        return not self.problems


def _has_control(line: str) -> bool:
    return any((ord(c) < 32 and c != "\t") or ord(c) == 127 for c in line)


def lint(text: str) -> LintResult:
    """Only `alert`, `log` and `pass` rules (each with a unique sid), comments and blanks."""
    if len(text) > MAX_BYTES or len(text.encode("utf-8", "replace")) > MAX_BYTES:
        return LintResult((), (Problem(0, "the rules text is over 64 KB"),))
    lines = text.replace("\r\n", "\n").split("\n")
    rules: list[LabRule] = []
    problems: list[Problem] = []
    first_line_of_sid: dict[int, int] = {}
    i = 0
    while i < len(lines):
        start = i + 1
        logical = lines[i]
        i += 1
        stripped = logical.strip()
        if not stripped or stripped.startswith("#"):
            if _has_control(logical):
                problems.append(Problem(start, "control character in the text"))
            continue
        broken = _has_control(logical)
        if broken:
            problems.append(Problem(start, "control character in the text"))
        while logical.rstrip().endswith("\\") and i < len(lines):  # rule continued on next line
            nxt = lines[i]
            if _has_control(nxt) and not broken:
                problems.append(Problem(i + 1, "control character in the text"))
                broken = True
            logical = logical.rstrip()[:-1] + " " + nxt
            i += 1
        if broken:
            continue
        action = logical.split(None, 1)[0]
        if action not in ALLOWED_ACTIONS:
            problems.append(
                Problem(
                    start,
                    f"'{action[:30]}' is not allowed in the lab: only alert, log and pass rules",
                )
            )
            continue
        sid = _SID.search(logical)
        if sid is None:
            problems.append(Problem(start, "the rule has no sid"))
            continue
        number = int(sid[1])
        if number in first_line_of_sid:
            problems.append(
                Problem(
                    start, f"duplicate sid {number} (first on line {first_line_of_sid[number]})"
                )
            )
            continue
        if len(rules) == MAX_RULES:
            return LintResult((), (Problem(0, f"more than {MAX_RULES} rules"),))
        first_line_of_sid[number] = start
        msg = _MSG.search(logical)
        rules.append(LabRule(start, number, msg[1] if msg else ""))
    return LintResult(tuple(rules), tuple(problems))
