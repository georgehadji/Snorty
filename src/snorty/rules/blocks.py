"""Pure text edits for Snort config files. No I/O: callers read and write the files.

Read files with `newline=""` so line endings survive; every edit here touches only the
lines it owns and leaves all other bytes alone.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass

START = "# >>> snorty managed: do not edit between these markers >>>"
END = "# <<< snorty managed <<<"

# Snort rejects a trailing comment on a suppress line, so a note is its own line above it.
_ENTRY = re.compile(r"^suppress gen_id 1, sig_id (\d+)$")
_NOTE = re.compile(r"^# (\d+): (.*)$")


@dataclass(frozen=True, slots=True)
class MutedRule:
    sid: int
    note: str = ""

    def __post_init__(self) -> None:
        if self.sid < 1:
            raise ValueError(f"SID must be positive, got {self.sid}")


def _eol(text: str) -> str:
    return "\r\n" if "\r\n" in text else "\n"


def _find_block(text: str) -> tuple[int, int] | None:
    """(start of the START line, end of the END line incl. its line ending), or None."""
    s = re.search(rf"^{re.escape(START)}[ \t]*\r?$", text, re.M)
    e = re.search(rf"^{re.escape(END)}[ \t]*\r?$", text, re.M)
    if s is None and e is None:
        return None
    if s is None or e is None or e.start() < s.start():
        raise ValueError("unbalanced snorty markers in threshold.conf")
    end = e.end()
    if text.startswith("\n", end):
        end += 1
    return s.start(), end


def read_block(text: str) -> list[MutedRule]:
    span = _find_block(text)
    if span is None:
        return []
    out: list[MutedRule] = []
    inner = text[span[0] : span[1]].splitlines()[1:-1]
    notes: dict[int, str] = {}
    for line in inner:
        if n := _NOTE.match(line):
            notes[int(n[1])] = n[2]
        elif m := _ENTRY.match(line):
            out.append(MutedRule(int(m[1]), notes.get(int(m[1]), "")))
        else:
            raise ValueError(f"unexpected line inside the managed block: {line!r}")
    return out


def _render(entries: Sequence[MutedRule], eol: str) -> str:
    by_sid = {e.sid: e for e in entries}  # last one wins
    lines = [START]
    for sid in sorted(by_sid):
        note = " ".join(by_sid[sid].note.split())  # one line, no stray whitespace
        if note:
            lines.append(f"# {sid}: {note}")
        lines.append(f"suppress gen_id 1, sig_id {sid}")
    lines.append(END)
    return eol.join(lines) + eol


def apply_block(text: str, entries: Sequence[MutedRule]) -> str:
    """Return `text` with the managed block set to `entries` (removed when empty)."""
    span = _find_block(text)
    if not entries:
        return text if span is None else text[: span[0]] + text[span[1] :]
    block = _render(entries, _eol(text))
    if span is not None:
        return text[: span[0]] + block + text[span[1] :]
    if text and not text.endswith("\n"):
        text += _eol(text)
    return text + block


def _replace_line(text: str, pattern: str, new: str) -> str:
    out, n = re.subn(pattern, lambda _: new, text, count=1, flags=re.M)
    if n == 0:
        raise ValueError(f"line not found: {pattern}")
    return out


def get_home_net(text: str) -> str:
    m = re.search(r"^ipvar[ \t]+HOME_NET[ \t]+([^\r\n]*)", text, re.M)
    if m is None:
        raise ValueError("line not found: ipvar HOME_NET")
    return m[1].strip()


def set_home_net(text: str, value: str) -> str:
    return _replace_line(text, r"^ipvar[ \t]+HOME_NET[ \t]+[^\r\n]*", f"ipvar HOME_NET {value}")


def rewrite_rule_path(text: str, path: str) -> str:
    return _replace_line(text, r"^var[ \t]+RULE_PATH[ \t]+[^\r\n]*", f"var RULE_PATH {path}")


def rewrite_include(text: str, name: str, path: str) -> str:
    pattern = rf"^include[ \t]+{re.escape(name)}[ \t]*(?=\r?$)"
    return _replace_line(text, pattern, f"include {path}")
