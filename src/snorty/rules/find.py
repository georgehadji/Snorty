"""Look a rule up by its sid in the rules files, for showing or explaining it."""

import re
from pathlib import Path


def find_rule(rules_dir: Path, sid: int) -> str | None:
    """The text of the rule with this sid, or None. A rule that is switched off (commented out)
    is found too, without its leading `#`."""
    pattern = re.compile(rf"^[^\n]*\bsid:\s*{int(sid)}\s*;[^\n]*$", re.MULTILINE)
    try:
        files = sorted(rules_dir.glob("*.rules"))
    except OSError:
        return None
    for path in files:
        try:
            match = pattern.search(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        if match:
            return match.group(0).strip().lstrip("#").strip()
    return None
