"""What the last update did, kept in a small JSON file beside the rules directory."""

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class RulesState:
    last_md5: str | None = None
    updated_at: str | None = None
    rule_count: int | None = None
    result: str | None = None


def load_state(path: Path) -> RulesState:
    """The saved state, or an empty one if the file is missing or not ours."""
    try:
        state = RulesState(**json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError):
        return RulesState()
    strings = (state.last_md5, state.updated_at, state.result)
    count_ok = state.rule_count is None or type(state.rule_count) is int
    if not (count_ok and all(s is None or isinstance(s, str) for s in strings)):
        return RulesState()
    return state


def save_state(path: Path, state: RulesState) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(asdict(state), indent=2), encoding="utf-8")
    os.replace(tmp, path)
