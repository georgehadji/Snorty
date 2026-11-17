"""Facts read from a rule's own text, for an alert's detail."""

from collections.abc import Callable
from functools import lru_cache

from snorty.core.rulemeta import Attack, attack_of, rule_metadata


class RuleInfo:
    """Joins finding a rule with reading its metadata. Cached per (sid, rev): a rules update that
    changes a rule gives its new alerts a new rev, so they are read again."""

    def __init__(self, find: Callable[[int], str | None], size: int = 1024) -> None:
        self._find = find
        self._cached = lru_cache(maxsize=size)(self._read)

    def _read(self, sid: int, rev: int) -> Attack | None:
        text = self._find(sid)
        return attack_of(rule_metadata(text)) if text else None

    def attack(self, sid: int, rev: int) -> Attack | None:
        return self._cached(sid, rev)
