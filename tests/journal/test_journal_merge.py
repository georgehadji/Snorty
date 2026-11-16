from datetime import date

import pytest

from snorty.journal.merge import NoteConflict, merge
from snorty.journal.render import BEGIN, END

DAY = date(2026, 11, 16)


def block(body: str = "x") -> str:
    return f"{BEGIN}\n## Snort alerts\n\n{body}\n{END}\n"


def test_no_note_creates_frontmatter_title_and_block() -> None:
    out = merge(None, block(), DAY)
    assert out.startswith("---\ndate: 2026-11-16\ntype: snort-journal\n")
    assert "tags:\n  - security\n  - snort\nai-first: true\n---\n" in out
    assert "# 2026-11-16 Snort journal" in out
    assert out.endswith(block())


def test_note_without_markers_gets_the_block_appended_and_nothing_else_changes() -> None:
    mine = "---\ndate: 2026-11-16\n---\n# My day\nwrote this\n"
    out = merge(mine, block(), DAY)
    assert out.startswith(mine)
    assert out == mine + "\n" + block()


def test_note_without_trailing_newline_is_still_preserved() -> None:
    mine = "my text"
    out = merge(mine, block(), DAY)
    assert out.startswith(mine) and out.endswith(block())


def test_empty_note_gets_just_the_block() -> None:
    assert merge("", block(), DAY) == block()


def test_good_markers_replace_only_what_is_between_them() -> None:
    before, after = "intro\n\n", "\n\n## My notes\nkeep me\n"
    existing = before + block("old") + after
    out = merge(existing, block("new"), DAY)
    assert out == before + block("new") + after
    assert "old" not in out


def test_user_text_and_frontmatter_survive_ten_regenerations_byte_for_byte() -> None:
    note = merge(None, block("v0"), DAY)
    head, tail = note.split(BEGIN)[0], "\n## Mine\nhand written ✓\n"
    note += tail
    for i in range(1, 11):
        note = merge(note, block(f"v{i}"), DAY)
    assert note.startswith(head) and note.endswith(tail)
    assert "v10" in note and "v9" not in note


def test_same_block_gives_same_text() -> None:
    once = merge(None, block(), DAY)
    assert merge(once, block(), DAY) == once


@pytest.mark.parametrize(
    "existing",
    [
        f"{BEGIN}\na\n{END}\n{BEGIN}\nb\n{END}\n",  # two blocks
        f"{BEGIN}\nonly begin\n",
        f"only end\n{END}\n",
        f"{END}\nreversed\n{BEGIN}\n",
        f"{BEGIN}\n{BEGIN}\n{END}\n",
    ],
)
def test_broken_markers_raise(existing: str) -> None:
    with pytest.raises(NoteConflict):
        merge(existing, block(), DAY)


def test_a_block_that_is_not_a_rendered_block_is_rejected() -> None:
    with pytest.raises(ValueError):
        merge(None, "just text\n", DAY)
