"""Reading the ET archive safely. Only `*.rules` files are ever taken from it."""

import io
import re
import tarfile
import zlib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

# Files the user owns. The archive can never replace them.
PROTECTED = frozenset(
    {"local.rules", "white_list.rules", "black_list.rules", "threatview_cs_c2.rules"}
)

_MD5 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])")
_RULE_LINE = re.compile(r"^\s*(?:alert|drop|reject|pass|log)\s", re.M)


@dataclass(frozen=True, slots=True)
class ExtractReport:
    written: tuple[str, ...]
    skipped: int


def parse_md5(text: str) -> str:
    m = _MD5.search(text)
    if m is None:
        raise ValueError("no md5 hash found")
    return m[0].lower()


def _basename(name: str) -> str | None:
    """The file name if `name` is a safe relative path to a takeable rules file."""
    path = PurePosixPath(name.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or re.match(r"^[A-Za-z]:", name):
        return None
    base = path.name
    if not base.endswith(".rules") or base.lower() in PROTECTED:
        return None
    return base


def safe_members(names: Iterable[str]) -> list[str]:
    return [n for n in names if _basename(n) is not None]


def extract_rules(data: bytes, dest: Path, *, max_member: int = 50 * 1024 * 1024) -> ExtractReport:
    """Write the archive's safe `*.rules` files flat into `dest`. Everything else is counted
    as skipped and never touches the disk."""
    files: dict[str, bytes] = {}
    skipped = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            for member in tf:
                if member.isdir():
                    continue
                base = _basename(member.name)
                fh = tf.extractfile(member) if member.isfile() else None
                if base is None or fh is None or member.size > max_member:
                    skipped += 1
                    continue
                files[base] = fh.read()
    except (tarfile.TarError, EOFError, zlib.error, OSError) as e:
        raise ValueError(f"not a readable rules archive: {e}") from e
    for base, content in files.items():
        (dest / base).write_bytes(content)
    return ExtractReport(tuple(files), skipped)


def count_rules(directory: Path) -> int:
    total = 0
    for path in directory.glob("*.rules"):
        total += len(_RULE_LINE.findall(path.read_text(encoding="utf-8", errors="replace")))
    return total


def sanity_ok(new: int, old: int, ratio: float = 0.5) -> bool:
    return old == 0 or new >= old * ratio
