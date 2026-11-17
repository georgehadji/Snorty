"""The generated package index: built from code, and the committed copy is current."""

import importlib.util
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("module_index", ROOT / "scripts/module_index.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mi = _load()


def test_committed_index_is_current() -> None:
    committed = (ROOT / "docs" / "modules.md").read_text(encoding="utf-8")
    assert committed == mi.render(ROOT), "run: uv run python scripts/module_index.py"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_rows_come_from_docstring_specs_tests_and_pyproject(tmp_path: Path) -> None:
    _write(tmp_path / "src/snorty/a/__init__.py", '"""Alpha: does a | b.\n\nMore detail."""\n')
    _write(tmp_path / "src/snorty/b/__init__.py", "X = 1\n")
    _write(tmp_path / "src/snorty/notpkg/readme.txt", "")
    _write(tmp_path / "SPEC-a.md", "")
    _write(tmp_path / "tests/x/test_one.py", "from snorty.a import X\n")
    _write(tmp_path / "tests/x/test_two.py", "import snorty.ab\n")  # names `ab`, not `a`
    _write(
        tmp_path / "pyproject.toml",
        """
[[tool.mypy.overrides]]
module = ["snorty.a.*"]
strict = true

[[tool.importlinter.contracts]]
name = "no processes"
type = "forbidden"
source_modules = ["snorty.a"]
forbidden_modules = ["subprocess"]

[[tool.importlinter.contracts]]
name = "siblings"
type = "independence"
modules = ["snorty.a", "snorty.b"]
""",
    )
    rows = mi.render(tmp_path).splitlines()[-2:]
    assert rows == [
        "| `a` | Alpha: does a \\| b. | [SPEC-a.md](../SPEC-a.md) | 1 | no | yes | yes |",
        "| `b` | (no docstring) | none | 0 | yes | no | yes |",
    ]
