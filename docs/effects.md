# What a change touches

Before changing something below, open the files in its row. First-order effects only; the source
files are the truth, and a row that disagrees with them is the thing to fix. Package overview:
[modules.md](modules.md).

## Inside the repo

### Add, rename or remove a package
- Touch: `pyproject.toml` `[tool.importlinter]`, in every contract the package belongs to: `core`'s
  forbidden list; the `subprocess` contract's sources unless it is an adapter that runs processes;
  the "never reach up" sources if it is a feature; the independence list if it is a sibling feature.
- Touch: the strict mypy override (`[[tool.mypy.overrides]]`) if it is typed strictly.
- Touch: `src/snorty/compose.py` to wire it; `src/snorty/services.py` if the UI uses it.
- Then: `uv run python scripts/module_index.py`; the package docstring is its Purpose line.
- Does not hit: `CAPABILITY-MAP.md` (the V1 record).

### Database schema
- Touch: a new function at the end of `MIGRATIONS` (`src/snorty/core/repository.py`). A database's
  `schema_version` is how many have run, so never edit, reorder or remove an existing one.
- Check: `AlertRepository.prune` deletes old rows; a new table with timestamps needs a line there.
- Test: `tests/core/test_repository.py`.

### Detection engine (add one, or change how one runs)
- Touch: `EnginePort` (`src/snorty/sensor/port.py`), the engine branch in `compose()`, the
  `AlertDecoder` it uses (`src/snorty/core/decoder.py`), `LabEngine` (`src/snorty/lab/engines.py`),
  the rules dialect (`src/snorty/rules/dialects.py`, chosen in `src/snorty/rules/config.py`).
- Touch: the engine names in `ENGINES` (`src/snorty/dashboard/config.py`), the `--engine` choices
  (`src/snorty/dashboard/__main__.py`) and the `Literal["snort", "suricata"]` in `compose.py` and
  `rules/config.py`.
- Touch: `pyproject.toml` contracts (`core` forbidden list, `packets` forbidden list).
- Does not hit: `snorty.packets`; it never imports an engine package (a contract enforces it).

### Alert `raw` text
- `Alert.flow_id` (`src/snorty/core/models.py`) parses the `eve:{flow_id}:{sid}:{ts}` form that
  `EveDecoder` writes; the alert context route uses it to find flow facts.
- Rows already stored keep their old `raw`; a new form must still parse the old one.

### Firewall blocking
- Three checks must agree: `valid_ip` (`src/snorty/dashboard/security.py`), `refusal`
  (`src/snorty/respond/policy.py`), and `_clean` (`src/snorty/winfw/firewall.py`), the last check
  before text reaches PowerShell. `BlockService` (`src/snorty/respond/service.py`) owns retries
  and the cleanup after a failed block.
- Never make Snorty run elevated to simplify this; each change asks Windows for approval.

### A `snorty.toml` key
- Touch: `DashConfig` and `_check` (`src/snorty/dashboard/config.py`); unknown keys are refused.
- Touch: the flag in `src/snorty/dashboard/__main__.py` if there is one, the `compose()` parameter,
  and the config block in `README.md`.

### Events on the bus
- Event types: `src/snorty/core/events.py`. Subscribers: the dashboard SSE (`dashboard/app.py`),
  `notify`, `journal`, `triage`, `attribution`, `enrich`, and the headless runner.

### Files Snorty edits in the Snort install
- `src/snorty/snort/perfmon.py` adds a marked line to `C:\Snort\etc\snort.conf`; `rules` manages
  blocks in `threshold.conf` and the `HOME_NET` line. Tests must stub these adapters
  (`tests/sensor/test_port.py`), never write to `C:\Snort`.

### Templates
- The CSP forbids inline scripts: behaviour goes in `src/snorty/dashboard/static/app.js`.
  Autoescape stays on; nothing is marked `|safe`.

## Outside the repo (breaks silently: nothing here names them)

| Consumer | Points at | Breaks when |
|---|---|---|
| `%APPDATA%\...\Startup\Snorty dashboard.vbs` (only after `autostart install`) | this repo's `.venv\Scripts\pythonw.exe` | the repo moves or `.venv` is rebuilt elsewhere; run `install` again |
| `%LOCALAPPDATA%\Snorty\backup.ps1` | `%USERPROFILE%\Documents\Vibe Coding` | the repo leaves that folder (it stops being backed up) |
| `%LOCALAPPDATA%\Snorty\snorty.db` | the `MIGRATIONS` list | a migration is edited or removed |
| `C:\Snort\etc\snort.conf` | the perfmon marker in `snort/perfmon.py` | the marker text changes (an old line is no longer found) |
| GitHub `georgehadji/Snorty` | branch `main` | history is rewritten |
