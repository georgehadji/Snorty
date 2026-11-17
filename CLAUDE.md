# Snorty

Local Windows dashboard around an IDS engine: Suricata (the default when installed) or Snort 2.9.20 at `C:\Snort`. One
asyncio process; FastAPI, Jinja2, htmx and SSE on `127.0.0.1:8765`. Python 3.12 with uv. Runtime
dependencies are fastapi, jinja2, uvicorn and winotify only: prefer the stdlib, ask before adding one.

This file routes. Facts live in the files it points at.

## Where things live

| Need | Go to |
|---|---|
| Every package: purpose, spec, tests, rules (generated) | `docs/modules.md` |
| What else moves when you change X | `docs/effects.md` |
| Original design, patterns per module | `CAPABILITY-MAP.md` |
| One module's contract | `SPEC-*.md` (see `docs/modules.md`); new ones copy `docs/_templates/spec.md` |
| User docs, config keys, CLIs | `README.md` |
| Architecture rules, enforced | `[tool.importlinter]` in `pyproject.toml` |
| Wiring, the one composition root | `src/snorty/compose.py` |
| Protocols the UI uses | `src/snorty/services.py` |
| Tests | `tests/<package>/` (host context and triage tests are in `tests/core/`) |
| CI (the gate minus `-m snort`, Windows runner) | `.github/workflows/ci.yml` |
| Runtime data (outside the repo) | `%LOCALAPPDATA%\Snorty`: `snorty.toml`, `snorty.db`, `suricata/`, `snorty.log` |
| Current work notes (untracked) | `PLAN-enhancements.md`, `RESEARCH-enhancements.md` |

## Gate (all must pass before calling work done)

```bash
uv run ruff format src tests scripts
uv run ruff check src tests scripts
uv run mypy src
uv run lint-imports
uv run pytest -q -m "not snort"    # run three times; flaky counts as failing
uv run pytest -q -m tshark
```

`uv run pytest -q -m snort` drives the real `C:\Snort` (about 90 s); run it when the snort,
suricata or sensor adapters change. After adding, removing or redescribing a package, run
`uv run python scripts/module_index.py`; a test fails while `docs/modules.md` is out of date.

## Hard rules

- Run Python tooling as `uv run ...` from this folder.
- Only the adapter packages run processes, and `core` imports no other snorty package.
  `lint-imports` enforces both; never weaken a contract to make code pass.
- The dashboard runs non-elevated. Firewall changes ask for Windows approval per change
  (`winfw`); never run Snorty or its tests elevated.
- Database migrations are append-only: add a function at the end of `MIGRATIONS`.
- Explain uses only a local Ollama model. Alert data never goes to a remote service.
- Tests never touch the real `C:\Snort` config or rules; stub the adapter (see
  `tests/sensor/test_port.py`).
- `PLAN-enhancements.md` and `RESEARCH-enhancements.md` stay untracked.
- Commit and push only when the user asks.
