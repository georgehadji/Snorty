# Spec: <package> (as built)

Copy this file to `SPEC-<package>.md` at the repository root. Keep it under 80 lines. Describe
what the code does now and cite the source file for each claim; a spec that disagrees with the code
is a bug in one of them. After adding one, run `uv run python scripts/module_index.py`.

## Objective

One paragraph: what the package answers for the user, and what it deliberately does not do.

## Architecture and patterns

- Where it sits: domain, feature service or adapter; which import-linter contracts name it
  (`[tool.importlinter]` in `pyproject.toml`).
- The pattern each piece uses and why (Strategy, Null Object, Observer, Specification, ...).
- Wiring: the line in `src/snorty/compose.py` that builds it, and what it is given.

## Ports

The Protocols it implements or depends on, with file paths. For each: the method, what it
returns, and what it does when the outside world fails.

## Behaviour and invariants

Numbered rules that must stay true, each with its source file. Include the limits (sizes, time
windows, caches) and what happens at each.

## Security and privacy

What crosses a trust boundary (input from the network, a file, the user) and how it is checked.
Say what never leaves the PC.

## Tests

The test files that pin the rules above, and any pytest marker that needs real software.

## Deviations and known limits

What differs from `CAPABILITY-MAP.md` or the plan, and what is known not to work.
