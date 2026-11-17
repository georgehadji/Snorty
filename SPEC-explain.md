# Spec: explain (as built)

## Objective

Give a short plain-English reading of the rule behind an alert, made by an Ollama model running
on this PC, and keep it per rule version so the model runs once per (sid, rev). It never sends
alert data to a remote service, never uses a model that Ollama runs remotely, and does not judge
the alert itself (`src/snorty/explain/`).

## Architecture and patterns

- Feature service with a port and one adapter. import-linter names it in "core is the domain",
  "only the process adapters ... run processes" (no `subprocess`), "feature modules never reach
  up" and the independence contract (`pyproject.toml`, `[tool.importlinter]`).
- Ports and adapters: `Explainer` Protocol (`explain/ports.py:12`), implemented by
  `OllamaExplainer` (`explain/ollama.py:79`). The HTTP call is an injected `Transport`
  (`ollama.py:21`) so tests need no Ollama.
- Cache-aside: `ExplainService` reads the `explanations` row for (sid, rev) first, and writes it
  only after a successful answer (`explain/service.py:40-50`).
- Wiring: `compose.py:200-208` builds `ExplainService(repo, OllamaExplainer(explain_model),
  lambda sid: find_rule(rules_dir, sid))` only when `explain_model` is not empty; otherwise
  `Services.explain` is None. The UI reaches it through `ExplainPort` (`services.py:110-113`).

## Ports

- `Explainer.explain(rule_text, alert) -> str` and attribute `model` (`ports.py:12-17`). Failure is
  `ExplainError` with a message for the user (`ports.py:8`).
- Rule lookup: `Callable[[int], str | None]` (sid to rule text) (`service.py:25,31`).
- Repository: `get`, `explanation(sid, rev)`, `put_explanation(...)` (`core/repository.py:519-533`).

## Behaviour and invariants

1. An unknown alert id raises `ExplainError("that alert no longer exists")`; a sid not found in the
   rules files raises `ExplainError` naming the sid (`service.py:36-45`).
2. One model run at a time: an `asyncio.Lock` covers the cache check, the run and the save
   (`service.py:33,39`).
3. A cached answer is returned with `cached=True` and the model that wrote it (`service.py:41-42`).
4. A failed run saves nothing (`service.py:46-50`).
5. Before the first request the adapter asks `/api/tags` (10 s timeout) and refuses a model that
   is not installed or that carries `remote_host` or `remote_model`. The check passes once per
   adapter instance (`ollama.py:48-57,89-91`).
6. Request: `/api/generate` with `stream: false`, `think: false`, temperature 0.2, at most 500
   tokens, timeout 180 s (`ollama.py:92-99`).
7. The prompt holds the alert's message, classification, priority and protocol, and the rule text
   cut to 4000 characters. It holds no addresses or ports (`ollama.py:60-71`).
8. The reply is capped at 256 KiB, must be a JSON object, and must carry a non-empty `response`
   string; `<think>` blocks are removed and the text is cut to 3000 characters with "…"
   (`ollama.py:33-45,74-76,100-103`).

## Security and privacy

- The only address used is the constant `http://127.0.0.1:11434` (`ollama.py:14`), and the opener
  is built with an empty `ProxyHandler`, so no proxy sees the request (`ollama.py:31`).
- "Cloud" models in Ollama forward prompts to a remote server; they are refused before any prompt
  is sent (`ollama.py:52-55`).
- The prompt tells the model the rule is data, not instructions (`ollama.py:64-65`).
- Network failures and non-JSON replies become `ExplainError` with a fixed message
  (`ollama.py:35-44`).

## Tests

- `tests/explain/test_ollama.py`: a local model answers, a remote model is refused before anything
  is sent, a missing model is reported, the local check runs once, odd replies are errors, the
  prompt has the rule but no addresses, long rules are cut and replies cleaned and capped.
- `tests/explain/test_explain_service.py`: answer from the rule text, cached per rule version, a new
  revision explained again, clear errors, a failure is not saved.
- `tests/dashboard/test_dash_explain.py`: the dashboard side.

## Deviations and known limits

- `Explainer.explain` receives the whole `Alert`, addresses included; each adapter must leave them
  out of what it sends (`ports.py:15-17`), and the Ollama adapter does (`ollama.py:60-71`).
- The answer is cached per (sid, rev), not per alert, so it cannot speak about one alert's traffic.
- A model removed from Ollama after the first check is reported only when `/api/generate` fails.
