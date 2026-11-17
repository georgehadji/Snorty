# Spec: explain (as built)

## Objective

Give a short plain-language reading of the rule behind an alert, made by an Ollama model running
on this PC, in the user's language and for the user's role, and keep it per rule version so the
model runs once per (sid, rev). Optionally explain each rule the first time it fires, in the
background, so the user's click finds the answer ready. It never sends alert data to a remote
service, never uses a model that Ollama runs remotely, and does not judge the alert itself
(`src/snorty/explain/`).

## Architecture and patterns

- Feature service with a port and one adapter. import-linter names it in "core is the domain",
  "only the process adapters ... run processes" (no `subprocess`), "feature modules never reach
  up" and the independence contract (`pyproject.toml`, `[tool.importlinter]`).
- Ports and adapters: `Explainer` Protocol (`explain/ports.py:12`), implemented by
  `OllamaExplainer` (`explain/ollama.py:93`). The HTTP call is an injected `Transport`
  (`ollama.py:21`) so tests need no Ollama.
- Cache-aside: `ExplainService._answer` reads the `explanations` row for (sid, rev) in the
  explainer's style first, and writes it only after a successful answer (`explain/service.py:64`).
- Observer: with a bus, `start()` subscribes to `AlertRaised` and a background task explains each
  rule version once (`service.py:87-122`), like `TriageService`.
- Wiring: `compose.py:213-220` builds `ExplainService(repo, OllamaExplainer(explain_model,
  language=..., audience=...), lambda sid: find_rule(rules_dir, sid), bus=bus if
  explain_prewarm)` only when `explain_model` is not empty; otherwise `Services.explain` is None.
  `Runtime` starts and stops it. The UI reaches it through `ExplainPort` (`services.py:110-113`).

## Ports

- `Explainer.explain(rule_text, alert) -> str` and attributes `model` and `style`
  (`"language/audience"`) (`ports.py:12-19`). Failure is `ExplainError` with a message for the
  user (`ports.py:8`).
- Rule lookup: `Callable[[int], str | None]` (sid to rule text).
- Repository: `get`, `explanation(sid, rev, style=)`, `put_explanation(..., style=)`
  (`core/repository.py:529-547`).

## Behaviour and invariants

1. An unknown alert id raises `ExplainError("that alert no longer exists")`; a sid not found in the
   rules files raises `ExplainError` naming the sid.
2. One model run at a time: an `asyncio.Lock` covers the cache check, the run and the save.
3. A cached answer is returned with `cached=True` and the model that wrote it.
4. A failed run saves nothing.
5. One answer is kept per (sid, rev). An answer kept in another style (language or audience) is
   not used; the new answer replaces it. Answers kept before the `style` column existed count as
   `English/home` (migration `_add_explanation_style`, `core/repository.py:170`).
6. Background: each (sid, rev) is offered once per process; the queue holds at most 100 and
   refuses newer ones when full. A rule not in the rules files is skipped quietly. While a person
   is waiting for an answer the background waits (`service.py:114`). When the model fails, the
   alert is dropped, the reason is logged once at INFO, and the background sleeps `retry_after`
   (300 s) before taking the next one.
7. Before the first request the adapter asks `/api/tags` (10 s timeout) and refuses a model that
   is not installed or that carries `remote_host` or `remote_model`. The check passes once per
   adapter instance (`ollama.py:48-57`).
8. Request: `/api/generate` with `stream: false`, `think: false`, temperature 0.2, at most 1500
   tokens (`MAX_ANSWER_TOKENS`: Greek and other scripts take several times more tokens than
   English), timeout 180 s. An answer that hit the limit (`done_reason: "length"`) ends in "…".
9. The prompt names the reader (`AUDIENCES`: home, office, analyst, `ollama.py:61`) and asks for
   the answer in the configured language. It holds the alert's message, classification, priority
   and protocol, and the rule text cut to 4000 characters. It holds no addresses or ports
   (`ollama.py:71`).
10. The reply is capped at 256 KiB, must be a JSON object, and must carry a non-empty `response`
    string; `<think>` blocks are removed and the text is cut to 3000 characters with "…".

## Security and privacy

- The only address used is the constant `http://127.0.0.1:11434` (`ollama.py:14`), and the opener
  is built with an empty `ProxyHandler`, so no proxy sees the request (`ollama.py:31`).
- "Cloud" models in Ollama forward prompts to a remote server; they are refused before any prompt
  is sent.
- The prompt tells the model the rule is data, not instructions.
- `explain_language` goes into the prompt, so the config accepts only one to four words of letters
  (`dashboard/config.py`, `_LANGUAGE`); `explain_audience` must be a key of `AUDIENCES`.
- The background sends the same prompt as a click; it adds no new data to the prompt.
- Network failures and non-JSON replies become `ExplainError` with a fixed message.

## Tests

- `tests/explain/test_ollama.py`: a local model answers, a remote model is refused before anything
  is sent, a missing model is reported, the local check runs once, odd replies are errors, the
  prompt has the rule but no addresses, the language and reader reach the prompt and name the
  style, long rules are cut and replies cleaned and capped.
- `tests/explain/test_explain_service.py`: answer from the rule text, cached per rule version, a new
  revision explained again, clear errors, a failure is not saved, another style is made again,
  background explaining once per rule, a click goes first, a pause after a failure, no background
  without a bus.
- `tests/dashboard/test_dash_config.py`: the three settings and their checks.
- `tests/dashboard/test_dash_explain.py`: the dashboard side.

## Deviations and known limits

- `Explainer.explain` receives the whole `Alert`, addresses included; each adapter must leave them
  out of what it sends, and the Ollama adapter does.
- The answer is cached per (sid, rev), not per alert, so it cannot speak about one alert's traffic.
- A model removed from Ollama after the first check is reported only when `/api/generate` fails.
- The background cannot interrupt a run already under way; a click can wait for it (about 5 s warm
  with an 8B model on a GPU).
- A rule dropped by the background (queue full, or the model failed) is explained only when
  clicked, until Snorty restarts.
- Changing the model does not remake kept answers; they still show the model that wrote them.
