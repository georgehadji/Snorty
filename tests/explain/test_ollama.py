from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

import pytest

from snorty.core.models import Alert
from snorty.explain import ExplainError, OllamaExplainer
from snorty.explain.ollama import OLLAMA_URL, build_prompt, clean

LOCAL = {"models": [{"name": "qwen3:8b", "model": "qwen3:8b"}]}
CLOUD = {"models": [{"name": "gemma:cloud", "remote_host": "https://ollama.com"}]}


def make_alert(msg: str = "ET TOR relay") -> Alert:
    return Alert(
        ts=datetime(2026, 11, 17, 12, tzinfo=UTC), gid=1, sid=2522401, rev=6440, msg=msg,
        classification="Misc Attack", priority=2, proto="TCP", src_ip="37.97.194.173",
        src_port=9001, dst_ip="192.168.1.25", dst_port=50303, raw="raw",
    )  # fmt: skip


class FakeOllama:
    def __init__(self, tags: Mapping[str, Any] = LOCAL, reply: Any = None) -> None:
        self.tags = tags
        self.reply = {"response": "It looks for X."} if reply is None else reply
        self.calls: list[tuple[str, Mapping[str, object] | None]] = []

    def __call__(
        self, url: str, payload: Mapping[str, object] | None, timeout: float
    ) -> Mapping[str, Any]:
        self.calls.append((url, payload))
        return self.tags if url.endswith("/api/tags") else self.reply


async def test_a_local_model_explains_the_rule() -> None:
    fake = FakeOllama()
    text = await OllamaExplainer("qwen3:8b", transport=fake).explain("alert tcp", make_alert())
    assert text == "It looks for X."
    url, payload = fake.calls[-1]
    assert url == f"{OLLAMA_URL}/api/generate" and OLLAMA_URL.startswith("http://127.0.0.1:")
    assert payload and payload["model"] == "qwen3:8b" and payload["stream"] is False
    assert payload["think"] is False


async def test_a_remote_model_is_refused_before_anything_is_sent() -> None:
    fake = FakeOllama(tags=CLOUD)
    with pytest.raises(ExplainError, match="remote server"):
        await OllamaExplainer("gemma:cloud", transport=fake).explain("rule", make_alert())
    assert [u for u, _ in fake.calls] == [f"{OLLAMA_URL}/api/tags"]  # never reached /generate


async def test_a_missing_model_is_reported() -> None:
    with pytest.raises(ExplainError, match="not installed"):
        await OllamaExplainer("nope", transport=FakeOllama()).explain("rule", make_alert())


async def test_the_local_check_is_made_once() -> None:
    fake = FakeOllama()
    ex = OllamaExplainer("qwen3:8b", transport=fake)
    await ex.explain("rule", make_alert())
    await ex.explain("rule", make_alert())
    assert sum(u.endswith("/api/tags") for u, _ in fake.calls) == 1


@pytest.mark.parametrize(
    "reply", [{}, {"response": ""}, {"response": 5}, {"response": " <think>x</think> "}]
)
async def test_an_empty_or_odd_reply_is_an_error(reply: Any) -> None:
    ex = OllamaExplainer("qwen3:8b", transport=FakeOllama(reply=reply))
    with pytest.raises(ExplainError, match="no answer"):
        await ex.explain("r", make_alert())


def test_the_prompt_has_the_rule_but_no_addresses() -> None:
    a = make_alert()
    prompt = build_prompt("alert tcp any any -> any any (sid:1;)", a)
    assert "ET TOR relay" in prompt and "sid:1;" in prompt
    assert a.src_ip not in prompt and a.dst_ip not in prompt


def test_the_prompt_asks_for_the_language_and_reader() -> None:
    prompt = build_prompt("rule", make_alert(), language="Greek", audience="analyst")
    assert "Write the answer in Greek." in prompt and "a security analyst" in prompt
    assert "home computer user" in build_prompt("rule", make_alert())


async def test_the_style_reaches_the_model_and_names_the_cache() -> None:
    fake = FakeOllama()
    ex = OllamaExplainer("qwen3:8b", language="Greek", audience="office", transport=fake)
    assert ex.style == "Greek/office"
    assert OllamaExplainer("qwen3:8b").style == "English/home"  # what older answers were
    await ex.explain("rule", make_alert())
    prompt = fake.calls[-1][1]["prompt"]  # type: ignore[index]
    assert "in Greek" in prompt and "small office" in prompt
    with pytest.raises(ValueError, match="audience"):
        OllamaExplainer("qwen3:8b", audience="boss")


def test_a_long_rule_is_cut_and_the_reply_is_cleaned_and_capped() -> None:
    assert "x" * 5000 not in build_prompt("x" * 5000, make_alert())
    assert clean("<think>secret plan</think>Answer.") == "Answer."
    assert len(clean("y" * 10_000)) <= 3001
