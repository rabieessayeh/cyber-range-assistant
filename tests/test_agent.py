"""Agent loop against a fake OpenAI client: no network, deterministic replies."""

from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest
from openai import APIConnectionError, AuthenticationError, RateLimitError

from app import agent as agent_module
from app.agent import SYSTEM_PROMPT, LLMError, run_agent
from app.config import Settings
from app.tools import ToolContext


def tool_call(name: str, args: dict | str, call_id: str = "c1") -> SimpleNamespace:
    raw = args if isinstance(args, str) else json.dumps(args)
    return SimpleNamespace(id=call_id, type="function", function=SimpleNamespace(name=name, arguments=raw))


def reply(content: str | None = None, calls: list | None = None) -> SimpleNamespace:
    message = SimpleNamespace(content=content, tool_calls=calls)
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


class FakeClient:
    """Mimics `client.chat.completions.create`, replaying scripted replies or raising errors."""

    def __init__(self, replies: list) -> None:
        self.replies = list(replies)
        self.requests: list[dict] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **kwargs):
        self.requests.append(json.loads(json.dumps(kwargs, default=str)))
        item = self.replies.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture()
def settings() -> Settings:
    return Settings(llm_api_key="test", max_steps=6, llm_max_retries=2, llm_retry_base_s=0, _env_file=None)


@pytest.fixture()
def ctx(attack, library) -> ToolContext:
    return ToolContext(attack, library)


def _http_error(cls, status: int):
    request = httpx.Request("POST", "https://llm.test/v1/chat/completions")
    response = httpx.Response(status, request=request, headers={"retry-after": "0"})
    return cls("error", response=response, body=None)


def test_tool_loop_builds_scenario_and_returns_ui(settings, ctx):
    client = FakeClient(
        [
            reply(calls=[tool_call("search_techniques", {"query": "password spraying"})]),
            reply(
                calls=[
                    tool_call("build_scenario", {"title": "Spray", "techniques": ["T1110.003", "T1021.001"]})
                ]
            ),
            reply("Built SCN-006 with 2 steps; validation passed."),
        ]
    )
    out = run_agent("Plan a password spraying exercise", ctx, settings, client)
    assert out["answer"].startswith("Built SCN-006")
    assert [t["tool"] for t in out["trace"]] == ["search_techniques", "build_scenario"]
    assert all(t["ok"] for t in out["trace"])
    assert out["ui"]["yaml"].startswith("id: SCN-006")
    assert out["ui"]["highlight"] == ["T1110.003", "T1021.001"]
    # Request parameters and what the model was shown.
    first = client.requests[0]
    assert first["temperature"] == 0 and first["tool_choice"] == "auto"
    assert first["messages"][0]["content"] == SYSTEM_PROMPT.format(version=ctx.attack.version)
    tool_msgs = [m for m in client.requests[-1]["messages"] if m["role"] == "tool"]
    assert "id: SCN-006" not in tool_msgs[-1]["content"]  # YAML withheld from the LLM


def test_system_prompt_forbids_attack_content():
    prompt = SYSTEM_PROMPT.lower()
    for phrase in ("refuse", "exploit code", "malware", "shell commands", "planning level"):
        assert phrase in prompt


def test_bad_tool_arguments_are_reported_back(settings, ctx):
    client = FakeClient(
        [
            reply(calls=[tool_call("build_scenario", "{not json")]),
            reply(calls=[tool_call("delete_everything", {})]),
            reply("Sorry, I could not build it."),
        ]
    )
    out = run_agent("q", ctx, settings, client)
    assert [t["ok"] for t in out["trace"]] == [False, False]
    assert "unknown tool" in out["trace"][1]["error"]
    tool_msgs = [m for m in client.requests[-1]["messages"] if m["role"] == "tool"]
    assert all("error" in json.loads(m["content"]) for m in tool_msgs)


def test_step_limit_forces_a_final_answer(settings, ctx):
    loop = [reply(calls=[tool_call("coverage", {}, f"c{i}")]) for i in range(5)]
    client = FakeClient([*loop, reply("Here is the coverage.")])
    out = run_agent("q", ctx, settings, client)
    assert len(client.requests) == settings.max_steps
    assert client.requests[-1]["tool_choice"] == "none"
    assert out["answer"] == "Here is the coverage." and len(out["trace"]) == 5


def test_empty_final_answer_gets_fallback(settings, ctx):
    out = run_agent("q", ctx, settings, FakeClient([reply("")]))
    assert "could not produce an answer" in out["answer"]


def test_retries_on_429_then_succeeds(settings, ctx, monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr(agent_module.time, "sleep", sleeps.append)
    client = FakeClient([_http_error(RateLimitError, 429), reply("ok")])
    assert run_agent("q", ctx, settings, client)["answer"] == "ok"
    assert sleeps == [0.0]  # Retry-After: 0 header honoured


def test_gives_up_after_retries(settings, ctx, monkeypatch):
    monkeypatch.setattr(agent_module.time, "sleep", lambda s: None)
    request = httpx.Request("POST", "https://llm.test")
    client = FakeClient([APIConnectionError(request=request)] * 3)
    with pytest.raises(LLMError):
        run_agent("q", ctx, settings, client)
    assert len(client.requests) == settings.llm_max_retries + 1


def test_non_retryable_error_maps_to_llm_error(settings, ctx):
    client = FakeClient([_http_error(AuthenticationError, 401)])
    with pytest.raises(LLMError):
        run_agent("q", ctx, settings, client)
    assert len(client.requests) == 1
