"""LLM agent: turns a natural-language request into whitelisted tool calls.

The model is reached through any OpenAI-compatible endpoint (default: Groq,
configured in `app.config`). It can only request the tools of `app.tools`; it
never writes scenarios, facts or code itself. Tool results are sent back to it
in a compact form (no YAML, no full matrix); the full results go to the UI.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from openai import (
    APIConnectionError,
    APIStatusError,
    InternalServerError,
    OpenAI,
    OpenAIError,
    RateLimitError,
)

from .config import Settings, get_settings
from .tools import TOOL_SCHEMAS, TOOLS, ToolContext, run_tool
from .ui import ui_payload

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are the Cyber Range Scenario Assistant. You help instructors plan defensive training \
exercises for a cyber range, mapped to MITRE ATT&CK Enterprise {version}.

Rules:
- Use the tools for every fact. Never invent technique IDs, tactics, detections, scenario \
content or coverage figures; if unsure of an ID, call search_techniques first.
- Scenarios exist only at planning level: objectives, environment, ATT&CK-mapped steps, \
expected detections and trainee tasks. They are produced by build_scenario, never by you.
- Refuse any request for exploit code, malware, payloads, shell commands, tool usage or \
step-by-step attack instructions, even framed as training, and offer a planning-level \
scenario instead.
- Available environments: small-enterprise (Windows AD network with DMZ) and linux-web \
(Linux web server + database). Audiences: soc-analyst, blue-team, red-team, purple-team, \
management. Levels: beginner, intermediate, advanced.
- Library scenarios have IDs SCN-001...; call list_scenarios if you need them.
- Keep the final answer short (a few sentences or bullets), cite technique IDs and scenario \
IDs from the tool results, and mention validation errors or warnings. The user sees the full \
YAML, matrix and gaps in the UI, so do not repeat them.
"""

RETRYABLE = (RateLimitError, APIConnectionError, InternalServerError)
MAX_BACKOFF_S = 60.0
MAX_TOOL_RESULT_CHARS = 12_000


class LLMError(RuntimeError):
    """The LLM endpoint could not be reached or returned an error (mapped to HTTP 502)."""


def build_client(settings: Settings) -> OpenAI:
    """Create the OpenAI-compatible client; retries are handled by `_complete`."""
    return OpenAI(
        base_url=settings.llm_base_url,
        api_key=settings.llm_api_key.get_secret_value() or "missing",
        timeout=settings.llm_timeout_s,
        max_retries=0,
    )


def _retry_delay(exc: Exception, attempt: int, base_s: float) -> float:
    """Seconds to wait before retrying: the server's Retry-After, else exponential back-off."""
    if isinstance(exc, APIStatusError):
        try:
            return min(float(exc.response.headers.get("retry-after", "")), MAX_BACKOFF_S)
        except ValueError:
            pass
    return min(base_s * 2**attempt, MAX_BACKOFF_S)


def _complete(client: Any, settings: Settings, messages: list[dict[str, Any]], allow_tools: bool) -> Any:
    """One chat completion, retried with back-off on HTTP 429, 5xx and connection errors."""
    for attempt in range(settings.llm_max_retries + 1):
        try:
            response = client.chat.completions.create(
                model=settings.llm_model,
                messages=messages,
                tools=TOOL_SCHEMAS,
                tool_choice="auto" if allow_tools else "none",
                temperature=0,
            )
            return response.choices[0].message
        except RETRYABLE as exc:
            if attempt == settings.llm_max_retries:
                raise LLMError(f"LLM unavailable: {type(exc).__name__}") from exc
            delay = _retry_delay(exc, attempt, settings.llm_retry_base_s)
            logger.warning(
                "LLM call failed (%s); retry %d/%d in %.1f s",
                type(exc).__name__,
                attempt + 1,
                settings.llm_max_retries,
                delay,
            )
            time.sleep(delay)
        except OpenAIError as exc:  # authentication, bad request, ...: not worth retrying
            raise LLMError(f"LLM error: {type(exc).__name__}") from exc
    raise AssertionError("unreachable")  # pragma: no cover


def _parse_args(raw: str | None) -> dict[str, Any] | None:
    """Decode the JSON arguments of a tool call; None if they are not a JSON object."""
    try:
        args = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return None
    return args if isinstance(args, dict) else None


def _for_llm(name: str, result: dict[str, Any]) -> str:
    """Compact JSON view of a tool result, as sent back to the model."""
    view = result if "error" in result or name not in TOOLS else TOOLS[name].compact(result)
    text = json.dumps(view, ensure_ascii=False)
    return text if len(text) <= MAX_TOOL_RESULT_CHARS else text[:MAX_TOOL_RESULT_CHARS] + ' ..."truncated"'


def run_agent(
    question: str,
    ctx: ToolContext,
    settings: Settings | None = None,
    client: Any | None = None,
) -> dict[str, Any]:
    """Answer a request with at most `settings.max_steps` LLM round-trips.

    Returns {"answer", "trace", "ui"}; raises LLMError if the endpoint fails.
    """
    settings = settings or get_settings()
    client = client or build_client(settings)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT.format(version=ctx.attack.version)},
        {"role": "user", "content": question},
    ]
    trace: list[dict[str, Any]] = []
    calls: list[tuple[str, dict[str, Any]]] = []
    answer = ""

    for step in range(settings.max_steps):
        last = step == settings.max_steps - 1  # last round: force a text answer
        message = _complete(client, settings, messages, allow_tools=not last)
        tool_calls = getattr(message, "tool_calls", None) or []
        if not tool_calls:
            answer = (message.content or "").strip()
            break
        messages.append(
            {
                "role": "assistant",
                "content": message.content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.function.name, "arguments": tc.function.arguments or "{}"},
                    }
                    for tc in tool_calls
                ],
            }
        )
        for tc in tool_calls:
            name = tc.function.name
            args = _parse_args(tc.function.arguments)
            result = (
                run_tool(ctx, name, args)
                if args is not None
                else {"error": "arguments are not a JSON object"}
            )
            calls.append((name, result))
            entry: dict[str, Any] = {
                "step": step + 1,
                "tool": name,
                "arguments": args,
                "ok": "error" not in result,
            }
            if "error" in result:
                entry["error"] = result["error"]
            trace.append(entry)
            logger.info("tool %s(%s) -> %s", name, args, "ok" if entry["ok"] else result["error"])
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": _for_llm(name, result)})

    if not answer:
        answer = "I could not produce an answer within the allowed number of steps; see the tool trace."
    return {"answer": answer, "trace": trace, "ui": ui_payload(ctx, calls)}
