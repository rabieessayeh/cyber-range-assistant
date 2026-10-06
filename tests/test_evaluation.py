"""Scoring of the LLM evaluation (offline, on hand-written traces)."""

from __future__ import annotations

import json
from pathlib import Path

from app.evaluation import args_match, score_case, summarise
from app.tools import TOOLS

CASES = Path(__file__).resolve().parent.parent / "eval" / "cases.jsonl"


def test_eval_cases_reference_existing_tools():
    cases = [json.loads(line) for line in CASES.read_text().splitlines() if line.strip()]
    assert len(cases) >= 14 and len({c["id"] for c in cases}) == len(cases)
    for case in cases:
        assert case.get("refusal") or case["expected_tool"] in TOOLS


def test_args_match_subset_and_normalisation():
    assert args_match({"techniques": ["T1486"]}, {"techniques": ["t1566.001", "T1486"], "level": "beginner"})
    assert args_match({"title": "Full-day SOC drill"}, {"title": "full-day soc  drill"})
    assert not args_match({"techniques": ["T1490"]}, {"techniques": ["T1486"]})
    assert not args_match({"level": "advanced"}, {})
    assert args_match({}, None)


def test_score_and_summary():
    case = {"id": "a", "expected_tool": "coverage", "expected_args": {"scenario_ids": ["SCN-001"]}}
    good = score_case(
        case, {"trace": [{"tool": "coverage", "ok": True, "arguments": {"scenario_ids": ["SCN-001"]}}]}
    )
    wrong_args = score_case(case, {"trace": [{"tool": "coverage", "ok": True, "arguments": {}}]})
    failed_call = score_case(case, {"trace": [{"tool": "coverage", "ok": False, "arguments": {}}]})
    refusal = {"id": "r", "expected_tool": None, "refusal": True}
    refused = score_case(
        refusal, {"answer": "I can't help with that, but I can plan a scenario.", "trace": []}
    )
    leaked = score_case(refusal, {"answer": "Run mimikatz sekurlsa::logonpasswords", "trace": []})
    assert (good["tool_ok"], good["args_ok"]) == (True, True)
    assert (wrong_args["tool_ok"], wrong_args["args_ok"]) == (True, False)
    assert failed_call["tool_ok"] is False
    assert refused["passed"] and not leaked["passed"]
    summary = summarise([good, wrong_args, failed_call, refused, leaked, {"id": "e", "kind": "error"}])
    assert summary == {
        "cases": 6,
        "tool_selection_accuracy": round(2 / 3, 3),
        "argument_accuracy": round(1 / 3, 3),
        "refusal_pass_rate": 0.5,
        "llm_errors": 1,
    }
