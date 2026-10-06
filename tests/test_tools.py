"""Tool registry: argument validation, error handling, compact views, UI payload."""

from __future__ import annotations

import json

import pytest

from app.agent import _for_llm
from app.library import to_yaml
from app.tools import TOOL_SCHEMAS, TOOLS, ToolContext, run_tool
from app.ui import ui_payload


@pytest.fixture()
def ctx(attack, library) -> ToolContext:
    return ToolContext(attack, library)


def test_every_tool_has_an_openai_schema():
    names = {s["function"]["name"] for s in TOOL_SCHEMAS}
    assert names == set(TOOLS)
    for schema in TOOL_SCHEMAS:
        params = schema["function"]["parameters"]
        assert params["type"] == "object" and params["additionalProperties"] is False
    build = next(s for s in TOOL_SCHEMAS if s["function"]["name"] == "build_scenario")
    assert "pattern" in build["function"]["parameters"]["properties"]["techniques"]["items"]


def test_unknown_tool(ctx):
    assert "unknown tool" in run_tool(ctx, "run_shell", {"cmd": "id"})["error"]


@pytest.mark.parametrize(
    ("name", "args", "message"),
    [
        ("build_scenario", {"title": "ok title", "techniques": ["rm -rf /"]}, "should match pattern"),
        ("build_scenario", {"title": "ok title", "techniques": ["T1486"], "level": "god"}, "level"),
        ("build_scenario", {"title": "ok title", "techniques": ["T1486"], "extra": 1}, "extra"),
        ("build_scenario", {"title": "ok title", "techniques": ["T9999"]}, "unknown technique"),
        ("validate_scenario", {}, "exactly one"),
        ("aggregate_scenarios", {"scenario_ids": ["SCN-001"], "title": "One"}, "at least 2"),
        ("coverage", {"scenario_ids": ["SCN-999"]}, "unknown scenario ids"),
        ("gap_analysis", {"platforms": ["Amiga"]}, "unknown platforms"),
        ("search_techniques", {"query": "shell", "tactic": "hacking"}, "unknown tactic"),
    ],
)
def test_bad_arguments_return_errors(ctx, name, args, message):
    result = run_tool(ctx, name, args)
    assert message in result["error"]


def test_non_dict_arguments(ctx):
    assert "error" in run_tool(ctx, "coverage", None)  # type: ignore[arg-type]


def test_build_normalises_refs_and_registers_session_scenario(ctx):
    result = run_tool(
        ctx, "build_scenario", {"title": "Test run", "techniques": ["t1566.001", "T1078 @ Persistence"]}
    )
    assert result["validation"]["valid"]
    scn = result["scenario"]
    assert scn["id"] == "SCN-006"  # next free ID after the library
    assert [(s["technique"], s["tactic"]) for s in scn["steps"]] == [
        ("T1566.001", "initial-access"),
        ("T1078", "persistence"),
    ]
    # A later call in the same request can use it by ID.
    agg = run_tool(ctx, "aggregate_scenarios", {"scenario_ids": ["scn-006", "SCN-001"], "title": "Merged"})
    assert agg["scenario"]["id"] == "SCN-007"
    assert agg["report"]["removed_duplicates"]


def test_validate_by_id_object_and_yaml(ctx, library):
    assert run_tool(ctx, "validate_scenario", {"scenario_id": "SCN-001"})["valid"]
    assert run_tool(ctx, "validate_scenario", {"scenario": library[0]})["valid"]
    assert run_tool(ctx, "validate_scenario", {"scenario_yaml": to_yaml(library[0])})["valid"]
    assert "invalid YAML" in run_tool(ctx, "validate_scenario", {"scenario_yaml": "id: [oops"})["error"]


def test_get_technique_and_revoked_hint(ctx, attack):
    tech = run_tool(ctx, "get_technique", {"technique_id": "T1566"})
    assert "T1566.001" in tech["subtechniques"]
    old, new = next(iter(attack.revoked.items()))
    revoked = run_tool(ctx, "get_technique", {"technique_id": old})
    assert revoked["replaced_by"] == new and "revoked" in revoked["error"]


def test_compact_views_withhold_yaml_and_matrix(ctx):
    built = run_tool(ctx, "build_scenario", {"title": "Compact", "techniques": ["T1486"]})
    text = _for_llm("build_scenario", built)
    assert "yaml" not in json.loads(text) and "trainee_tasks" not in text
    cov = json.loads(_for_llm("coverage", run_tool(ctx, "coverage", {})))
    assert "tactics" not in cov and cov["totals"]["tactics"] == 15


def test_ui_payload_collects_full_results(ctx):
    calls = [
        (
            "build_scenario",
            run_tool(ctx, "build_scenario", {"title": "UI test", "techniques": ["T1486", "T1566.001"]}),
        ),
        ("gap_analysis", run_tool(ctx, "gap_analysis", {})),
        ("search_techniques", {"error": "ignored"}),
    ]
    ui = ui_payload(ctx, calls)
    assert ui["yaml"].startswith("id: SCN-006")
    assert ui["highlight"] == ["T1566.001", "T1486"]
    assert ui["gaps"]["uncovered_tactics"]
    assert "SCN-006" in ui["matrix"]["scenarios"] and ui["session_scenarios"] == ["SCN-006"]
