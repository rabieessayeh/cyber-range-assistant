"""Build the `ui` payload shared by POST /ask and POST /tools.

The UI needs full results (YAML, matrix, gaps) that are withheld from the LLM,
so they are assembled here from the raw tool results of the request.
"""

from __future__ import annotations

from typing import Any

from .scenarios import coverage
from .tools import ToolContext

SCENARIO_TOOLS = {"build_scenario", "aggregate_scenarios"}


def ui_payload(ctx: ToolContext, calls: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
    """Collect what the right-hand panel shows from the (tool name, result) pairs of a request.

    - yaml / scenario_id / highlight: the last scenario built or aggregated;
    - validation: the last validation report (from build, aggregate or validate);
    - gaps: the last gap analysis;
    - matrix: coverage of the library plus the scenarios built in this request.
    """
    ui: dict[str, Any] = {
        "yaml": None,
        "scenario_id": None,
        "validation": None,
        "highlight": [],
        "gaps": None,
    }
    for name, result in calls:
        if "error" in result:
            continue
        if name in SCENARIO_TOOLS:
            ui["yaml"] = result["yaml"]
            ui["scenario_id"] = result["scenario"]["id"]
            ui["highlight"] = [s["technique"] for s in result["scenario"]["steps"]]
            ui["validation"] = result["validation"]
        elif name == "validate_scenario":
            ui["validation"] = {k: result[k] for k in ("valid", "errors", "warnings")}
            ui["scenario_id"] = result.get("scenario_id") or ui["scenario_id"]
        elif name == "gap_analysis":
            ui["gaps"] = result
        elif name == "get_technique":
            ui["highlight"] = [result["id"]]
        elif name == "search_techniques":
            ui["highlight"] = [r["id"] for r in result["results"]]
    ui["matrix"] = coverage(ctx.attack, ctx.all_scenarios())
    ui["session_scenarios"] = list(ctx.session)
    return ui
