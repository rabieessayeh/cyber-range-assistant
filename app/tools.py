"""Whitelisted tools exposed to the LLM (and to POST /tools).

Each tool has a Pydantic argument model (whose JSON schema is sent to the LLM),
a function over the deterministic engine, and a `compact` view of its result:
the LLM only sees the compact view (no YAML, no full matrix), while the UI gets
the full result. `run_tool` never raises: bad input becomes {"error": ...}.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, ValidationError, model_validator

from . import library as lib
from .attack import AttackData
from .environments import PRESETS
from .scenarios import (
    ScenarioError,
    aggregate_scenarios,
    build_scenario,
    coverage,
    gap_analysis,
    validate_scenario,
)


def _normalise_ref(value: Any) -> Any:
    """'t1078 @ Persistence' -> 'T1078@persistence' (only the format, not the existence)."""
    if not isinstance(value, str):
        return value
    tid, sep, tactic = value.replace(" ", "").partition("@")
    return tid.upper() + (sep + tactic.lower() if sep else "")


# Field comes first so the pattern shows in the JSON schema; the BeforeValidator still runs first.
TechniqueRef = Annotated[
    str,
    Field(pattern=r"^T\d{4}(\.\d{3})?(@[a-z]+(-[a-z]+)*)?$", description="e.g. T1078 or T1078@persistence"),
    BeforeValidator(_normalise_ref),
]
TechniqueId = Annotated[str, Field(pattern=r"^T\d{4}(\.\d{3})?$"), BeforeValidator(_normalise_ref)]
ScenarioId = Annotated[str, BeforeValidator(lambda v: v.strip().upper() if isinstance(v, str) else v)]
Level = Literal["beginner", "intermediate", "advanced"]
Audience = Literal["soc-analyst", "blue-team", "red-team", "purple-team", "management"]
Environment = Literal[tuple(PRESETS)]  # type: ignore[valid-type]


class Args(BaseModel):
    model_config = ConfigDict(extra="forbid")


class BuildScenarioArgs(Args):
    title: str = Field(min_length=3, max_length=120)
    techniques: list[TechniqueRef] = Field(
        min_length=1,
        max_length=20,
        description="ATT&CK technique IDs; append @tactic to force a tactic, e.g. T1078@persistence",
    )
    level: Level = "intermediate"
    audience: Audience = "soc-analyst"
    environment: Environment = "small-enterprise"  # type: ignore[valid-type]
    objectives: list[str] | None = Field(default=None, max_length=8)


class ValidateScenarioArgs(Args):
    scenario_id: ScenarioId | None = Field(
        default=None, description="library or previously built scenario ID"
    )
    scenario: dict[str, Any] | None = Field(default=None, description="a full scenario object (API use)")
    scenario_yaml: str | None = Field(default=None, max_length=200_000, description="a scenario as YAML text")

    @model_validator(mode="after")
    def _exactly_one(self) -> ValidateScenarioArgs:
        given = [x for x in (self.scenario_id, self.scenario, self.scenario_yaml) if x is not None]
        if len(given) != 1:
            raise ValueError("give exactly one of scenario_id, scenario, scenario_yaml")
        return self


class CoverageArgs(Args):
    scenario_ids: list[ScenarioId] | None = Field(default=None, description="default: whole library")


class GapAnalysisArgs(Args):
    scenario_ids: list[ScenarioId] | None = Field(default=None, description="default: whole library")
    platforms: list[str] | None = Field(default=None, description="ATT&CK platforms, e.g. Windows, Linux")
    required_techniques: list[TechniqueId] | None = Field(
        default=None, max_length=100, description="threat profile: techniques that must be trained"
    )


class AggregateArgs(Args):
    scenario_ids: list[ScenarioId] = Field(min_length=2, max_length=10)
    title: str = Field(min_length=3, max_length=120)


class SearchArgs(Args):
    query: str = Field(min_length=2, max_length=100)
    tactic: str | None = Field(default=None, description="tactic shortname, e.g. credential-access")
    platform: str | None = None
    limit: int = Field(default=10, ge=1, le=25)


class GetTechniqueArgs(Args):
    technique_id: TechniqueId


class ListScenariosArgs(Args):
    pass


@dataclass
class ToolContext:
    """State available to the tools during one request.

    `session` holds scenarios built or aggregated during the request, so a later
    tool call can validate or aggregate them by ID; the library on disk is read-only.
    """

    attack: AttackData
    library: list[dict[str, Any]]
    session: dict[str, dict[str, Any]] = field(default_factory=dict)

    def all_scenarios(self) -> list[dict[str, Any]]:
        return self.library + list(self.session.values())

    def select(self, ids: list[str] | None) -> list[dict[str, Any]]:
        return lib.select(self.library, None) if not ids else lib.select(self.all_scenarios(), ids)

    def next_id(self) -> str:
        return lib.next_id(self.all_scenarios())


# --------------------------------------------------------------------------- tool functions


def _scenario_result(ctx: ToolContext, scenario: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "scenario": scenario,
        "yaml": lib.to_yaml(scenario),
        "validation": validate_scenario(ctx.attack, scenario),
        **extra,
    }


def t_build_scenario(ctx: ToolContext, a: BuildScenarioArgs) -> dict[str, Any]:
    scenario = build_scenario(
        ctx.attack,
        title=a.title,
        techniques=a.techniques,
        level=a.level,
        audience=a.audience,
        environment=a.environment,
        objectives=a.objectives,
        scenario_id=ctx.next_id(),
    )
    ctx.session[scenario["id"]] = scenario
    return _scenario_result(ctx, scenario)


def t_validate_scenario(ctx: ToolContext, a: ValidateScenarioArgs) -> dict[str, Any]:
    if a.scenario_id:
        scenario = ctx.select([a.scenario_id])[0]
    elif a.scenario is not None:
        scenario = a.scenario
    else:
        try:
            scenario = yaml.safe_load(a.scenario_yaml or "")
        except yaml.YAMLError as exc:
            raise ScenarioError(f"invalid YAML: {exc}") from None
    return {
        "scenario_id": scenario.get("id") if isinstance(scenario, dict) else None,
        **validate_scenario(ctx.attack, scenario),
    }


def t_coverage(ctx: ToolContext, a: CoverageArgs) -> dict[str, Any]:
    return coverage(ctx.attack, ctx.select(a.scenario_ids))


def t_gap_analysis(ctx: ToolContext, a: GapAnalysisArgs) -> dict[str, Any]:
    if a.platforms:
        known = {p.lower(): p for t in ctx.attack.techniques.values() for p in t["platforms"]}
        unknown = [p for p in a.platforms if p.lower() not in known]
        if unknown:
            raise ScenarioError(f"unknown platforms {unknown}; known: {sorted(known.values())}")
        platforms = [known[p.lower()] for p in a.platforms]
    else:
        platforms = None
    return gap_analysis(ctx.attack, ctx.select(a.scenario_ids), platforms, a.required_techniques)


def t_aggregate(ctx: ToolContext, a: AggregateArgs) -> dict[str, Any]:
    result = aggregate_scenarios(ctx.attack, ctx.select(a.scenario_ids), a.title, scenario_id=ctx.next_id())
    ctx.session[result["scenario"]["id"]] = result["scenario"]
    return _scenario_result(ctx, result["scenario"], report=result["report"])


def t_search(ctx: ToolContext, a: SearchArgs) -> dict[str, Any]:
    if a.tactic and not ctx.attack.has_tactic(a.tactic):
        raise ScenarioError(f"unknown tactic {a.tactic!r}; known: {ctx.attack.tactic_order}")
    return {"results": ctx.attack.search(a.query, a.tactic, a.platform, a.limit)}


def t_get_technique(ctx: ToolContext, a: GetTechniqueArgs) -> dict[str, Any]:
    if ctx.attack.technique(a.technique_id) is None:
        replaced = ctx.attack.revoked.get(a.technique_id)
        return {"error": ctx.attack.unknown_technique_message(a.technique_id), "replaced_by": replaced}
    tech = ctx.attack.techniques[a.technique_id]
    return {
        **ctx.attack.summary(a.technique_id),
        "parent": tech.get("parent"),
        "subtechniques": ctx.attack.subtechniques(a.technique_id),
        "attack_version": ctx.attack.version,
    }


def t_list_scenarios(ctx: ToolContext, a: ListScenariosArgs) -> dict[str, Any]:
    return {"scenarios": [scenario_summary(s) for s in ctx.all_scenarios()]}


def scenario_summary(s: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": s["id"],
        "title": s["title"],
        "level": s["level"],
        "audience": s["audience"],
        "duration_minutes": s["duration_minutes"],
        "environment": s["environment"].get("preset", "custom"),
        "techniques": [st["technique"] for st in s["steps"]],
    }


# --------------------------------------------------------------------------- compact views for the LLM


def _compact_scenario(r: dict[str, Any]) -> dict[str, Any]:
    s = r["scenario"]
    out = {
        "id": s["id"],
        "title": s["title"],
        "level": s["level"],
        "audience": s["audience"],
        "duration_minutes": s["duration_minutes"],
        "steps": [
            {"id": st["id"], "tactic": st["tactic"], "technique": st["technique"], "host": st["target_host"]}
            for st in s["steps"]
        ],
        "validation": r["validation"],
        "note": "Full YAML is shown to the user in the UI.",
    }
    if "report" in r:
        out["report"] = r["report"]
    return out


def _compact_coverage(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "totals": r["totals"],
        "techniques_per_tactic": {c["shortname"]: [t["id"] for t in c["techniques"]] for c in r["tactics"]},
        "note": "The full matrix is shown to the user in the UI.",
    }


def _identity(r: dict[str, Any]) -> dict[str, Any]:
    return r


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    args: type[Args]
    fn: Callable[[ToolContext, Any], dict[str, Any]]
    compact: Callable[[dict[str, Any]], dict[str, Any]] = _identity


TOOLS: dict[str, Tool] = {
    t.name: t
    for t in [
        Tool(
            "build_scenario",
            "Build a planning-level training scenario from ATT&CK technique IDs. Steps are ordered along the "
            "kill chain; hosts, expected detections, trainee tasks and duration are computed and validated. "
            "Look IDs up with search_techniques first if unsure.",
            BuildScenarioArgs,
            t_build_scenario,
            _compact_scenario,
        ),
        Tool(
            "validate_scenario",
            "Validate a scenario (schema and ATT&CK semantics) and list errors and warnings.",
            ValidateScenarioArgs,
            t_validate_scenario,
        ),
        Tool(
            "coverage",
            "ATT&CK tactic x technique coverage matrix of the scenario library (or of given scenario IDs).",
            CoverageArgs,
            t_coverage,
            _compact_coverage,
        ),
        Tool(
            "gap_analysis",
            "Find uncovered and thinly covered tactics of the library with suggested techniques, optionally "
            "for given platforms, and which techniques of a threat profile no scenario covers.",
            GapAnalysisArgs,
            t_gap_analysis,
        ),
        Tool(
            "aggregate_scenarios",
            "Merge two or more scenarios into one exercise: environments merged, duplicate steps removed, "
            "steps renumbered; reports host conflicts and mixed audiences.",
            AggregateArgs,
            t_aggregate,
            _compact_scenario,
        ),
        Tool(
            "search_techniques",
            "Search ATT&CK techniques by words in their ID or name, optionally by tactic and platform.",
            SearchArgs,
            t_search,
        ),
        Tool(
            "get_technique",
            "Details of one ATT&CK technique: tactics, platforms, detecting data components, sub-techniques.",
            GetTechniqueArgs,
            t_get_technique,
        ),
        Tool(
            "list_scenarios",
            "List the scenarios of the library (ID, title, level, audience, techniques).",
            ListScenariosArgs,
            t_list_scenarios,
        ),
    ]
}


def _schema(model: type[Args]) -> dict[str, Any]:
    schema = model.model_json_schema()
    schema.pop("title", None)
    for prop in schema.get("properties", {}).values():
        prop.pop("title", None)
    return schema


# OpenAI "tools" parameter.
TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {"name": t.name, "description": t.description, "parameters": _schema(t.args)},
    }
    for t in TOOLS.values()
]


def _format_validation_error(exc: ValidationError) -> str:
    parts = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"]) or "(args)"
        parts.append(f"{loc}: {re.sub(r'^Value error, ', '', err['msg'])}")
    return "invalid arguments: " + "; ".join(parts)


def run_tool(ctx: ToolContext, name: str, args: dict[str, Any] | None) -> dict[str, Any]:
    """Run a whitelisted tool; any failure is returned as {"error": message}."""
    tool = TOOLS.get(name)
    if tool is None:
        return {"error": f"unknown tool {name!r}; available: {sorted(TOOLS)}"}
    if not isinstance(args, dict):
        return {"error": "arguments must be a JSON object"}
    try:
        parsed = tool.args.model_validate(args)
        return tool.fn(ctx, parsed)
    except ValidationError as exc:
        return {"error": _format_validation_error(exc)}
    except (ScenarioError, KeyError) as exc:
        return {"error": str(exc).strip("'\"")}
