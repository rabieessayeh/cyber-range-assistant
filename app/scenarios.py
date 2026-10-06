"""Deterministic scenario engine: build, validate, cover, gap-analyse, aggregate.

Every function here is plain Python over the ATT&CK dataset (`app.attack`) and
scenario dicts that follow `schema/scenario.schema.json`. The LLM never calls
this module directly; it goes through the whitelisted tools in `app.tools`.

Scenarios are planning documents: steps name an ATT&CK technique, a target host,
the telemetry expected to record it and what trainees must do. They never contain
attack procedures, commands or code.
"""

from __future__ import annotations

import json
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .attack import AttackData
from .environments import NON_TARGET_ROLES, TACTIC_ROLES, TECHNIQUE_ROLES, get_preset, iter_hosts

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema" / "scenario.schema.json"

LEVELS = ("beginner", "intermediate", "advanced")
AUDIENCES = ("soc-analyst", "blue-team", "red-team", "purple-team", "management")
STEP_MINUTES = {"beginner": 20, "intermediate": 15, "advanced": 10}
BRIEFING_MINUTES = 30  # briefing + debriefing, added once per scenario
THIN_THRESHOLD = 1  # a tactic covered by this many techniques or fewer is "thin"

# Trainee task templates per audience. Placeholders: {tid} {name} {host} {role} {telemetry}.
# They describe defensive / exercise-management work only.
TASK_TEMPLATES: dict[str, list[str]] = {
    "soc-analyst": [
        "Triage the SIEM alert for {name} ({tid}) on {host}",
        "Confirm the activity in the telemetry: {telemetry}",
        "Record severity, scope and an escalation decision in the ticket",
    ],
    "blue-team": [
        "Identify {name} ({tid}) activity on {host} from {telemetry}",
        "Propose and apply a containment action for {host} with the range operator",
        "Propose one detection or hardening improvement mapped to {tid}",
    ],
    "red-team": [
        "Select the approved range-catalogue emulation of {tid} for {host} within the rules of engagement",
        "Log time, host and technique ID of the emulation for the white team",
        "Note which telemetry ({telemetry}) the action is expected to leave",
    ],
    "purple-team": [
        "Red cell: run the approved range-catalogue emulation of {tid} on {host}; blue cell: detect it",
        "Compare expected telemetry ({telemetry}) with what the SIEM actually recorded",
        "Agree on one detection gap for {tid} and tune or write an analytic",
    ],
    "management": [
        "Assess the business impact of {name} on {host} ({role})",
        "Decide on escalation and communication (internal, regulator, customers)",
        "Identify the decision owner and the information needed from the SOC",
    ],
}
NO_TELEMETRY = "no in-range telemetry (pre-compromise activity; rely on threat intelligence)"


@lru_cache(maxsize=1)
def _schema_validator() -> Draft202012Validator:
    with open(SCHEMA_PATH, encoding="utf-8") as fh:
        return Draft202012Validator(json.load(fh))


class ScenarioError(ValueError):
    """Raised when a scenario cannot be built from the given arguments."""


# --------------------------------------------------------------------------- build


def parse_technique_ref(attack: AttackData, ref: str) -> tuple[str, str]:
    """Resolve "T1078" or "T1078@persistence" into (technique ID, tactic shortname).

    Without a forced tactic, the technique's earliest tactic in kill-chain order is used.
    """
    tid, _, forced = ref.strip().partition("@")
    tid = tid.strip().upper()
    tech = attack.technique(tid)
    if tech is None:
        raise ScenarioError(attack.unknown_technique_message(tid))
    if not forced:
        return tid, attack.earliest_tactic(tid)
    forced = forced.strip().lower()
    if forced not in tech["tactics"]:
        raise ScenarioError(
            f"{tid} ({tech['name']}) is not in tactic {forced!r}; it belongs to {tech['tactics']}"
        )
    return tid, forced


def choose_host(attack: AttackData, environment: dict[str, Any], tid: str, tactic: str) -> dict[str, Any]:
    """Pick the target host for a step: preferred roles first, then OS compatibility.

    Order of preference:
    1. platform-agnostic (PRE) techniques run from the attacker host;
    2. a host whose role is preferred (technique hint, then tactic default) and whose OS
       is one of the technique's platforms;
    3. any non-infrastructure host with a compatible OS;
    4. the first host with a preferred role (the validator then warns about the OS).
    Ties are broken by declaration order so the result is deterministic.
    """
    hosts = iter_hosts(environment)
    if not hosts:
        raise ScenarioError("environment has no hosts")
    if attack.is_pre(tid):
        attacker = next((h for h in hosts if h["role"] == "attacker"), None)
        if attacker:
            return attacker
    platforms = set(attack.techniques[tid]["platforms"])
    parent = attack.techniques[tid].get("parent") or tid
    roles = TECHNIQUE_ROLES.get(parent, []) + TACTIC_ROLES.get(tactic, [])
    for role in roles:
        for host in hosts:
            if host["role"] == role and host["os"] in platforms:
                return host
    for host in hosts:
        if host["role"] not in NON_TARGET_ROLES and host["os"] in platforms:
            return host
    for role in roles:
        for host in hosts:
            if host["role"] == role:
                return host
    return next((h for h in hosts if h["role"] not in NON_TARGET_ROLES), hosts[0])


def _telemetry(components: list[str], limit: int = 3) -> str:
    if not components:
        return NO_TELEMETRY
    shown = ", ".join(components[:limit])
    return shown + (f" (+{len(components) - limit} more)" if len(components) > limit else "")


def _make_step(
    attack: AttackData, index: int, tid: str, tactic: str, host: dict[str, Any], level: str, audience: str
) -> dict[str, Any]:
    tech = attack.techniques[tid]
    components = list(tech["data_components"])
    fill = {
        "tid": tid,
        "name": tech["name"],
        "host": host["name"],
        "role": host["role"],
        "telemetry": _telemetry(components),
    }
    return {
        "id": f"S{index}",
        "title": f"{attack.tactic_name(tactic)}: {tech['name']}",
        "tactic": tactic,
        "technique": tid,
        "description": (
            f"The adversary emulation performs {tech['name']} ({tid}, {attack.tactic_name(tactic)}) "
            f"against {host['name']} ({host['role']}, {host['os']}). Planning level: the range operator "
            f"selects an approved emulation from the range catalogue; no procedure is specified here."
        ),
        "target_host": host["name"],
        "duration_minutes": STEP_MINUTES[level],
        "expected_detections": components,
        "trainee_tasks": [t.format(**fill) for t in TASK_TEMPLATES[audience]],
    }


def _default_objectives(attack: AttackData, steps: list[dict[str, Any]], audience: str) -> list[str]:
    tactics = list(dict.fromkeys(s["tactic"] for s in steps))
    names = ", ".join(attack.tactic_name(t) for t in tactics)
    focus = {
        "soc-analyst": "Detect and triage",
        "blue-team": "Detect, contain and harden against",
        "red-team": "Emulate within the rules of engagement",
        "purple-team": "Jointly emulate and detect",
        "management": "Make timely decisions during",
    }[audience]
    return [
        f"{focus} activity across: {names}",
        f"Map each observed event to its ATT&CK technique ({', '.join(s['technique'] for s in steps)})",
    ]


def build_scenario(
    attack: AttackData,
    title: str,
    techniques: list[str],
    level: str = "intermediate",
    audience: str = "soc-analyst",
    environment: str | dict[str, Any] = "small-enterprise",
    objectives: list[str] | None = None,
    scenario_id: str = "SCN-100",
    version: str = "1.0",
) -> dict[str, Any]:
    """Build a validated scenario from ATT&CK technique references.

    Steps are ordered along the kill chain (stable for equal tactics), each gets a
    target host, the technique's data components as expected detections and trainee
    tasks for the audience. Raises ScenarioError on bad input or if the result is invalid.
    """
    if level not in LEVELS:
        raise ScenarioError(f"level must be one of {LEVELS}")
    if audience not in AUDIENCES:
        raise ScenarioError(f"audience must be one of {AUDIENCES}")
    if not techniques:
        raise ScenarioError("at least one technique is required")
    env = get_preset(environment) if isinstance(environment, str) else environment

    resolved: list[tuple[str, str]] = []
    for ref in techniques:
        item = parse_technique_ref(attack, ref)
        if item not in resolved:  # same technique in the same tactic only once
            resolved.append(item)
    resolved.sort(key=lambda item: attack.tactic_index(item[1]))  # sort is stable

    steps = [
        _make_step(attack, i, tid, tactic, choose_host(attack, env, tid, tactic), level, audience)
        for i, (tid, tactic) in enumerate(resolved, start=1)
    ]
    tags = list(dict.fromkeys([s["tactic"] for s in steps] + ([env["preset"]] if env.get("preset") else [])))
    scenario = {
        "id": scenario_id,
        "title": title,
        "version": version,
        "attack_version": attack.version,
        "level": level,
        "audience": audience,
        "duration_minutes": sum(s["duration_minutes"] for s in steps) + BRIEFING_MINUTES,
        "objectives": objectives or _default_objectives(attack, steps, audience),
        "tags": tags,
        "environment": env,
        "steps": steps,
    }
    report = validate_scenario(attack, scenario)
    if not report["valid"]:
        raise ScenarioError("generated scenario is invalid: " + "; ".join(report["errors"]))
    return scenario


# --------------------------------------------------------------------------- validate


def validate_scenario(attack: AttackData, scenario: Any) -> dict[str, Any]:
    """Check a scenario against the JSON Schema and the ATT&CK semantics.

    Returns {"valid": bool, "errors": [...], "warnings": [...]}. Errors make the
    scenario unusable; warnings flag plausible but questionable choices.
    """
    errors: list[str] = []
    warnings: list[str] = []
    for err in sorted(_schema_validator().iter_errors(scenario), key=lambda e: list(e.absolute_path)):
        path = "/".join(str(p) for p in err.absolute_path) or "(root)"
        errors.append(f"schema: {path}: {err.message}")
    if not isinstance(scenario, dict):
        return {"valid": False, "errors": errors, "warnings": warnings}

    env = scenario.get("environment") if isinstance(scenario.get("environment"), dict) else {}
    hosts: dict[str, dict[str, Any]] = {}
    for host in iter_hosts(env):
        if not isinstance(host, dict) or "name" not in host:
            continue
        if host["name"] in hosts:
            errors.append(f"duplicate host name {host['name']!r}")
        hosts[host["name"]] = host

    if scenario.get("attack_version") and scenario["attack_version"] != attack.version:
        warnings.append(
            f"scenario was mapped against ATT&CK {scenario['attack_version']}, data is {attack.version}"
        )

    known_components = attack.data_components
    steps = (
        [s for s in scenario.get("steps", []) if isinstance(s, dict)]
        if isinstance(scenario.get("steps"), list)
        else []
    )
    seen_ids: set[str] = set()
    previous_index = -1
    for step in steps:
        sid = str(step.get("id", "?"))
        if sid in seen_ids:
            errors.append(f"duplicate step id {sid}")
        seen_ids.add(sid)

        tid, tactic = str(step.get("technique", "")), str(step.get("tactic", ""))
        tech = attack.technique(tid)
        if tech is None:
            errors.append(f"{sid}: {attack.unknown_technique_message(tid)}")
        if not attack.has_tactic(tactic):
            errors.append(f"{sid}: unknown tactic {tactic!r}")
        elif tech is not None and tactic not in tech["tactics"]:
            errors.append(f"{sid}: {tid} ({tech['name']}) does not belong to tactic {tactic!r}")

        host = hosts.get(str(step.get("target_host", "")))
        if host is None:
            errors.append(f"{sid}: target host {step.get('target_host')!r} is not in the environment")
        elif tech is not None and "PRE" not in tech["platforms"] and host.get("os") not in tech["platforms"]:
            warnings.append(
                f"{sid}: {tid} targets {tech['platforms']} but {host['name']} runs {host.get('os')}"
            )

        detections = step.get("expected_detections", [])
        if isinstance(detections, list):
            unknown = [d for d in detections if d not in known_components]
            if unknown:
                errors.append(f"{sid}: unknown data components {unknown}")
            if not detections and not (tech is not None and "PRE" in tech["platforms"]):
                warnings.append(f"{sid}: no expected detections")

        if attack.has_tactic(tactic):
            index = attack.tactic_index(tactic)
            if index < previous_index:
                warnings.append(
                    f"{sid}: tactic {tactic!r} comes earlier in the kill chain than the previous step"
                )
            previous_index = index

    total = sum(s.get("duration_minutes", 0) for s in steps if isinstance(s.get("duration_minutes"), int))
    duration = scenario.get("duration_minutes")
    if isinstance(duration, int) and total > duration:
        errors.append(f"steps take {total} min but the scenario lasts {duration} min")

    return {"valid": not errors, "errors": errors, "warnings": warnings}


# --------------------------------------------------------------------------- coverage


def coverage(attack: AttackData, scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    """Tactic x technique matrix listing the scenarios that cover each cell."""
    cells: dict[tuple[str, str], list[str]] = {}
    for scn in scenarios:
        for step in scn.get("steps", []):
            ids = cells.setdefault((step["tactic"], step["technique"]), [])
            if scn["id"] not in ids:
                ids.append(scn["id"])
    columns = []
    for tac in attack.tactics:
        techs = [
            {"id": tid, "name": attack.techniques.get(tid, {}).get("name", tid), "scenarios": ids}
            for (tactic, tid), ids in sorted(cells.items())
            if tactic == tac["shortname"]
        ]
        columns.append({**tac, "techniques": techs})
    covered = [c for c in columns if c["techniques"]]
    return {
        "attack_version": attack.version,
        "scenarios": [s["id"] for s in scenarios],
        "tactics": columns,
        "totals": {
            "tactics": len(columns),
            "tactics_covered": len(covered),
            "techniques_covered": len({tid for (_, tid) in cells}),
        },
    }


# --------------------------------------------------------------------------- gaps


def suggest_techniques(
    attack: AttackData,
    tactic: str,
    platforms: list[str] | None = None,
    exclude: set[str] | None = None,
    limit: int = 5,
) -> list[dict[str, Any]]:
    """Parent techniques of a tactic, most detection data first, optionally platform-filtered.

    Platform-agnostic (PRE) techniques always pass the platform filter.
    """
    wanted = {p.lower() for p in platforms or []}
    exclude = exclude or set()
    candidates = []
    for tid, tech in attack.techniques.items():
        if tech["subtechnique"] or tactic not in tech["tactics"] or tid in exclude:
            continue
        plats = {p.lower() for p in tech["platforms"]}
        if wanted and not (plats & wanted) and "pre" not in plats:
            continue
        candidates.append((-len(tech["data_components"]), tid))
    candidates.sort()
    return [
        {"id": tid, "name": attack.techniques[tid]["name"], "detections": -neg}
        for neg, tid in candidates[:limit]
    ]


def _is_covered(required: str, covered: set[str]) -> bool:
    """A required parent technique is covered by itself or any of its sub-techniques."""
    if required in covered:
        return True
    return "." not in required and any(c.split(".")[0] == required for c in covered)


def gap_analysis(
    attack: AttackData,
    scenarios: list[dict[str, Any]],
    platforms: list[str] | None = None,
    required_techniques: list[str] | None = None,
    suggestions_per_tactic: int = 3,
) -> dict[str, Any]:
    """Find what a scenario library does not train.

    - uncovered tactics, with suggested parent techniques (most detection data first);
    - thinly covered tactics (THIN_THRESHOLD techniques or fewer);
    - techniques of a threat profile (`required_techniques`) that no scenario covers.
    """
    matrix = coverage(attack, scenarios)
    covered_ids = {t["id"] for col in matrix["tactics"] for t in col["techniques"]}

    uncovered, thin = [], []
    for col in matrix["tactics"]:
        n = len(col["techniques"])
        if n == 0:
            uncovered.append(
                {
                    "tactic": col["shortname"],
                    "name": col["name"],
                    "suggestions": suggest_techniques(
                        attack, col["shortname"], platforms, covered_ids, suggestions_per_tactic
                    ),
                }
            )
        elif n <= THIN_THRESHOLD:
            thin.append(
                {
                    "tactic": col["shortname"],
                    "name": col["name"],
                    "covered_by": [t["id"] for t in col["techniques"]],
                    "suggestions": suggest_techniques(
                        attack, col["shortname"], platforms, covered_ids, suggestions_per_tactic
                    ),
                }
            )

    profile = None
    if required_techniques:
        missing, covered, invalid = [], [], []
        for ref in dict.fromkeys(r.strip().upper() for r in required_techniques):
            tech = attack.technique(ref)
            if tech is None:
                invalid.append({"id": ref, "reason": attack.unknown_technique_message(ref)})
            elif _is_covered(ref, covered_ids):
                covered.append(ref)
            else:
                missing.append({"id": ref, "name": tech["name"], "tactics": tech["tactics"]})
        profile = {
            "required": len(required_techniques),
            "covered": covered,
            "missing": missing,
            "invalid": invalid,
        }

    return {
        "attack_version": attack.version,
        "scenarios": matrix["scenarios"],
        "platforms": platforms or [],
        "totals": matrix["totals"],
        "uncovered_tactics": uncovered,
        "thin_tactics": thin,
        "threat_profile": profile,
    }


# --------------------------------------------------------------------------- aggregate


def aggregate_scenarios(
    attack: AttackData,
    scenarios: list[dict[str, Any]],
    title: str,
    scenario_id: str = "SCN-200",
) -> dict[str, Any]:
    """Merge several scenarios into one exercise.

    Environments are merged by segment and host name (a host defined twice with a
    different OS or role is reported as a conflict; the first definition wins).
    Steps are de-duplicated on (technique, tactic), re-sorted along the kill chain
    and renumbered. Returns {"scenario", "report", "validation"}.
    """
    if len(scenarios) < 2:
        raise ScenarioError("aggregation needs at least two scenarios")

    segments: dict[str, dict[str, Any]] = {}
    host_defs: dict[str, tuple[dict[str, Any], str]] = {}
    conflicts = []
    for scn in scenarios:
        for seg in scn["environment"]["segments"]:
            merged = segments.setdefault(seg["name"], {"name": seg["name"], "hosts": []})
            for host in seg["hosts"]:
                if host["name"] not in host_defs:
                    host_defs[host["name"]] = (host, scn["id"])
                    merged["hosts"].append(dict(host))
                elif (host["os"], host["role"]) != (
                    host_defs[host["name"]][0]["os"],
                    host_defs[host["name"]][0]["role"],
                ):
                    first, first_scn = host_defs[host["name"]]
                    conflicts.append(
                        {
                            "host": host["name"],
                            "kept": {"scenario": first_scn, "os": first["os"], "role": first["role"]},
                            "dropped": {"scenario": scn["id"], "os": host["os"], "role": host["role"]},
                        }
                    )

    steps, seen, duplicates = [], {}, []
    for scn in scenarios:
        for step in scn["steps"]:
            key = (step["technique"], step["tactic"])
            if key in seen:
                duplicates.append(
                    {"technique": key[0], "tactic": key[1], "scenario": scn["id"], "kept_from": seen[key]}
                )
                continue
            seen[key] = scn["id"]
            steps.append(dict(step))
    steps.sort(key=lambda s: attack.tactic_index(s["tactic"]) if attack.has_tactic(s["tactic"]) else 99)
    for i, step in enumerate(steps, start=1):
        step["id"] = f"S{i}"

    audiences = Counter(s["audience"] for s in scenarios)
    audience = max(audiences, key=lambda a: (audiences[a], -[s["audience"] for s in scenarios].index(a)))
    level = max((s["level"] for s in scenarios), key=LEVELS.index)
    merged_scn = {
        "id": scenario_id,
        "title": title,
        "version": "1.0",
        "attack_version": attack.version,
        "level": level,
        "audience": audience,
        "duration_minutes": sum(s["duration_minutes"] for s in steps) + BRIEFING_MINUTES,
        "objectives": list(dict.fromkeys(o for s in scenarios for o in s["objectives"])),
        "tags": list(dict.fromkeys(t for s in scenarios for t in s.get("tags", []))),
        "environment": {"segments": list(segments.values())},
        "steps": steps,
    }
    report = {
        "sources": [s["id"] for s in scenarios],
        "host_conflicts": conflicts,
        "removed_duplicates": duplicates,
        "mixed_audiences": sorted(audiences) if len(audiences) > 1 else [],
        "chosen_audience": audience,
        "chosen_level": level,
    }
    return {"scenario": merged_scn, "report": report, "validation": validate_scenario(attack, merged_scn)}
