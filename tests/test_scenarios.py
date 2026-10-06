"""The deterministic engine: build, validate, coverage, gap analysis, aggregation."""

from __future__ import annotations

import copy

import pytest

from app.scenarios import (
    BRIEFING_MINUTES,
    STEP_MINUTES,
    ScenarioError,
    aggregate_scenarios,
    build_scenario,
    coverage,
    gap_analysis,
    parse_technique_ref,
    validate_scenario,
)

# ---------------------------------------------------------------- build


def test_build_orders_steps_along_kill_chain(attack, phishing):
    tactics = [s["tactic"] for s in phishing["steps"]]
    assert tactics == ["initial-access", "execution", "impact"]
    assert [s["id"] for s in phishing["steps"]] == ["S1", "S2", "S3"]
    assert validate_scenario(attack, phishing) == {"valid": True, "errors": [], "warnings": []}


def test_build_uses_earliest_tactic_in_matrix_order(attack):
    # T1078 is listed with "stealth" first in STIX; the earliest in the matrix is initial-access.
    assert parse_technique_ref(attack, "T1078") == ("T1078", "initial-access")


def test_build_forced_tactic(attack):
    assert parse_technique_ref(attack, "T1078@persistence") == ("T1078", "persistence")
    scn = build_scenario(attack, "Forced", ["T1078@persistence"], scenario_id="SCN-902")
    assert scn["steps"][0]["tactic"] == "persistence"


def test_build_rejects_wrong_forced_tactic_and_unknown_ids(attack):
    with pytest.raises(ScenarioError, match="is not in tactic"):
        parse_technique_ref(attack, "T1486@initial-access")
    with pytest.raises(ScenarioError, match="unknown technique"):
        parse_technique_ref(attack, "T9999")
    revoked = next(iter(attack.revoked))
    with pytest.raises(ScenarioError, match="revoked"):
        build_scenario(attack, "Revoked", [revoked])


def test_build_rejects_bad_level_audience_and_empty(attack):
    for kwargs in ({"level": "expert"}, {"audience": "ceo"}):
        with pytest.raises(ScenarioError):
            build_scenario(attack, "Bad", ["T1486"], **kwargs)
    with pytest.raises(ScenarioError):
        build_scenario(attack, "Empty", [])


def test_build_host_choice_by_tactic_and_platform(attack):
    scn = build_scenario(
        attack, "Hosts", ["T1566.001", "T1003.001", "T1021.002", "T1595.002"], scenario_id="SCN-903"
    )
    hosts = {s["technique"]: s["target_host"] for s in scn["steps"]}
    assert hosts["T1595.002"] == "attacker"  # PRE technique runs from the attacker host
    assert hosts["T1566.001"] == "ws01"  # phishing targets a workstation
    assert hosts["T1003.001"] == "dc01"  # credential access prefers the domain controller
    assert hosts["T1021.002"] == "fs01"  # lateral movement to the file server
    # Windows-only technique in an all-Linux environment never lands on attacker/siem.
    linux = build_scenario(
        attack, "Linux", ["T1190", "T1059.004"], environment="linux-web", scenario_id="SCN-904"
    )
    assert {s["target_host"] for s in linux["steps"]} == {"web01"}


def test_build_detections_tasks_and_duration(attack, phishing):
    step = phishing["steps"][0]
    assert step["expected_detections"] == attack.techniques[step["technique"]]["data_components"]
    assert any("SIEM" in task for task in step["trainee_tasks"])
    assert phishing["duration_minutes"] == 3 * STEP_MINUTES["beginner"] + BRIEFING_MINUTES
    mgmt = build_scenario(attack, "Mgmt", ["T1486"], audience="management", scenario_id="SCN-905")
    assert any("escalation" in t for t in mgmt["steps"][0]["trainee_tasks"])


def test_build_output_contains_no_procedures(library):
    """Scenarios are planning documents: no commands or code-like content."""
    text = str(library).lower()
    for marker in ("powershell -", "cmd.exe /c", "mimikatz", "invoke-", "sudo ", "wget ", "curl "):
        assert marker not in text


# ---------------------------------------------------------------- validate


def test_validate_reports_schema_errors(attack, phishing):
    bad = copy.deepcopy(phishing)
    bad["id"] = "scenario-1"
    bad["extra"] = True
    del bad["steps"][0]["trainee_tasks"]
    report = validate_scenario(attack, bad)
    assert not report["valid"]
    text = " ".join(report["errors"])
    assert "(root)" in text and "id" in text and "trainee_tasks" in text


def test_validate_semantic_errors(attack, phishing):
    bad = copy.deepcopy(phishing)
    bad["steps"][0]["technique"] = "T1486"  # impact technique under initial-access
    bad["steps"][1]["target_host"] = "nowhere"
    bad["steps"][2]["id"] = "S1"
    bad["steps"][2]["expected_detections"] = ["Telepathy"]
    bad["duration_minutes"] = 15
    bad["environment"]["segments"][0]["hosts"].append(dict(bad["environment"]["segments"][0]["hosts"][0]))
    errors = " | ".join(validate_scenario(attack, bad)["errors"])
    assert "does not belong to tactic" in errors
    assert "not in the environment" in errors
    assert "duplicate step id S1" in errors
    assert "duplicate host name" in errors
    assert "unknown data components ['Telepathy']" in errors
    assert "but the scenario lasts 15 min" in errors


def test_validate_unknown_and_revoked_technique(attack, phishing):
    bad = copy.deepcopy(phishing)
    bad["steps"][0]["technique"] = next(iter(attack.revoked))
    assert "revoked" in " ".join(validate_scenario(attack, bad)["errors"])


def test_validate_warnings_os_and_order(attack, phishing):
    scn = copy.deepcopy(phishing)
    scn["steps"][1]["target_host"] = "web01"  # PowerShell (Windows) on a Linux host
    scn["steps"].reverse()  # impact before initial access
    report = validate_scenario(attack, scn)
    assert report["valid"]
    warnings = " | ".join(report["warnings"])
    assert "runs Linux" in warnings
    assert "earlier in the kill chain" in warnings


def test_validate_non_dict_input(attack):
    assert validate_scenario(attack, ["not", "a", "scenario"])["valid"] is False


def test_library_is_valid(attack, library):
    assert len(library) == 5
    for scn in library:
        assert validate_scenario(attack, scn)["valid"], scn["id"]


# ---------------------------------------------------------------- coverage & gaps


def test_coverage_counts(attack, library):
    matrix = coverage(attack, library)
    assert [c["shortname"] for c in matrix["tactics"]] == attack.tactic_order
    impact = next(c for c in matrix["tactics"] if c["shortname"] == "impact")
    cell = next(t for t in impact["techniques"] if t["id"] == "T1486")
    assert cell["scenarios"] == ["SCN-001", "SCN-005"]
    distinct = {(s["tactic"], s["technique"]) for scn in library for s in scn["steps"]}
    assert sum(len(c["techniques"]) for c in matrix["tactics"]) == len(distinct)
    assert matrix["totals"]["tactics_covered"] == sum(1 for c in matrix["tactics"] if c["techniques"])


def test_gaps_uncovered_and_thin_tactics(attack, library):
    gaps = gap_analysis(attack, library)
    uncovered = {g["tactic"] for g in gaps["uncovered_tactics"]}
    assert {"reconnaissance", "resource-development", "stealth"} <= uncovered
    for gap in gaps["uncovered_tactics"]:
        counts = [s["detections"] for s in gap["suggestions"]]
        assert counts == sorted(counts, reverse=True)
        assert all("." not in s["id"] for s in gap["suggestions"])  # parents only
    assert all(len(t["covered_by"]) == 1 for t in gaps["thin_tactics"])


def test_gaps_platform_filter(attack):
    gaps = gap_analysis(attack, [], platforms=["Linux"])
    for gap in gaps["uncovered_tactics"]:
        for s in gap["suggestions"]:
            plats = attack.techniques[s["id"]]["platforms"]
            assert "Linux" in plats or "PRE" in plats


def test_gaps_threat_profile(attack, library):
    revoked = next(iter(attack.revoked))
    gaps = gap_analysis(attack, library, required_techniques=["T1566", "T1486", "T1595", "T9999", revoked])
    profile = gaps["threat_profile"]
    assert profile["covered"] == ["T1566", "T1486"]  # T1566 covered through its sub-techniques
    assert [m["id"] for m in profile["missing"]] == ["T1595"]
    assert {i["id"] for i in profile["invalid"]} == {"T9999", revoked}


# ---------------------------------------------------------------- aggregate


def test_aggregate_merges_and_deduplicates(attack, library):
    by_id = {s["id"]: s for s in library}
    result = aggregate_scenarios(attack, [by_id["SCN-001"], by_id["SCN-002"]], "Merged")
    scn, report = result["scenario"], result["report"]
    assert result["validation"]["valid"]
    keys = [(s["technique"], s["tactic"]) for s in scn["steps"]]
    assert len(keys) == len(set(keys))
    assert {
        "technique": "T1021.002",
        "tactic": "lateral-movement",
        "scenario": "SCN-002",
        "kept_from": "SCN-001",
    } in (report["removed_duplicates"])
    assert [s["id"] for s in scn["steps"]] == [f"S{i}" for i in range(1, len(keys) + 1)]
    indexes = [attack.tactic_index(s["tactic"]) for s in scn["steps"]]
    assert indexes == sorted(indexes)
    assert report["mixed_audiences"] == ["blue-team", "soc-analyst"]


def test_aggregate_reports_host_conflicts(attack, library):
    by_id = {s["id"]: s for s in library}
    # Shared host names (attacker, web01, siem01) are identical; change an OS to force a conflict.
    other = copy.deepcopy(by_id["SCN-003"])
    other["environment"]["segments"][1]["hosts"][0]["os"] = "Windows"
    report = aggregate_scenarios(attack, [by_id["SCN-001"], other], "Merged")["report"]
    assert report["host_conflicts"][0]["host"] == "web01"
    assert report["host_conflicts"][0]["kept"]["os"] == "Linux"


def test_aggregate_needs_two(attack, library):
    with pytest.raises(ScenarioError):
        aggregate_scenarios(attack, library[:1], "One")
