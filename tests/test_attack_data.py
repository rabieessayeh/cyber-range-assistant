"""The compact ATT&CK dataset and the converter that produces it."""

from __future__ import annotations

from app.environments import PRESETS, TACTIC_ROLES, TECHNIQUE_ROLES
from scripts.build_attack_data import build


def test_tactics_in_matrix_order(attack):
    order = attack.tactic_order
    assert order[0] == "reconnaissance" and order[-1] == "impact"
    assert order.index("initial-access") < order.index("execution") < order.index("exfiltration")
    assert len(order) == len(set(order))


def test_environment_tables_reference_existing_tactics_and_techniques(attack):
    """Guards against ATT&CK renaming tactics or renumbering techniques."""
    assert set(TACTIC_ROLES) == set(attack.tactic_order)
    for tid in TECHNIQUE_ROLES:
        assert attack.technique(tid) is not None, tid


def test_techniques_have_matrix_ordered_tactics_and_detections(attack):
    for tid, tech in attack.techniques.items():
        assert tech["tactics"], tid
        indexes = [attack.tactic_index(t) for t in tech["tactics"]]
        assert indexes == sorted(indexes), tid
        if "PRE" not in tech["platforms"]:
            assert tech["data_components"], f"{tid} has no detection data"


def test_revoked_ids_point_to_active_techniques(attack):
    assert attack.revoked, "revoked map should not be empty"
    for old, new in attack.revoked.items():
        assert attack.technique(old) is None
        assert attack.technique(new) is not None
    assert "revoked" in attack.unknown_technique_message(next(iter(attack.revoked)))


def test_search_and_earliest_tactic(attack):
    hits = attack.search("password spraying")
    assert hits and hits[0]["name"] == "Password Spraying"
    assert all("Windows" in h["platforms"] for h in attack.search("shell", platform="windows"))
    multi = next(tid for tid, t in attack.techniques.items() if len(t["tactics"]) > 1)
    assert attack.earliest_tactic(multi) == attack.techniques[multi]["tactics"][0]


def test_presets_use_known_os_names(attack):
    platforms = {p for t in attack.techniques.values() for p in t["platforms"]}
    for preset in PRESETS.values():
        for seg in preset["segments"]:
            for host in seg["hosts"]:
                assert host["os"] in platforms


def _stix(type_, id_, **kw):
    return {"type": type_, "id": f"{type_}--{id_}", **kw}


def test_build_converter_on_minimal_bundle():
    """The STIX -> compact conversion: matrix order, revoked/deprecated skipped, detection chain."""
    ref = lambda eid: [{"source_name": "mitre-attack", "external_id": eid}]  # noqa: E731
    objects = [
        _stix("x-mitre-collection", "c", x_mitre_version="99.0"),
        _stix(
            "x-mitre-tactic", "t2", name="Impact", x_mitre_shortname="impact", external_references=ref("TA2")
        ),
        _stix(
            "x-mitre-tactic", "t1", name="Access", x_mitre_shortname="access", external_references=ref("TA1")
        ),
        _stix("x-mitre-matrix", "m", tactic_refs=["x-mitre-tactic--t1", "x-mitre-tactic--t2"]),
        _stix(
            "attack-pattern",
            "a",
            name="Alpha",
            external_references=ref("T0001"),
            x_mitre_platforms=["Windows"],
            kill_chain_phases=[
                {"kill_chain_name": "mitre-attack", "phase_name": "impact"},
                {"kill_chain_name": "mitre-attack", "phase_name": "access"},
            ],
        ),
        _stix("attack-pattern", "old", name="Old", external_references=ref("T0002"), revoked=True),
        _stix("attack-pattern", "dep", name="Dep", external_references=ref("T0003"), x_mitre_deprecated=True),
        _stix("x-mitre-data-component", "dc", name="Process Creation"),
        _stix(
            "x-mitre-analytic",
            "an",
            x_mitre_log_source_references=[{"x_mitre_data_component_ref": "x-mitre-data-component--dc"}],
        ),
        _stix("x-mitre-detection-strategy", "ds", x_mitre_analytic_refs=["x-mitre-analytic--an"]),
        _stix(
            "relationship",
            "r1",
            relationship_type="detects",
            source_ref="x-mitre-detection-strategy--ds",
            target_ref="attack-pattern--a",
        ),
        _stix(
            "relationship",
            "r2",
            relationship_type="revoked-by",
            source_ref="attack-pattern--old",
            target_ref="attack-pattern--a",
        ),
    ]
    data = build({"objects": objects})
    assert data["attack_version"] == "99.0"
    assert [t["shortname"] for t in data["tactics"]] == ["access", "impact"]
    assert list(data["techniques"]) == ["T0001"]
    assert data["techniques"]["T0001"]["tactics"] == ["access", "impact"]
    assert data["techniques"]["T0001"]["data_components"] == ["Process Creation"]
    assert data["revoked"] == {"T0002": "T0001"}
