"""Build the compact ATT&CK Enterprise dataset used by the engine.

Downloads the official STIX 2.1 bundle (or reads a local copy with --input) and
writes `data/attack_enterprise.json` with:

- tactics in matrix order (from the x-mitre-matrix `tactic_refs`);
- active techniques and sub-techniques (revoked / deprecated ones skipped) with
  their tactics, platforms and the data components that detect them;
- a `revoked` map (old ID -> replacement ID) so the tools can explain renumbering.

Detections follow the ATT&CK v18+ model:
technique <-[detects]- detection strategy -> analytics -> log source references
-> data component.

Usage:
    python scripts/build_attack_data.py                  # download the latest bundle
    python scripts/build_attack_data.py --input enterprise-attack.json
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "data" / "attack_enterprise.json"


def external_id(obj: dict[str, Any]) -> str | None:
    """Return the ATT&CK ID (e.g. T1078, TA0001) of a STIX object, if any."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def is_active(obj: dict[str, Any]) -> bool:
    """True if the object is neither revoked nor deprecated."""
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def load_bundle(path: str | None) -> dict[str, Any]:
    """Read the STIX bundle from a local file or download it."""
    if path:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    print(f"Downloading {SOURCE_URL} ...", file=sys.stderr)
    with urllib.request.urlopen(SOURCE_URL, timeout=120) as resp:  # noqa: S310 (fixed https URL)
        return json.load(resp)


def build(bundle: dict[str, Any]) -> dict[str, Any]:
    """Convert a STIX bundle into the compact dataset."""
    objects: list[dict[str, Any]] = bundle["objects"]
    by_id = {o["id"]: o for o in objects}

    version = next(
        (o.get("x_mitre_version") for o in objects if o["type"] == "x-mitre-collection"), "unknown"
    )

    # Tactics in matrix order.
    matrix = next(o for o in objects if o["type"] == "x-mitre-matrix" and is_active(o))
    tactics = []
    for ref in matrix["tactic_refs"]:
        tac = by_id[ref]
        tactics.append({"id": external_id(tac), "shortname": tac["x_mitre_shortname"], "name": tac["name"]})
    tactic_names = {t["shortname"] for t in tactics}

    # Data component names, and the components each detection strategy relies on.
    component_name = {o["id"]: o["name"] for o in objects if o["type"] == "x-mitre-data-component"}
    strategy_components: dict[str, set[str]] = {}
    for o in objects:
        if o["type"] != "x-mitre-detection-strategy" or not is_active(o):
            continue
        names: set[str] = set()
        for analytic_ref in o.get("x_mitre_analytic_refs", []):
            analytic = by_id.get(analytic_ref)
            if not analytic or not is_active(analytic):
                continue
            for log_source in analytic.get("x_mitre_log_source_references", []):
                name = component_name.get(log_source.get("x_mitre_data_component_ref", ""))
                if name:
                    names.add(name)
        strategy_components[o["id"]] = names

    technique_components: dict[str, set[str]] = defaultdict(set)
    revoked_by: dict[str, str] = {}
    for o in objects:
        if o["type"] != "relationship":
            continue
        if o["relationship_type"] == "detects" and o["source_ref"] in strategy_components:
            technique_components[o["target_ref"]] |= strategy_components[o["source_ref"]]
        elif o["relationship_type"] == "revoked-by" and o["source_ref"].startswith("attack-pattern--"):
            revoked_by[o["source_ref"]] = o["target_ref"]

    techniques: dict[str, dict[str, Any]] = {}
    for o in objects:
        if o["type"] != "attack-pattern" or not is_active(o):
            continue
        tid = external_id(o)
        if not tid:
            continue
        phases = [
            p["phase_name"]
            for p in o.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack" and p["phase_name"] in tactic_names
        ]
        # Store tactics in matrix order: STIX lists them in arbitrary order.
        phases.sort(key=lambda s: [t["shortname"] for t in tactics].index(s))
        subtechnique = bool(o.get("x_mitre_is_subtechnique", False))
        techniques[tid] = {
            "name": o["name"],
            "tactics": phases,
            "platforms": sorted(o.get("x_mitre_platforms", [])),
            "subtechnique": subtechnique,
            "parent": tid.split(".")[0] if subtechnique else None,
            "data_components": sorted(technique_components.get(o["id"], set())),
        }

    # Revoked IDs -> active replacement (follow chains of revocations).
    revoked: dict[str, str] = {}
    for old_ref, new_ref in revoked_by.items():
        seen = {old_ref}
        while new_ref in revoked_by and new_ref not in seen:
            seen.add(new_ref)
            new_ref = revoked_by[new_ref]
        old_id, new_id = external_id(by_id[old_ref]), external_id(by_id.get(new_ref, {}))
        if old_id and new_id in techniques and old_id not in techniques:
            revoked[old_id] = new_id

    return {
        "attack_version": version,
        "source_url": SOURCE_URL,
        "generated": datetime.now(UTC).strftime("%Y-%m-%d"),
        "attribution": "MITRE ATT&CK(R) Enterprise, (c) The MITRE Corporation. "
        "Used under the ATT&CK Terms of Use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/",
        "tactics": tactics,
        "techniques": dict(sorted(techniques.items())),
        "revoked": dict(sorted(revoked.items())),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--input", help="local enterprise-attack.json (default: download)")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()

    data = build(load_bundle(args.input))

    print(f"ATT&CK Enterprise version {data['attack_version']}")
    print("Tactics (matrix order):")
    for tac in data["tactics"]:
        print(f"  {tac['id']}  {tac['shortname']:<22} {tac['name']}")
    techs = data["techniques"]
    no_det = [t for t, v in techs.items() if not v["data_components"]]
    print(
        f"{len(techs)} active techniques ({sum(v['subtechnique'] for v in techs.values())} sub-techniques), "
        f"{len(no_det)} without detection data, {len(data['revoked'])} revoked IDs mapped"
    )

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {out} ({out.stat().st_size // 1024} KiB)")


if __name__ == "__main__":
    main()
