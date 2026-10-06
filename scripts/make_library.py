"""Generate the example scenario library in `scenarios/` with the deterministic builder.

Every scenario is built by `app.scenarios.build_scenario` and validated; the script
fails if a technique ID does not exist in the current ATT&CK data (IDs are
checked, not trusted). Some tactics are left uncovered on purpose (e.g.
reconnaissance, resource development, stealth) so the gap analysis has
something to show.

Usage:
    python scripts/make_library.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.attack import load_attack  # noqa: E402
from app.library import LIBRARY_DIR, to_yaml  # noqa: E402
from app.scenarios import build_scenario, validate_scenario  # noqa: E402

LIBRARY = [
    {
        "scenario_id": "SCN-001",
        "title": "Phishing to ransomware",
        "level": "intermediate",
        "audience": "soc-analyst",
        "environment": "small-enterprise",
        "techniques": [
            "T1566.001",  # Spearphishing Attachment
            "T1204.002",  # Malicious File
            "T1059.001",  # PowerShell
            "T1547.001",  # Registry Run Keys / Startup Folder
            "T1003.001",  # LSASS Memory
            "T1021.002",  # SMB/Windows Admin Shares
            "T1486",  # Data Encrypted for Impact
            "T1490",  # Inhibit System Recovery
        ],
    },
    {
        "scenario_id": "SCN-002",
        "title": "Password spraying to lateral movement",
        "level": "intermediate",
        "audience": "blue-team",
        "environment": "small-enterprise",
        "techniques": [
            "T1110.003",  # Password Spraying
            "T1087.002",  # Domain Account discovery
            "T1135",  # Network Share Discovery
            "T1021.001",  # Remote Desktop Protocol
            "T1021.002",  # SMB/Windows Admin Shares (shared with SCN-001: aggregation demo)
        ],
    },
    {
        "scenario_id": "SCN-003",
        "title": "Web application compromise to data exfiltration",
        "level": "advanced",
        "audience": "purple-team",
        "environment": "linux-web",
        "techniques": [
            "T1190",  # Exploit Public-Facing Application
            "T1505.003",  # Web Shell
            "T1059.004",  # Unix Shell
            "T1068",  # Exploitation for Privilege Escalation
            "T1005",  # Data from Local System
            "T1560.001",  # Archive via Utility
            "T1071.001",  # Web Protocols (C2)
            "T1048",  # Exfiltration Over Alternative Protocol
        ],
    },
    {
        "scenario_id": "SCN-004",
        "title": "Defence impairment and log tampering",
        "level": "advanced",
        "audience": "blue-team",
        "environment": "small-enterprise",
        "techniques": [
            "T1078.002",  # Domain Accounts (earliest tactic: initial access)
            "T1112@defense-impairment",  # Modify Registry, forced out of its earliest tactic (persistence)
            "T1685",  # Disable or Modify Tools (replaces revoked T1562.001)
            "T1685.001",  # Disable or Modify Windows Event Log (replaces T1562.002)
            "T1685.005",  # Clear Windows Event Logs (replaces T1070.001)
            "T1686.003",  # Windows Host Firewall
        ],
    },
    {
        "scenario_id": "SCN-005",
        "title": "Ransomware crisis exercise for management",
        "level": "beginner",
        "audience": "management",
        "environment": "small-enterprise",
        "techniques": [
            "T1566.002",  # Spearphishing Link
            "T1567.002",  # Exfiltration to Cloud Storage (double extortion)
            "T1489",  # Service Stop
            "T1486",  # Data Encrypted for Impact
            "T1490",  # Inhibit System Recovery
        ],
    },
]


def main() -> None:
    attack = load_attack()
    LIBRARY_DIR.mkdir(exist_ok=True)
    for spec in LIBRARY:
        scenario = build_scenario(attack, **spec)
        report = validate_scenario(attack, scenario)
        path = LIBRARY_DIR / f"{scenario['id']}.yaml"
        path.write_text(to_yaml(scenario), encoding="utf-8")
        print(
            f"{scenario['id']}  {len(scenario['steps'])} steps  {scenario['duration_minutes']:>3} min  "
            f"warnings={len(report['warnings'])}  {path.name}"
        )


if __name__ == "__main__":
    main()
