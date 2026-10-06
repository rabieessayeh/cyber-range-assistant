"""Range environment presets and host-selection preferences.

Hosts are described only by name, OS and role: enough to plan who is targeted
and which telemetry should exist, nothing about how to attack them.
"""

from __future__ import annotations

import copy
from typing import Any

# OS names match ATT&CK platform names so they can be compared directly.
PRESETS: dict[str, dict[str, Any]] = {
    "small-enterprise": {
        "preset": "small-enterprise",
        "segments": [
            {"name": "internet", "hosts": [{"name": "attacker", "os": "Linux", "role": "attacker"}]},
            {
                "name": "dmz",
                "hosts": [
                    {"name": "web01", "os": "Linux", "role": "web-server"},
                    {"name": "mail01", "os": "Windows", "role": "mail-server"},
                ],
            },
            {
                "name": "corp-lan",
                "hosts": [
                    {"name": "ws01", "os": "Windows", "role": "workstation"},
                    {"name": "ws02", "os": "Windows", "role": "workstation"},
                    {"name": "dc01", "os": "Windows", "role": "domain-controller"},
                    {"name": "fs01", "os": "Windows", "role": "file-server"},
                ],
            },
            {"name": "soc", "hosts": [{"name": "siem01", "os": "Linux", "role": "siem"}]},
        ],
    },
    "linux-web": {
        "preset": "linux-web",
        "segments": [
            {"name": "internet", "hosts": [{"name": "attacker", "os": "Linux", "role": "attacker"}]},
            {"name": "dmz", "hosts": [{"name": "web01", "os": "Linux", "role": "web-server"}]},
            {"name": "backend", "hosts": [{"name": "db01", "os": "Linux", "role": "database"}]},
            {"name": "soc", "hosts": [{"name": "siem01", "os": "Linux", "role": "siem"}]},
        ],
    },
}

# Preferred target roles per tactic, most preferred first. Keys are checked
# against the ATT&CK data in the tests, so a renamed tactic fails loudly.
TACTIC_ROLES: dict[str, list[str]] = {
    "reconnaissance": ["attacker"],
    "resource-development": ["attacker"],
    "initial-access": ["workstation", "web-server", "mail-server"],
    "execution": ["workstation", "web-server"],
    "persistence": ["workstation", "web-server", "domain-controller"],
    "privilege-escalation": ["workstation", "web-server", "database"],
    "stealth": ["workstation", "web-server"],
    "defense-impairment": ["workstation", "domain-controller", "web-server"],
    "credential-access": ["domain-controller", "workstation", "web-server", "database"],
    "discovery": ["workstation", "web-server"],
    "lateral-movement": ["file-server", "domain-controller", "database", "workstation"],
    "collection": ["file-server", "database", "mail-server", "workstation"],
    "command-and-control": ["workstation", "web-server"],
    "exfiltration": ["file-server", "database", "web-server"],
    "impact": ["file-server", "database", "workstation", "web-server"],
}

# A few techniques whose natural target differs from their tactic default
# (e.g. exploiting a public-facing app targets the web server, not a workstation).
# Keyed by parent technique ID; also checked against the data in the tests.
TECHNIQUE_ROLES: dict[str, list[str]] = {
    "T1190": ["web-server", "mail-server"],  # Exploit Public-Facing Application
    "T1133": ["web-server", "mail-server"],  # External Remote Services
    "T1505": ["web-server", "mail-server"],  # Server Software Component (e.g. web shell)
    "T1566": ["workstation", "mail-server"],  # Phishing
}

# Roles that are infrastructure of the exercise, never a fallback target.
NON_TARGET_ROLES = {"attacker", "siem"}


def get_preset(name: str) -> dict[str, Any]:
    """Return a deep copy of a preset so callers can modify it freely."""
    if name not in PRESETS:
        raise KeyError(f"unknown environment preset {name!r}; choose one of {sorted(PRESETS)}")
    return copy.deepcopy(PRESETS[name])


def iter_hosts(environment: dict[str, Any]) -> list[dict[str, Any]]:
    """All hosts of an environment, in declaration order."""
    return [h for seg in environment.get("segments", []) for h in seg.get("hosts", [])]
