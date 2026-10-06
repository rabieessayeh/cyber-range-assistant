"""Read-only access to the compact MITRE ATT&CK Enterprise dataset.

The dataset is produced by `scripts/build_attack_data.py`. Nothing in the engine
hard-codes tactic names or technique IDs: tactic order, names, platforms and
detections all come from this file.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "attack_enterprise.json"
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
PRE_PLATFORM = "PRE"  # reconnaissance / resource development: happens outside the range


@dataclass(frozen=True)
class AttackData:
    """Tactics, techniques and detections of one ATT&CK release."""

    version: str
    tactics: list[dict[str, str]]
    techniques: dict[str, dict[str, Any]]
    revoked: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> AttackData:
        return cls(
            version=str(raw["attack_version"]),
            tactics=list(raw["tactics"]),
            techniques=dict(raw["techniques"]),
            revoked=dict(raw.get("revoked", {})),
        )

    # --- tactics -----------------------------------------------------------------

    @property
    def tactic_order(self) -> list[str]:
        """Tactic shortnames in kill-chain (matrix) order."""
        return [t["shortname"] for t in self.tactics]

    def tactic_index(self, shortname: str) -> int:
        """Position of a tactic in the matrix; raises KeyError if unknown."""
        try:
            return self.tactic_order.index(shortname)
        except ValueError:
            raise KeyError(shortname) from None

    def tactic_name(self, shortname: str) -> str:
        return next((t["name"] for t in self.tactics if t["shortname"] == shortname), shortname)

    def has_tactic(self, shortname: str) -> bool:
        return shortname in self.tactic_order

    # --- techniques --------------------------------------------------------------

    def technique(self, tid: str) -> dict[str, Any] | None:
        """The technique record, or None if the ID is unknown or revoked."""
        return self.techniques.get(tid.strip().upper())

    def unknown_technique_message(self, tid: str) -> str:
        """Explain why an ID is not usable, pointing at its replacement if it was revoked."""
        tid = tid.strip().upper()
        if tid in self.revoked:
            return (
                f"{tid} was revoked in ATT&CK {self.version}; use {self.revoked[tid]} "
                f"({self.techniques[self.revoked[tid]]['name']}) instead"
            )
        return f"unknown technique {tid} in ATT&CK {self.version}"

    def earliest_tactic(self, tid: str) -> str:
        """The technique's first tactic in kill-chain order (not in STIX list order)."""
        tactics = self.techniques[tid]["tactics"]
        return min(tactics, key=self.tactic_index)

    def is_pre(self, tid: str) -> bool:
        """True for platform-agnostic, pre-compromise techniques."""
        return PRE_PLATFORM in self.techniques[tid]["platforms"]

    @property
    def data_components(self) -> set[str]:
        return {c for t in self.techniques.values() for c in t["data_components"]}

    def subtechniques(self, parent: str) -> list[str]:
        return sorted(tid for tid, t in self.techniques.items() if t.get("parent") == parent)

    def search(
        self, query: str, tactic: str | None = None, platform: str | None = None, limit: int = 10
    ) -> list[dict[str, Any]]:
        """Case-insensitive search on ID and name; every query word must match."""
        words = query.lower().split()
        hits: list[tuple[int, str]] = []
        for tid, tech in self.techniques.items():
            if tactic and tactic not in tech["tactics"]:
                continue
            if platform and platform.lower() not in {p.lower() for p in tech["platforms"]}:
                continue
            haystack = f"{tid} {tech['name']}".lower()
            if not all(w in haystack for w in words):
                continue
            # Rank: exact ID, then name starting with the query, then parents before sub-techniques.
            if tid.lower() == query.strip().lower():
                rank = 0
            elif tech["name"].lower().startswith(query.strip().lower()):
                rank = 1
            else:
                rank = 2 if not tech["subtechnique"] else 3
            hits.append((rank, tid))
        hits.sort()
        return [self.summary(tid) for _, tid in hits[:limit]]

    def summary(self, tid: str) -> dict[str, Any]:
        """Compact description of a technique, as returned to the LLM."""
        tech = self.techniques[tid]
        return {
            "id": tid,
            "name": tech["name"],
            "tactics": tech["tactics"],
            "platforms": tech["platforms"],
            "data_components": tech["data_components"],
        }


@lru_cache(maxsize=4)
def load_attack(path: str | Path = DATA_PATH) -> AttackData:
    """Load (and cache) the compact dataset."""
    with open(path, encoding="utf-8") as fh:
        return AttackData.from_dict(json.load(fh))
