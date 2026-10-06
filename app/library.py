"""The scenario library: YAML files in `scenarios/`, one scenario per file."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

LIBRARY_DIR = Path(__file__).resolve().parent.parent / "scenarios"


def to_yaml(scenario: dict[str, Any]) -> str:
    """Serialise a scenario as YAML, keeping the field order of the dict."""
    return yaml.safe_dump(scenario, sort_keys=False, allow_unicode=True, width=110)


def load_library(directory: str | Path = LIBRARY_DIR) -> list[dict[str, Any]]:
    """Load every `*.yaml` scenario, sorted by file name."""
    scenarios = []
    for path in sorted(Path(directory).glob("*.yaml")):
        with open(path, encoding="utf-8") as fh:
            scenarios.append(yaml.safe_load(fh))
    return scenarios


def select(scenarios: list[dict[str, Any]], ids: list[str] | None) -> list[dict[str, Any]]:
    """Scenarios with the given IDs (all if `ids` is empty); raises KeyError on unknown IDs."""
    if not ids:
        return scenarios
    by_id = {s["id"]: s for s in scenarios}
    missing = [i for i in ids if i not in by_id]
    if missing:
        raise KeyError(f"unknown scenario ids {missing}; library has {sorted(by_id)}")
    return [by_id[i] for i in ids]


def next_id(scenarios: list[dict[str, Any]]) -> str:
    """First free SCN-nnn ID after the highest one in the library."""
    numbers = [int(s["id"].split("-")[1]) for s in scenarios if str(s.get("id", "")).startswith("SCN-")]
    return f"SCN-{max(numbers, default=0) + 1:03d}"
