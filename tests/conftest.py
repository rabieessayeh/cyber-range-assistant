"""Shared fixtures. Everything runs offline against the committed ATT&CK data file."""

from __future__ import annotations

import copy

import pytest

from app.attack import AttackData, load_attack
from app.library import load_library
from app.scenarios import build_scenario


@pytest.fixture(scope="session")
def attack() -> AttackData:
    return load_attack()


@pytest.fixture()
def library() -> list[dict]:
    return copy.deepcopy(load_library())


@pytest.fixture()
def phishing(attack) -> dict:
    """A small valid scenario built by the engine."""
    return build_scenario(
        attack,
        title="Phishing test",
        techniques=["T1486", "T1566.001", "T1059.001"],  # deliberately out of kill-chain order
        level="beginner",
        audience="soc-analyst",
        scenario_id="SCN-901",
    )
