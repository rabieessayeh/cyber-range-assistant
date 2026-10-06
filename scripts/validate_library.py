"""Validate every scenario in `scenarios/` (schema + ATT&CK semantics). Exit 1 on any error.

Usage:
    python scripts/validate_library.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.attack import load_attack  # noqa: E402
from app.library import load_library  # noqa: E402
from app.scenarios import validate_scenario  # noqa: E402


def main() -> int:
    attack = load_attack()
    scenarios = load_library()
    if not scenarios:
        print("no scenarios found")
        return 1
    failed = 0
    for scenario in scenarios:
        report = validate_scenario(attack, scenario)
        status = "OK  " if report["valid"] else "FAIL"
        print(
            f"{status} {scenario.get('id', '?')}: "
            f"{len(report['errors'])} errors, {len(report['warnings'])} warnings"
        )
        for msg in report["errors"]:
            print(f"     error:   {msg}")
        for msg in report["warnings"]:
            print(f"     warning: {msg}")
        failed += not report["valid"]
    print(f"{len(scenarios) - failed}/{len(scenarios)} scenarios valid (ATT&CK {attack.version})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
