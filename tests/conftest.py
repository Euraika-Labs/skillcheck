from __future__ import annotations

from pathlib import Path

import pytest

from skillcheck.models import Target
from skillcheck.targets import classify

FIXTURES = Path(__file__).parent / "fixtures"


def load_target(path: Path, relative_to: Path) -> Target:
    content = path.read_text(encoding="utf-8")
    rel = str(path.relative_to(relative_to))
    return Target(kind=classify(rel, content), path=rel, content=content)


def rule_by_id(rule_id: str):
    from skillcheck.rules import ALL_RULES

    for rule in ALL_RULES:
        if rule.rule_id == rule_id:
            return rule
    pytest.fail(f"unknown rule id: {rule_id}")
