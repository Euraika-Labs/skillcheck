from __future__ import annotations

from pathlib import Path

import pytest

from tests.conftest import FIXTURES, load_target, rule_by_id

RULE_IDS = sorted(d.name for d in FIXTURES.iterdir() if d.is_dir())


@pytest.mark.parametrize("rule_id", RULE_IDS)
class TestRuleFixtures:
    def test_positive_fixture_triggers(self, rule_id: str) -> None:
        rule = rule_by_id(rule_id)
        positives = sorted((FIXTURES / rule_id / "positive").rglob("*"))
        assert positives, f"rule {rule_id} has no positive fixtures"
        triggered = 0
        for path in positives:
            if not path.is_file():
                continue
            target = load_target(path, FIXTURES / rule_id / "positive")
            if not rule.applies_to(target.kind):
                continue
            if rule.scan(target):
                triggered += 1
        assert triggered > 0, f"rule {rule_id} triggered on no positive fixture"

    def test_negative_fixture_is_clean(self, rule_id: str) -> None:
        rule = rule_by_id(rule_id)
        negatives = sorted((FIXTURES / rule_id / "negative").rglob("*"))
        assert negatives, f"rule {rule_id} has no negative fixtures"
        for path in negatives:
            if not path.is_file():
                continue
            target = load_target(path, FIXTURES / rule_id / "negative")
            if not rule.applies_to(target.kind):
                continue
            findings = rule.scan(target)
            assert not findings, (
                f"rule {rule_id} flagged negative fixture {target.path}: "
                f"{[f.message for f in findings]}"
            )
