from __future__ import annotations

from skillcheck.scanner import scan_path
from skillcheck.targets import classify

from tests.conftest import FIXTURES, load_target


def test_scanner_reports_findings_across_fixture_tree() -> None:
    report = scan_path(FIXTURES)
    assert report.scanned_targets > 0
    assert report.findings, "scanner found nothing in a fixture tree full of positives"
    rule_ids = {f.rule_id for f in report.findings}
    assert {"SC001", "SC002", "SC003"} <= rule_ids


def test_classify_kinds() -> None:
    assert classify("SKILL.md", "").value == "skill_md"
    assert classify("docs/guide.md", "").value == "reference_md"
    assert classify("scripts/setup.sh", "").value == "script"
    assert classify(".claude/settings.json", "{}").value == "hook_config"
    assert classify("claude_desktop_config.json", "{}").value == "mcp_manifest"
    assert classify("package.json", '{"mcpServers": {}}').value == "mcp_manifest"
    assert classify("package.json", '{"name": "x"}').value == "other_text"
