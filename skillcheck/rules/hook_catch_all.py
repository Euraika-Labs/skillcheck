from __future__ import annotations

import re

from skillcheck.models import Confidence, Finding, Severity, Target, TargetKind
from skillcheck.rules.base import Rule, iter_line_matches

# Catch-all matchers: a hook registered for every tool use / every event.
_CATCH_ALL_RE = re.compile(
    r'"matcher"\s*:\s*(?:"(\*|)"|\."\*")|'
    r'"matcher"\s*:\s*"\.\*"',
)


class HookCatchAllMatcher(Rule):
    rule_id = "SC007"
    title = "Hook matches every event"
    kinds = {TargetKind.HOOK_CONFIG}

    def scan(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        for line_no, line, _m in iter_line_matches(target.lines, _CATCH_ALL_RE):
            findings.append(
                self.build_finding(
                    target=target,
                    line=line_no,
                    message=(
                        "Hook is registered with a catch-all matcher (matches every tool use "
                        "or event). Confirm the hook's purpose requires this breadth."
                    ),
                    severity=Severity.WARNING,
                    confidence=Confidence.MEDIUM,
                    evidence=line.strip()[:200],
                )
            )
        return findings
