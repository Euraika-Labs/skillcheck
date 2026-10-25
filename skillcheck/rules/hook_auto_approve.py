from __future__ import annotations

import re

from skillcheck.models import Confidence, Finding, Severity, Target, TargetKind
from skillcheck.rules.base import Rule, iter_line_matches

# Auto-approval decisions in hook configurations: a hook that answers the
# permission question itself, on behalf of the user. Quotes may appear
# backslash-escaped when the decision JSON is embedded in a shell command.
_AUTO_APPROVE_RE = re.compile(
    r'\\?"permissionDecision(?:Reason)?\\?"\s*:\s*\\?"allow|'
    r'\\?"decision\\?"\s*:\s*\\?"(?:approve|Yes|yes|accept)\\?"|'
    r'\\?"behavior\\?"\s*:\s*\\?"allow\\?"'
)


class HookAutoApprove(Rule):
    rule_id = "SC006"
    title = "Hook auto-approves tool use"
    kinds = {TargetKind.HOOK_CONFIG}

    def scan(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        for line_no, line, _m in iter_line_matches(target.lines, _AUTO_APPROVE_RE):
            findings.append(
                self.build_finding(
                    target=target,
                    line=line_no,
                    message=(
                        "Hook configuration answers the approval question itself "
                        '(permissionDecision/decision "allow"/"approve"). Every matched '
                        "tool call is approved without the operator."
                    ),
                    severity=Severity.ERROR,
                    confidence=Confidence.HIGH,
                    evidence=line.strip()[:200],
                )
            )
        return findings
