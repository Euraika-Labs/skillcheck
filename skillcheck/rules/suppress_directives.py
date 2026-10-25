from __future__ import annotations

import re

from skillcheck.models import Confidence, Finding, Severity, Target, TargetKind
from skillcheck.rules.base import Rule, iter_line_matches

# Phrases that instruct the model to act against the operator's visibility
# or to override prior context. Matched anywhere in text the model reads.
_SUPPRESS_RE = re.compile(
    r"\b(?:ignore (?:all )?(?:previous|prior|above|earlier) (?:instructions|context|rules|directives)|"
    r"disregard (?:all )?(?:previous|prior|above) (?:instructions|context|rules)|"
    r"do not tell the (?:user|operator)|don't tell the (?:user|operator)|"
    r"without (?:telling|informing|notifying) the (?:user|operator)|"
    r"hide (?:this|it|these) from the (?:user|operator)|"
    r"do not reveal (?:this|these|the following)|"
    r"never (?:mention|disclose|report) (?:this|it|these) (?:to (?:the )?(?:user|operator|human)|in (?:the )?(?:output|summary|log)))\b",
    re.IGNORECASE,
)


class SuppressUserDirectives(Rule):
    rule_id = "SC003"
    title = "Instructions to suppress or override the operator"
    kinds = {
        TargetKind.SKILL_MD,
        TargetKind.REFERENCE_MD,
        TargetKind.SCRIPT,
        TargetKind.HOOK_CONFIG,
        TargetKind.MCP_MANIFEST,
        TargetKind.OTHER_TEXT,
    }

    def scan(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        for line_no, line, _m in iter_line_matches(target.lines, _SUPPRESS_RE):
            findings.append(
                self.build_finding(
                    target=target,
                    line=line_no,
                    message=(
                        "Line instructs the model to hide actions from the operator or to "
                        "ignore prior instructions."
                    ),
                    severity=Severity.ERROR,
                    confidence=Confidence.MEDIUM,
                    evidence=line.strip()[:200],
                )
            )
        return findings
