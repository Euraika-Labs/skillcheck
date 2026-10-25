from __future__ import annotations

import re

from skillcheck.models import Confidence, Finding, Severity, Target, TargetKind
from skillcheck.rules.base import Rule, iter_line_matches

# Download-and-execute: remote code runs at install/startup time.
_PIPE_SHELL_RE = re.compile(
    r"(?:curl|wget)[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da|a)?sh\b|"
    r"\|\s*(?:sudo\s+)?(?:ba|z|a)?sh\s+(?:-c\s+)?[\"']|"
    r"(?:pip|pip3|uv)\s+install\s+(?:git\+)?https?://|"
    r"npm\s+install\s+(?:-g\s+)?https?://",
    re.IGNORECASE,
)


class PipeToShell(Rule):
    rule_id = "SC008"
    title = "Downloads remote code and executes it"
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
        for line_no, line, _m in iter_line_matches(target.lines, _PIPE_SHELL_RE):
            findings.append(
                self.build_finding(
                    target=target,
                    line=line_no,
                    message=(
                        "Line fetches remote code and executes it (pipe to shell, or install "
                        "directly from a URL). The executed content is unpinned and can change "
                        "after review."
                    ),
                    severity=Severity.ERROR,
                    confidence=Confidence.HIGH,
                    evidence=line.strip()[:200],
                )
            )
        return findings
