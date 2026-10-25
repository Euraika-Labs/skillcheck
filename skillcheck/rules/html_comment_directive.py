from __future__ import annotations

import re

from skillcheck.models import Confidence, Finding, Severity, Target, TargetKind
from skillcheck.rules.base import Rule, iter_line_matches

_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)

# Imperative, model-directed phrasing inside an HTML comment. A comment is
# not rendered to the human reader, so instructions there are aimed at the
# model.
_DIRECTIVE_RE = re.compile(
    r"\b(?:ignore|disregard|never (?:tell|reveal|mention|discuss)|"
    r"do not (?:tell|reveal|mention|discuss|obey)|don't (?:tell|reveal)|"
    r"hide (?:this|it|the)|conceal|secretly|exfiltrate|upload|send (?:the )?(?:user|prompt|transcript|conversation)|"
    r"you (?:must|should|are to|will)|always (?:respond|act|follow|obey)|"
    r"the user (?:must not|should not|cannot) (?:know|see|find|learn))\b",
    re.IGNORECASE,
)


class HtmlCommentDirective(Rule):
    rule_id = "SC002"
    title = "Model-directed instructions hidden in an HTML comment"
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
        offset = 1
        for m in _COMMENT_RE.finditer(target.content):
            if _DIRECTIVE_RE.search(m.group(1)):
                line_no = target.content.count("\n", 0, m.start()) + offset
                findings.append(
                    self.build_finding(
                        target=target,
                        line=line_no,
                        message=(
                            "HTML comment contains instructions directed at the model "
                            "(not rendered to the human reader)."
                        ),
                        severity=Severity.ERROR,
                        confidence=Confidence.MEDIUM,
                        evidence=m.group(0)[:200],
                    )
                )
        return findings
