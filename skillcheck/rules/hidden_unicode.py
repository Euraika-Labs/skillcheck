from __future__ import annotations

import re

from skillcheck.models import Confidence, Finding, Severity, Target, TargetKind
from skillcheck.rules.base import Rule, iter_line_matches

# Zero-width and directional-override characters: invisible in every editor,
# they can alter what a model reads versus what a human sees.
_INVISIBLE_RE = re.compile(
    "[\u00ad\u180e\u200b\u200c\u200d\u2060\ufeff"
    "\u202a\u202b\u202c\u202d\u202e"
    "\u2066\u2067\u2068\u2069]"
)

_DESCRIPTIONS = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE (BOM)",
    "\u00ad": "SOFT HYPHEN",
    "\u180e": "MONGOLIAN VOWEL SEPARATOR",
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u2069": "POP DIRECTIONAL ISOLATE",
}


class HiddenInvisibleCharacters(Rule):
    rule_id = "SC001"
    title = "Hidden invisible characters"
    kinds = {
        TargetKind.SKILL_MD,
        TargetKind.REFERENCE_MD,
        TargetKind.SCRIPT,
        TargetKind.HOOK_CONFIG,
        TargetKind.MCP_MANIFEST,
        TargetKind.OTHER_TEXT,
    }

    def scan(self, target: Target) -> list[Finding]:
        findings = []
        for line_no, line, _m in iter_line_matches(target.lines, _INVISIBLE_RE):
            chars = ", ".join(
                _DESCRIPTIONS.get(ch, f"U+{ord(ch):04X}") for ch in _INVISIBLE_RE.findall(line)
            )
            findings.append(
                self.build_finding(
                    target=target,
                    line=line_no,
                    message=(
                        "Line contains invisible Unicode characters that change what a model "
                        f"reads without changing what a human sees: {chars}."
                    ),
                    severity=Severity.ERROR,
                    confidence=Confidence.HIGH,
                    evidence=line.strip()[:120],
                )
            )
        return findings
