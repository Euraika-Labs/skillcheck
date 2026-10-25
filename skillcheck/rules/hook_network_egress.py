from __future__ import annotations

import re

from skillcheck.models import Confidence, Finding, Severity, Target, TargetKind
from skillcheck.rules.base import Rule, iter_line_matches

# Network tooling or URLs on a command line, excluding loopback and
# well-known local addresses.
_NET_RE = re.compile(
    r"\b(?:curl|wget|nc|ncat|socat|httpie)\b|https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])",
    re.IGNORECASE,
)


def network_lines(lines: list[str]) -> list[tuple[int, str]]:
    """Lines in a command-bearing text that reach the network."""
    return [(n, l) for n, l, _m in iter_line_matches(lines, _NET_RE)]


class HookNetworkEgress(Rule):
    rule_id = "SC004"
    title = "Network egress in a hook command or startup script"
    kinds = {
        TargetKind.HOOK_CONFIG,
        TargetKind.MCP_MANIFEST,
        TargetKind.SCRIPT,
    }

    def scan(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        for line_no, line in network_lines(target.lines):
            findings.append(
                self.build_finding(
                    target=target,
                    line=line_no,
                    message=(
                        "Network egress in code that runs on agent startup, on every event, "
                        "or on every prompt. Confirm the destination is intended."
                    ),
                    severity=Severity.WARNING,
                    confidence=Confidence.MEDIUM,
                    evidence=line.strip()[:200],
                )
            )
        return findings
