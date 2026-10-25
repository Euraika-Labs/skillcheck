from __future__ import annotations

import re

from skillcheck.models import Confidence, Finding, Severity, Target, TargetKind
from skillcheck.rules.base import Rule, iter_line_matches

# Direct access to secrets and sensitive user data outside a stated purpose.
_SENSITIVE_PATH_RE = re.compile(
    r"~?/\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.netrc|"
    r"\.config/gcloud|\.kube/config|\.docker/config\.json|"
    r"Login Data|Cookies\b|Web Data|formhistory\.sqlite|"
    r"bitwarden|Bitwarden|1Password|KeePass|keepass|LastPass|"
    r"\.zsh_history|\.bash_history|\.python_history",
    re.IGNORECASE,
)


class SensitivePathAccess(Rule):
    rule_id = "SC010"
    title = "Accesses secrets or sensitive user data"
    kinds = {
        TargetKind.SKILL_MD,
        TargetKind.REFERENCE_MD,
        TargetKind.SCRIPT,
        TargetKind.HOOK_CONFIG,
        TargetKind.MCP_MANIFEST,
    }

    def scan(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        for line_no, line, _m in iter_line_matches(target.lines, _SENSITIVE_PATH_RE):
            findings.append(
                self.build_finding(
                    target=target,
                    line=line_no,
                    message=(
                        "Line touches SSH keys, cloud or kube credentials, browser session "
                        "stores, password-manager data, or shell history. Confirm this access "
                        "is required by the stated purpose."
                    ),
                    severity=Severity.WARNING,
                    confidence=Confidence.MEDIUM,
                    evidence=line.strip()[:200],
                )
            )
        return findings
