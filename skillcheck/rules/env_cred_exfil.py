from __future__ import annotations

import re

from skillcheck.models import Confidence, Finding, Severity, Target, TargetKind
from skillcheck.rules.base import Rule
from skillcheck.rules.hook_network_egress import network_lines

# Sources of secrets and user data: environment, shell history, SSH keys,
# cloud credentials, keychains.
_CRED_SOURCE_RE = re.compile(
    r"\b(?:process\.env|os\.environ|os\.getenv|getenv\(|"
    r"~?/\.ssh/|id_rsa|id_ed25519|authorized_keys|known_hosts|"
    r"\.aws/credentials|\.netrc|\.env\b|"
    r"\.zsh_history|\.bash_history|\.config/gcloud|legacy_credentials|"
    r"keychain|Keychain|bitwarden|1Password|keepass|LastPass)\b",
    re.IGNORECASE,
)


class EnvCredentialExfil(Rule):
    rule_id = "SC005"
    title = "Credential source combined with network egress"
    kinds = {
        TargetKind.HOOK_CONFIG,
        TargetKind.MCP_MANIFEST,
        TargetKind.SCRIPT,
    }

    def scan(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        net = network_lines(target.lines)
        if not net:
            return findings
        net_lines = {n for n, _ in net}
        for line_no, line in enumerate(target.lines, start=1):
            if _CRED_SOURCE_RE.search(line):
                # Same line, or a network line elsewhere in the same unit:
                # the unit both reads credentials and can send data out.
                related = line_no if line_no in net_lines else net_lines and min(net_lines)
                findings.append(
                    self.build_finding(
                        target=target,
                        line=line_no,
                        message=(
                            "Reads a credential or user-data source (environment, SSH keys, "
                            "cloud credentials, shell history, password store) in a unit "
                            "that also performs network egress. This is an exfiltration path."
                        ),
                        severity=Severity.ERROR,
                        confidence=Confidence.HIGH,
                        evidence=line.strip()[:200],
                    )
                )
                break  # one finding per target unit is enough to triage
        return findings
