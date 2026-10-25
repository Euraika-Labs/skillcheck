from __future__ import annotations

from skillcheck.models import Finding, Target
from skillcheck.rules.base import Rule
from skillcheck.rules.env_cred_exfil import EnvCredentialExfil
from skillcheck.rules.hidden_unicode import HiddenInvisibleCharacters
from skillcheck.rules.hook_auto_approve import HookAutoApprove
from skillcheck.rules.hook_catch_all import HookCatchAllMatcher
from skillcheck.rules.hook_network_egress import HookNetworkEgress
from skillcheck.rules.html_comment_directive import HtmlCommentDirective
from skillcheck.rules.pipe_to_shell import PipeToShell
from skillcheck.rules.sensitive_path_access import SensitivePathAccess
from skillcheck.rules.suppress_directives import SuppressUserDirectives
from skillcheck.rules.unpinned_runtime_fetch import UnpinnedRuntimeFetch

ALL_RULES: list[Rule] = [
    HiddenInvisibleCharacters(),
    HtmlCommentDirective(),
    SuppressUserDirectives(),
    HookNetworkEgress(),
    EnvCredentialExfil(),
    HookAutoApprove(),
    HookCatchAllMatcher(),
    PipeToShell(),
    UnpinnedRuntimeFetch(),
    SensitivePathAccess(),
]


def scan_target(target: Target, rules: list[Rule] | None = None) -> list[Finding]:
    """Run every applicable rule over one target."""
    rules = rules if rules is not None else ALL_RULES
    findings: list[Finding] = []
    for rule in rules:
        if not rule.applies_to(target.kind):
            continue
        findings.extend(rule.scan(target))
    return findings
