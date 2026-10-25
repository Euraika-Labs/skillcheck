from __future__ import annotations

import re

from skillcheck.models import Confidence, Finding, Severity, Target, TargetKind
from skillcheck.rules.base import Rule

# Runtime fetchers used in MCP/hook launch commands. `npx pkg`,
# `npx pkg@latest`, `uvx pkg` all resolve to the latest published version
# at every launch; only a pinned version (`pkg@1.2.3`, `pkg==0.1.4`) is
# reviewable.
#
# In manifests the launcher and its arguments sit on different lines
# (`"command": "npx"` + a separate `"args"` array), so this rule works on
# a content window after each launcher occurrence, not on single lines.
_LAUNCHER_RE = re.compile(r"\b(?:npx|npm\s+exec|uvx|pipx|bunx|deno\s+run)\b")

_WINDOW = 220
_JSON_PUNCT = str.maketrans({c: " " for c in "\"'[]{}(),"})

# Structural keys that may appear between the launcher and its package.
_STRUCTURAL_TOKENS = {
    "args", "command", "env", "type", "hooks", "matcher",
    "mcpServers", "true", "false", "null",
}
_PKG_SHAPE = re.compile(r"^@?[A-Za-z0-9_.\-]+(/[A-Za-z0-9_.\-]+)?(@[^\s]+)?$")


def _pick_package(window: str) -> str | None:
    for token in window.translate(_JSON_PUNCT).split():
        if token.startswith("-") or token in _STRUCTURAL_TOKENS:
            continue
        if _PKG_SHAPE.match(token):
            return token
    return None


def _is_unpinned(pkg_token: str) -> bool:
    body = pkg_token
    if body.startswith("@"):
        body = body[1:]
    if "==" in body:
        return False
    if "@" in body:
        version = body.split("@", 1)[1]
        return version == "" or version == "latest"
    return True


class UnpinnedRuntimeFetch(Rule):
    rule_id = "SC009"
    title = "Launches a runtime dependency unpinned"
    kinds = {TargetKind.MCP_MANIFEST, TargetKind.HOOK_CONFIG}

    def scan(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        seen_lines: set[int] = set()
        for m in _LAUNCHER_RE.finditer(target.content):
            pkg = _pick_package(target.content[m.end() : m.end() + _WINDOW])
            if pkg is None or not _is_unpinned(pkg):
                continue
            line_no = target.content.count("\n", 0, m.start()) + 1
            if line_no in seen_lines:
                continue
            seen_lines.add(line_no)
            line = target.lines[line_no - 1] if line_no <= len(target.lines) else ""
            findings.append(
                self.build_finding(
                    target=target,
                    line=line_no,
                    message=(
                        f"Launch command resolves '{pkg}' to the latest published version "
                        "at every start. The code a user reviewed is not the code that runs."
                    ),
                    severity=Severity.WARNING,
                    confidence=Confidence.MEDIUM,
                    evidence=line.strip()[:200] or pkg,
                )
            )
        return findings
