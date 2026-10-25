from __future__ import annotations

from pathlib import PurePosixPath

from skillcheck.models import TargetKind

_HOOK_CONFIG_NAMES = {"settings.json", "hooks.json", "hooktasks.json", "config.yaml", "config.yml"}
_MCP_MANIFEST_NAMES = {
    "claude_desktop_config.json",
    "mcp.json",
    "mcp_servers.json",
    "claude.json",
}


def classify(path: str, content: str) -> TargetKind:
    """Classify a file path into a scan target kind.

    Deterministic: same path and same manifest markers always classify the same.
    Content is only consulted for manifest detection where the filename alone is
    ambiguous (package.json may or may not declare mcpServers).
    """
    p = PurePosixPath(path)
    name = p.name.lower()
    parts = {part.lower() for part in p.parts}

    if name == "skill.md":
        return TargetKind.SKILL_MD

    if name.endswith((".md", ".mdx")):
        return TargetKind.REFERENCE_MD

    if name.endswith((".sh", ".bash", ".zsh", ".ps1", ".py", ".js", ".ts", ".mjs", ".cjs")):
        return TargetKind.SCRIPT

    if name in _MCP_MANIFEST_NAMES:
        return TargetKind.MCP_MANIFEST

    if name in _HOOK_CONFIG_NAMES and any(
        part.startswith(".claude") or part.startswith(".codex") or part == ".agent" for part in parts
    ):
        return TargetKind.HOOK_CONFIG

    if name == "package.json" and '"mcpServers"' in content:
        return TargetKind.MCP_MANIFEST

    if name == "settings.json":
        # Claude Code settings files double as hook configurations.
        if any(part.startswith(".claude") for part in parts) or '"hooks"' in content:
            return TargetKind.HOOK_CONFIG

    if any(part.startswith(".claude") or part.startswith(".cursor") for part in parts):
        if name.endswith(".json"):
            return TargetKind.MCP_MANIFEST

    if name.endswith((".json", ".yaml", ".yml", ".toml")):
        return TargetKind.OTHER_TEXT

    return TargetKind.OTHER_TEXT
