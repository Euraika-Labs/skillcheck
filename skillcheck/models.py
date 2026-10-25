from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    NOTE = "note"
    WARNING = "warning"
    ERROR = "error"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class TargetKind(StrEnum):
    SKILL_MD = "skill_md"
    REFERENCE_MD = "reference_md"
    SCRIPT = "script"
    HOOK_CONFIG = "hook_config"
    MCP_MANIFEST = "mcp_manifest"
    OTHER_TEXT = "other_text"


class Finding(BaseModel):
    rule_id: str
    title: str
    message: str
    severity: Severity
    confidence: Confidence
    path: str
    line: int
    evidence: str = ""
    fingerprint: str = ""


class Target(BaseModel):
    """A single loaded unit to scan: a file from disk or from the corpus."""

    kind: TargetKind
    path: str
    content: str

    @property
    def lines(self) -> list[str]:
        return self.content.splitlines()


class CorpusEntry(BaseModel):
    """A discovered file in the corpus (GitHub search result)."""

    repo: str
    path: str
    sha: str = ""
    html_url: str = ""

    @property
    def key(self) -> str:
        return f"{self.repo}/{self.path}"


class CorpusState(BaseModel):
    """Dedupe state: which corpus entries were already scanned at which sha."""

    version: str = "1"
    scanned: dict[str, str] = Field(default_factory=dict)  # key -> sha


class ScanReport(BaseModel):
    version: str = "1"
    root: str
    scanned_targets: int = 0
    findings: list[Finding] = Field(default_factory=list)
