from __future__ import annotations

from abc import ABC, abstractmethod
from hashlib import sha256

from skillcheck.models import Confidence, Finding, Severity, Target, TargetKind


class Rule(ABC):
    """Base class for all skillcheck rules.

    A rule must be deterministic: the same target content must always produce
    the same findings. Every rule ships with fixtures that trigger it and
    fixtures that must not (see tests/fixtures/).
    """

    rule_id: str
    title: str
    kinds: set[TargetKind]

    def applies_to(self, kind: TargetKind) -> bool:
        return kind in self.kinds

    @staticmethod
    def fingerprint(*parts: str) -> str:
        return sha256("\x00".join(parts).encode("utf-8")).hexdigest()

    def build_finding(
        self,
        *,
        target: Target,
        line: int,
        message: str,
        severity: Severity,
        confidence: Confidence,
        evidence: str,
    ) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            message=message,
            severity=severity,
            confidence=confidence,
            path=target.path,
            line=line,
            evidence=evidence[:300],
            fingerprint=self.fingerprint(self.rule_id, target.path, str(line), evidence[:300]),
        )

    @abstractmethod
    def scan(self, target: Target) -> list[Finding]:
        raise NotImplementedError


def iter_line_matches(lines: list[str], pattern) -> list[tuple[int, str, "re.Match"]]:
    """Yield (1-based line number, line text, match) for every line matching."""
    out = []
    for idx, line in enumerate(lines, start=1):
        m = pattern.search(line)
        if m:
            out.append((idx, line, m))
    return out
