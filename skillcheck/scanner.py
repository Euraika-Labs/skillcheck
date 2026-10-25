from __future__ import annotations

from pathlib import Path

from skillcheck.models import ScanReport, Target
from skillcheck.rules import scan_target
from skillcheck.targets import classify

_TEXT_SUFFIXES = {
    ".md", ".mdx", ".json", ".yaml", ".yml", ".toml", ".txt",
    ".sh", ".bash", ".zsh", ".ps1", ".py", ".js", ".ts", ".mjs", ".cjs",
}


def scan_path(root: Path) -> ScanReport:
    """Scan every text file under root (or the single file root itself)."""
    report = ScanReport(root=str(root))

    if root.is_file():
        files = [root]
    else:
        files = sorted(
            p for p in root.rglob("*")
            if p.is_file() and p.suffix.lower() in _TEXT_SUFFIXES and "node_modules" not in p.parts
        )

    for path in files:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(root) if root.is_dir() else path.name)
        target = Target(kind=classify(rel, content), path=rel, content=content)
        report.scanned_targets += 1
        report.findings.extend(scan_target(target))

    report.findings.sort(key=lambda f: (f.path, f.line, f.rule_id))
    return report
