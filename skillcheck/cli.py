from __future__ import annotations

import json
from pathlib import Path

import typer

from skillcheck import __version__
from skillcheck.corpus import DEFAULT_QUERIES, CorpusState, GitHubClient, discover
from skillcheck.models import CorpusEntry, ScanReport, Target
from skillcheck.rules import ALL_RULES, scan_target
from skillcheck.scanner import scan_path
from skillcheck.targets import classify

app = typer.Typer(
    add_completion=False,
    help="Deterministic scanner for Agent Skills, hooks and MCP server manifests.",
)


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)


@app.command("rules")
def rules_cmd() -> None:
    """List all rules."""
    for rule in ALL_RULES:
        typer.echo(f"{rule.rule_id}  {rule.title}")


@app.command()
def scan(
    path: Path = typer.Argument(..., exists=True, help="File or directory to scan"),
    json_out: bool = typer.Option(False, "--json", help="Emit the report as JSON"),
) -> None:
    """Scan a local file or directory."""
    report = scan_path(path)
    if json_out:
        typer.echo(report.model_dump_json(indent=2))
    else:
        typer.echo(f"Scanned {report.scanned_targets} targets under {report.root}")
        for f in report.findings:
            typer.echo(f"  {f.severity.value.upper():7} {f.rule_id} {f.path}:{f.line}  {f.evidence[:80]}")
        typer.echo(f"{len(report.findings)} findings")
    if report.findings:
        raise typer.Exit(code=1)


@app.command()
def scan_corpus(
    state_file: Path = typer.Option(Path("state.json"), help="Corpus dedupe state"),
    out_dir: Path = typer.Option(Path("findings"), help="Directory for per-finding queue files"),
    state_out: Path = typer.Option(None, help="Where to write updated state (default: state_file)"),
    max_results: int = typer.Option(100, help="Max results per discovery query"),
    since_scratch: bool = typer.Option(False, help="Ignore existing state and rescan everything"),
) -> None:
    """Discover new corpus entries on GitHub, scan them, and write queue files.

    Findings are written one JSON file per fingerprint into out_dir/open/,
    which is the private triage queue. They are never printed to stdout —
    this command is safe to run in CI on public logs.
    """
    state = CorpusState()
    if state_file.exists() and not since_scratch:
        state = CorpusState.model_validate_json(state_file.read_text())

    client = GitHubClient()
    if not client.token:
        typer.echo("ERROR: set GITHUB_TOKEN or SKILLCHECK_GITHUB_TOKEN (code search requires auth).", err=True)
        raise typer.Exit(code=2)

    open_dir = out_dir / "open"
    dismissed_dir = out_dir / "dismissed"
    published_dir = out_dir / "published"
    for d in (open_dir, dismissed_dir, published_dir):
        d.mkdir(parents=True, exist_ok=True)

    known_fingerprints: set[str] = set()
    for d in (open_dir, dismissed_dir, published_dir):
        for p in d.glob("*.json"):
            try:
                known_fingerprints.add(json.loads(p.read_text())["fingerprint"])
            except (OSError, KeyError, ValueError):
                continue

    fresh = discover(client, state, DEFAULT_QUERIES, max_results_per_query=max_results)
    typer.echo(f"Discovered {len(fresh)} new or changed corpus entries.")

    new_state = state.model_copy(deep=True)
    new_findings = 0
    for entry in fresh:
        try:
            content = client.fetch_content(entry)
        except (OSError, ValueError) as exc:
            typer.echo(f"  skip {entry.key}: fetch failed ({exc})", err=True)
            continue
        target = Target(kind=classify(entry.path, content), path=entry.key, content=content)
        findings = scan_target(target)
        for f in findings:
            if f.fingerprint in known_fingerprints:
                continue
            record = {
                **f.model_dump(),
                "repo": entry.repo,
                "path_in_repo": entry.path,
                "html_url": entry.html_url,
            }
            (open_dir / f"{f.fingerprint[:16]}.json").write_text(
                json.dumps(record, indent=2) + "\n", encoding="utf-8"
            )
            known_fingerprints.add(f.fingerprint)
            new_findings += 1
        new_state.scanned[entry.key] = entry.sha

    out = state_out or state_file
    out.write_text(new_state.model_dump_json(indent=2), encoding="utf-8")
    typer.echo(f"Queued {new_findings} new findings. State written to {out}.")


@app.command()
def advisory_entry(
    cve_id: str = typer.Option(..., "--id", help="CVE or GHSA identifier"),
    title: str = typer.Option(..., help="One-line title"),
    target: str = typer.Option(..., help="Affected repo or package"),
    url: str = typer.Option(..., help="Link to the advisory"),
    published: str = typer.Option(..., help="Publication date, YYYY-MM-DD"),
    summary: str = typer.Option("", help="One-sentence summary"),
) -> None:
    """Emit a TypeScript entry for the euraika-labs.net advisory ledger."""
    entry = {
        "id": cve_id,
        "title": title,
        "target": target,
        "url": url,
        "publishedAt": published,
        **({"summary": summary} if summary else {}),
    }
    typer.echo("Add to lib/advisories.ts:")
    typer.echo(json.dumps(entry, indent=2))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
