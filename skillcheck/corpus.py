from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request

from skillcheck.models import CorpusEntry, CorpusState

_GITHUB_API = "https://api.github.com"
_RAW = "https://raw.githubusercontent.com"

# Code-search queries that surface agent-ecosystem install surface.
# Each entry: (label, query). Queries target filenames and paths only —
# no content judgements happen at discovery time.
DEFAULT_QUERIES: list[tuple[str, str]] = [
    ("skills", "filename:SKILL.md"),
    ("claude-hooks", "filename:settings.json path:.claude"),
    ("mcp-desktop", "filename:claude_desktop_config.json"),
    ("mcp-json", "filename:mcp.json"),
    ("mcp-package", '"mcpServers" filename:package.json'),
]

# Never scan our own repositories: findings there are not third-party evidence
# and would pollute the queue.
EXCLUDED_OWNER = "Euraika-Labs"


class GitHubClient:
    """Minimal read-only GitHub REST client (stdlib only)."""

    def __init__(self, token: str | None = None, per_page: int = 30):
        self.token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("SKILLCHECK_GITHUB_TOKEN") or ""
        self.per_page = per_page

    def _get(self, url: str, accept: str = "application/vnd.github+json") -> bytes:
        req = urllib.request.Request(url, headers={
            "Accept": accept,
            "User-Agent": "skillcheck",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            return resp.read()

    def search_code(self, query: str, max_results: int = 100) -> list[CorpusEntry]:
        entries: list[CorpusEntry] = []
        seen: set[str] = set()
        pages = max(1, max_results // self.per_page)
        for page in range(1, pages + 1):
            q = urllib.parse.quote(query, safe="")
            url = f"{_GITHUB_API}/search/code?q={q}&per_page={self.per_page}&page={page}"
            body = json.loads(self._get(url))
            items = body.get("items", [])
            if not items:
                break
            for item in items:
                repo = item["repository"]["full_name"]
                path = item["path"]
                key = f"{repo}/{path}"
                if repo.split("/")[0] == EXCLUDED_OWNER or key in seen:
                    continue
                seen.add(key)
                entries.append(
                    CorpusEntry(
                        repo=repo,
                        path=path,
                        sha=item.get("sha", ""),
                        html_url=item.get("html_url", ""),
                    )
                )
            time.sleep(6)  # code search rate limit: 10/min authenticated
        return entries

    def fetch_content(self, entry: CorpusEntry, ref: str = "HEAD") -> str:
        url = f"{_RAW}/{entry.repo}/{ref}/{entry.path}"
        return self._get(url, accept="text/plain").decode("utf-8", errors="replace")


def discover(
    client: GitHubClient,
    state: CorpusState,
    queries: list[tuple[str, str]] | None = None,
    max_results_per_query: int = 100,
) -> list[CorpusEntry]:
    """Discover corpus entries not yet scanned (new repos/paths or changed sha)."""
    fresh: list[CorpusEntry] = []
    for _label, query in queries or DEFAULT_QUERIES:
        for entry in client.search_code(query, max_results=max_results_per_query):
            if state.scanned.get(entry.key) != entry.sha:
                fresh.append(entry)
    return fresh
