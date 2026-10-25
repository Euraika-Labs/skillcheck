# skillcheck

> Deterministic scanner for Agent Skills, hooks and MCP server manifests.

**Status: v0.1.0.** 10 rules, each with fixtures that trigger it and fixtures
that must not. Python 3.12+, `pip install git+https://github.com/Euraika-Labs/skillcheck`.

## The question

Coding agents now load third-party instructions and code on startup: Agent Skills (`SKILL.md` plus scripts), lifecycle hooks that run shell commands on every prompt or tool call, and MCP servers that expose tools to the model. Installing one is closer to adding a dependency with shell access than to reading documentation. What does a supply-chain check for that surface look like, and which risky patterns can be caught deterministically, without asking another model?

## Threat model

In scope: a skill, plugin, hook configuration or MCP manifest that a user installs into Claude Code, Codex or a compatible harness, written by someone the user does not fully trust or updated after review.

We look for three classes:

- **Exfiltration paths.** Hooks or scripts that send prompts, transcripts, environment variables, credentials or file contents to the network.
- **Hidden instructions.** Text aimed at the model rather than the reader: zero-width or bidi characters, HTML comments, instructions buried in reference files, directives to ignore the user or hide actions.
- **Over-broad capability.** Hooks on every event, `PreToolUse` hooks that auto-approve, permission grants wider than the stated purpose, unpinned remote code fetched at run time.

Out of scope: the security of the harness itself, and model behaviour once the content is loaded (see [injection-bench](https://github.com/Euraika-Labs/injection-bench)).

## Rules

| ID | Rule |
|---|---|
| SC001 | Hidden invisible characters (zero-width, bidi overrides) |
| SC002 | Model-directed instructions hidden in an HTML comment |
| SC003 | Instructions to suppress or override the operator |
| SC004 | Network egress in a hook command or startup script |
| SC005 | Credential source combined with network egress |
| SC006 | Hook auto-approves tool use |
| SC007 | Hook matches every event |
| SC008 | Downloads remote code and executes it |
| SC009 | Launches a runtime dependency unpinned |
| SC010 | Accesses secrets or sensitive user data |

Every rule is deterministic: same input, same findings. Each ships with
fixtures under `tests/fixtures/<rule>/` — a positive set that must trigger
and a negative set that must stay clean. The negative sets are part of the
rule, not an afterthought: a rule that cannot show what it does *not* catch
is not done.

## Usage

Scan a local directory (exits 1 when findings exist):

```bash
skillcheck scan path/to/skill-or-config
skillcheck scan path/to/repo --json
```

List rules:

```bash
skillcheck rules
```

Corpus mode — discover new public SKILL.md / hook configs / MCP manifests
via GitHub code search, scan them, and queue findings as JSON files for
human triage. Findings are written to disk, never to stdout, so it is safe
to run in CI with public logs:

```bash
export GITHUB_TOKEN=...   # code search requires auth
skillcheck scan-corpus --state-file state.json --out-dir findings
```

Triage works on the queue directory: `findings/open/` (new), `findings/dismissed/`
(benign or not a vulnerability), `findings/published/` (coordinated disclosure
completed, carrying the CVE/GHSA identifier). Moving a file between
directories is the whole workflow; `scan-corpus` dedupes against all three.

## What it will not claim

A clean scan is not a security review. Deterministic rules miss novel and obfuscated payloads by construction. We publish false-positive and false-negative examples next to every rule (the fixtures are the first instalment). Findings are leads for a human, never verdicts.

## Disclosure

If the research surfaces a malicious or vulnerable skill, plugin or server in the wild, we report it privately to its maintainer and the hosting marketplace before publishing details. To report an issue in this repository, see the [security policy](https://github.com/Euraika-Labs/.github/blob/master/SECURITY.md).

---

Maintained by [Euraika-Labs](https://www.euraika-labs.net). MIT licence.
