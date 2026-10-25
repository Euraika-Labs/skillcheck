# skillcheck

> Deterministic scanner for Agent Skills, hooks and MCP server manifests.

**Status: research in progress.** No release yet. The rule set below is the plan, not a feature list.

## The question

Coding agents now load third-party instructions and code on startup: Agent Skills (`SKILL.md` plus scripts), lifecycle hooks that run shell commands on every prompt or tool call, and MCP servers that expose tools to the model. Installing one is closer to adding a dependency with shell access than to reading documentation. What does a supply-chain check for that surface look like, and which risky patterns can be caught deterministically, without asking another model?

## Threat model

In scope: a skill, plugin, hook configuration or MCP manifest that a user installs into Claude Code, Codex or a compatible harness, written by someone the user does not fully trust or updated after review.

We look for three classes:

- **Exfiltration paths.** Hooks or scripts that send prompts, transcripts, environment variables, credentials or file contents to the network.
- **Hidden instructions.** Text aimed at the model rather than the reader: zero-width or bidi characters, HTML comments, instructions buried in reference files, directives to ignore the user or hide actions.
- **Over-broad capability.** Hooks on every event, `PreToolUse` hooks that auto-approve, permission grants wider than the stated purpose, unpinned remote code fetched at run time.

Out of scope: the security of the harness itself, and model behaviour once the content is loaded (see [injection-bench](https://github.com/Euraika-Labs/injection-bench)).

## Method

The approach of [ai-slopcheck](https://github.com/Euraika-Labs/ai-slopcheck): rules that produce the same finding on the same input every time, each with a fixture that triggers it and one that must not. Findings are put in front of a human; nothing is auto-fixed or auto-blocked.

## What it will not claim

A clean scan is not a security review. Deterministic rules miss novel and obfuscated payloads by construction. We will publish false-positive and false-negative examples next to every rule.

## Disclosure

If the research surfaces a malicious or vulnerable skill, plugin or server in the wild, we report it privately to its maintainer and the hosting marketplace before publishing details. To report an issue in this repository, see the [security policy](https://github.com/Euraika-Labs/.github/blob/master/SECURITY.md).

---

Maintained by [Euraika-Labs](https://www.euraika-labs.net). MIT licence.
