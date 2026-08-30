# BlastRadius

**Cross-repo infrastructure memory for coding agents.** Knows which of your other repos use an artifact, and tells your agent *before* it changes one.

Not a code graph. There are excellent tools that index functions, classes and imports. BlastRadius indexes the other half — Docker images, Terraform modules, GitHub Actions, Helm charts, npm packages — across every repository you open, and answers the question none of them can: *if I bump this, who breaks?*

```
BlastRadius — cross-repo impact for .github/workflows/ci.yml:
- `actions/checkout` (line 12) — also used by 11 other repo(s):
    org/payments @ main (unpinned) — .github/workflows/deploy.yml:8
    org/web      @ v4   (partial)  — .github/workflows/ci.yml:14
    org/jobs     @ 8f4e…(sha)      — .github/workflows/nightly.yml:6
    …and 8 more
    ⚠ HIGH CVE-2026-1234
```

That block was not requested. A hook pushed it into context the moment the agent opened the file.

## Why hooks, not just MCP

MCP tools are model-elective — the agent may or may not call them. So BlastRadius puts the two things that must always happen into hooks, which the harness runs whether the model thinks to or not:

| Lane | Mechanism | Fires |
|---|---|---|
| **Push** | `PreToolUse` hook on `Read`/`Edit` | Agent opens a manifest → cross-repo impact injected unprompted |
| **Capture** | `Stop` hook | Session ends → manifests missing from the index get flagged for recording |
| **Pull** | MCP tools | Agent explicitly asks: `blast_radius`, `hygiene`, `record_dependencies` |

Only the asking is optional.

## Extraction is the model's job

BlastRadius ships no parsers. Regex-matching `FROM` lines gets multi-stage aliases, templated base images and heredocs wrong — the agent already reads these files correctly. The hook decides *when* extraction is owed; the model does the extraction; BlastRadius stores it, joins it across repos, and watches it.

One rule the tools enforce: **version specs are stored exactly as written.** `^18.2.0` is a range that absorbs every minor release, not an exact pin. Normalising it away before classifying is how a hygiene report ends up confidently wrong.

## Install

```bash
uv tool install blastradius-mcp
```

Then add the plugin, or wire it manually into `~/.claude/settings.json` from `plugin/hooks.json` and `plugin/.mcp.json`.

Everything is local: one SQLite file at `~/.blastradius/index.db`. No account, no server, no API key, nothing leaves your machine.

## Tools

| Tool | Answers |
|---|---|
| `blast_radius(identifier, type?)` | Who else uses this, at which file and line, how tightly pinned, with open CVEs |
| `hygiene(type?, min_consumers?)` | Every shared artifact ranked worst-pinned first, flagging version drift across repos |
| `record_dependencies(repository, deps)` | Write path — normally driven by the capture hook |

`type` disambiguates names shared across ecosystems: `node` is both a Docker image and an npm package, and they are different rows.

## Status

Early. Working today: the index, the pinning classifier, both hooks, all three MCP tools, 49 tests.

Next: the CVE daemon (OSV polling with local alerts), and packaging to the plugin marketplace.

## License

MIT
