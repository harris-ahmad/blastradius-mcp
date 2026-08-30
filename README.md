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
pip install blastradius-mcp
blastradius install      # wires the hooks + MCP server into Claude Code
blastradius link         # puts the CLI on PATH, so no venv activation is needed
blastradius doctor       # verifies it, by running the hooks for real
```

Installing from a virtualenv? The **hooks never need it activated** — `install`
writes absolute paths, and the console script's shebang points at its own
interpreter. `link` does the same for your own shell, so a fresh terminal tab
just works.

Once installed, one script takes you from there to ready-to-test:

```bash
./verify.sh                 # checks wiring, builds fixtures, proves inject fires
./verify.sh --reset-index   # ...and wipes the index first, for a clean measurement
```

It fails fast with the specific fix for each problem rather than a stack trace,
proves the push lane using a throwaway index so your real one is never touched,
and ends by printing the exact sessions to run.

Working on it locally:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest -q      # `python -m` beats a global pytest shadowing the venv
```

`install` merges into `~/.claude/settings.json` rather than overwriting it —
existing keys and other people's hooks are preserved, re-running never
duplicates, and the previous file is backed up first. `blastradius uninstall`
reverses it cleanly. Use `--dry-run` to see the merge before it happens.

It writes an absolute path to the binary, because hooks inherit Claude Code's
environment rather than your shell's, and a bare `blastradius` that fails to
resolve fails *silently* — indistinguishable from a hook with nothing to say.

Everything is local: one SQLite file at `~/.blastradius/index.db`. No account,
no server, no API key, nothing leaves your machine.

## Tools

| Tool | Answers |
|---|---|
| `blast_radius(identifier, type?)` | Who else uses this, at which file and line, how tightly pinned, with open CVEs |
| `hygiene(type?, min_consumers?)` | Every shared artifact ranked worst-pinned first, flagging version drift across repos |
| `record_dependencies(repository, deps)` | Write path — normally driven by the capture hook |

`type` disambiguates names shared across ecosystems: `node` is both a Docker image and an npm package, and they are different rows.

## Watching

```bash
blastradius check                  # one cycle now
blastradius watch --interval-hours 6
```

New advisories land in the index, so the next time an agent opens a file
referencing that artifact the inject hook surfaces them. Optionally, drop a
webhook in `~/.blastradius/config.json`:

```json
{ "slack_webhook_url": "https://hooks.slack.com/...", "notify_min_severity": "high" }
```

Severity is computed from the CVSS v3.1 vector with the real formula, because
OSV reports a vector far more often than a number. Only ecosystems OSV actually
covers are monitored — GitHub Actions and npm. Docker images, Terraform modules
and Helm charts are indexed but never reported as "no known CVEs", which would
be a lie.

## Status

Early. Working today: the index, the pinning classifier, both hooks, all three
MCP tools, the CVSS scorer, the OSV monitor, and a one-command installer.
**102 tests passing.**

Next: plugin marketplace packaging, and extraction quality work.

## License

MIT
