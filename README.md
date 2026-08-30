<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/harris-ahmad/blastradius-mcp/main/assets/banner-dark.svg">
    <img src="https://raw.githubusercontent.com/harris-ahmad/blastradius-mcp/main/assets/banner.svg" width="620"
         alt="BlastRadius — cross-repo infrastructure memory for coding agents">
  </picture>
</p>

# BlastRadius

[![PyPI](https://img.shields.io/pypi/v/blastradius-mcp?color=0b7285&label=pypi)](https://pypi.org/project/blastradius-mcp/)
[![Python](https://img.shields.io/pypi/pyversions/blastradius-mcp?color=0b7285)](https://pypi.org/project/blastradius-mcp/)
[![ci](https://github.com/harris-ahmad/blastradius-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/harris-ahmad/blastradius-mcp/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-0b7285)](https://github.com/harris-ahmad/blastradius-mcp/blob/main/LICENSE)

It remembers what every repository you open depends on, tells your agent who else
is affected *before* it changes one, and watches those dependencies for
vulnerabilities while nobody is asking.

Not a code graph. Excellent tools already index functions, classes and imports. BlastRadius indexes the other half — Docker images, Terraform modules, GitHub Actions, Helm charts, npm packages — across repository boundaries, and answers the question a single session cannot: *if I bump this, who breaks?*

---

## What it actually produces

**43 advisories from OSV. 9 that apply to your pinned versions.**

```
[CRITICAL] vitest                 CVE-2026-47429
           When Vitest UI server is listening, arbitrary file can be read and executed
           reaches: 3.2.4  (installed version)
           in:      acme/checkout
[HIGH    ] lodash                 CVE-2021-23337
           lodash vulnerable to Code Injection via `_.template` imports key names
           reaches: 4.17.21, ^4.17.21
           in:      acme/checkout, acme/notifications, acme/web
[HIGH    ] vite                   CVE-2026-53571
           vite: `server.fs.deny` bypass on Windows alternate paths
           reaches: 5.4.19  (installed version)
           in:      acme/web
[MEDIUM  ] lodash                 CVE-2025-13465  (2 advisory records)
           lodash vulnerable to Prototype Pollution via array path bypass in `_.unset` and `_.omit`
           reaches: 4.17.21, ^4.17.21
           in:      acme/checkout, acme/notifications, acme/web

critical: 1  high: 2  medium: 4  low: 2
10 advisory record(s) covering 9 distinct vulnerability(ies)
```

Those two lodash entries are the point. They have **no fixed version**, so even an
exact `4.17.21` pin is still exposed — and three separate repositories carry it.
Nothing in a single-repo scan surfaces that.

Every line above is reproducible: `./verify.sh && ./run-capture.sh && blastradius alerts`.

## What it does unasked

Open a repo, ask for something ordinary — *"bump react to 19"* — and before the
agent reads a line of `package.json`, a hook has already told it:

> `acme/checkout` (a separate repo) also depends on `react@^18.2.0`, and `lodash`
> here is shared with `acme/notifications` and `acme/checkout` too.

Two repositories that were not open, not mentioned, and have no trace in the
working directory. The agent never called a tool to find them.

---

## Why hooks, not just MCP

MCP tools are model-elective — the agent may or may not call them. So the things
that must always happen are hooks, which the harness runs whether the model
thinks to or not:

| Lane | Mechanism | Fires |
|---|---|---|
| **Push** | `PreToolUse` on `Read`/`Edit` | Agent opens a manifest → cross-repo impact injected unprompted |
| **Capture** | `Stop` | Session ends → unindexed manifests flagged for recording |
| **Pull** | MCP tools | Agent asks: `blast_radius`, `hygiene`, `record_dependencies` |
| **Watch** | Daemon | OSV polling on an interval, with local alerts |

Only the asking is optional.

## Extraction is the model's job

BlastRadius ships **no manifest parsers**. Regex-matching `FROM` lines gets
multi-stage aliases, templated base images and heredocs wrong; the agent reads
those correctly already. The hook decides *when* extraction is owed, the model
does it, BlastRadius stores and joins and watches the result.

The one exception is lockfiles, which are machine-generated and schema-stable —
no judgement required, so no session required either.

---

## Install

```bash
pip install blastradius-mcp

blastradius install    # wires hooks + MCP server into Claude Code
blastradius link       # puts the CLI on PATH, no venv activation needed
blastradius doctor     # verifies it — by running the hooks for real
```

Or as a Claude Code plugin, which wires the hooks and MCP server for you:

```
/plugin marketplace add harris-ahmad/blastradius-mcp
/plugin install blastradius@blastradius
```

The plugin still needs the package — it declares hooks and an MCP server that
shell out to `blastradius`, so `pip install blastradius-mcp` comes first either
way. What it saves you is `blastradius install` and keeping the wiring current.
`claude plugin details blastradius@blastradius` puts its always-on cost at
~126 tokens per session; the hooks themselves are harness-side and cost
nothing until they fire.

<details>
<summary>From a clone</summary>

```bash
git clone https://github.com/harris-ahmad/blastradius-mcp
cd blastradius-mcp && pip install .
blastradius install && blastradius doctor
```

Prefer a plain install over `-e` unless you are working on the package itself:
an editable install resolves imports through `src/` at runtime, and anything
that disturbs that path produces `ModuleNotFoundError` while the console script
sits there looking fine.
</details>

Everything is local: one SQLite file at `~/.blastradius/index.db`. No account, no
server, no API key, nothing leaves your machine.

`install` merges into `~/.claude/settings.json` rather than overwriting it —
your other hooks and settings survive, re-running never duplicates, and the
previous file is backed up first. `uninstall` reverses it cleanly.

## Commands

| Command | Does |
|---|---|
| `blastradius consumers <artifact>` | Who uses it, at which file and line, how tightly pinned |
| `blastradius hygiene` | Shared artifacts ranked worst-pinned first, flagging version drift |
| `blastradius alerts` | Open advisories, which pins they reach, which repos carry them |
| `blastradius check [--refresh]` | Query OSV now; `--refresh` re-evaluates recorded alerts |
| `blastradius resolve <repos…>` | Read lockfiles, making vulnerability matching exact |
| `blastradius watch` | Poll on an interval, in the foreground |
| `blastradius service install` | Run the watcher in the background, across reboots |
| `blastradius service stop` / `start` / `uninstall` | Pause it, resume it, remove it |
| `blastradius cost [--days N]` | What injection has spent on context, and what dedupe saved |
| `blastradius repos` / `stats` / `doctor` | Index and wiring state |

The MCP tools are `blast_radius`, `hygiene` and `record_dependencies`. `type`
disambiguates names shared across ecosystems: `node` is both a Docker image and
an npm package, and they are different rows with different blast radii.

## Controlling what it does

```bash
blastradius config          # what is active right now
blastradius config --init   # write an example to ~/.blastradius/config.json
```

```json
{
  "inject": {
    "enabled": true,
    "max_artifacts": 8,
    "max_consumers": 5,
    "types": ["terraform_module", "github_action"],
    "only_when_shared": true,
    "min_cve_severity": "medium"
  },
  "exclude": {
    "repositories": ["acme/internal-*"],
    "paths": ["vendor/**", "examples/**"],
    "artifacts": ["registry.internal.*"]
  }
}
```

Injection spends context on every matching read, so it is tunable: narrow it to
the artifact types you care about, raise the severity floor, or turn it off.

Because it is capped, **what gets cut matters more than what fits**. Artifacts
are ranked before truncation — an open advisory dominates, then breadth of use,
then version drift — so a `package.json` with fifty dependencies surfaces the
two that matter rather than the first eight alphabetically. Ranking costs two
batched queries, because this runs inside a five-second hook timeout.

**The injected block is terse on purpose.** Measured across the fixture corpus,
the compact format is **58% smaller** than prose for identical facts — 202
characters per injection against 475. Three savings, largest first: the trailing
"call blast_radius before making a change" instruction is dropped entirely, since
it is identical every time and the bundled skill already teaches it; consumers go
inline rather than one indented line each; and a consumer's file path is
shortened against the file being read, because every repo's `Dockerfile` is
called `Dockerfile`.

```
blastradius .github/workflows/ci.yml
actions/checkout L5 → 5 repos: acme/checkout main UNPINNED deploy.yml:7 ·
  acme/legacy-cron main UNPINNED nightly.yml:5 · acme/payments v4 partial
actions/setup-node L6 → 1 repo: acme/checkout v4 partial deploy.yml:8
```

Set `"format": "verbose"` for the original prose form.

**Repeats within a session are suppressed** for `dedupe_minutes` (default 120).
An agent re-reads the same manifest constantly — before an edit, after an edit,
when re-checking — and the second injection tells it nothing the first did not.

Suppression expires rather than lasting forever, because a session id cannot be
fully trusted to be unique: six separate `claude -p` runs were observed sharing
one. Without the window, a single early injection would silence that file
permanently.

**Injection needs the file to already be indexed**, so a repo's first visit
captures and the visits after it enrich. On a corpus BlastRadius has never seen,
pass one records and pass two starts speaking.

`blastradius cost` shows what the tool is actually spending:

```
  4 injection(s) across 2 session(s)
  1,270 characters  ≈ 334 tokens
  318 characters each  ≈ 84 tokens

  4 repeat(s) suppressed within a session
  ≈ 334 tokens not spent re-telling the same thing

  Most expensive files
       736 ch    2x  acme/web:package.json
```

Token figures are estimates — Claude's tokenizer is not available locally, so
this uses ~3.8 characters per token, which suits paths and version strings
better than the usual prose ratio. The character counts are exact.

Exclusions govern capture as well as injection. Dependency names are usually
dull, but a private repository name or an internal registry hostname is not, so
excluded repositories, paths and artifacts are never written to the index in the
first place. Every setting has a working default — an absent config file behaves
exactly as if this section did not exist, and a malformed one falls back to
defaults rather than breaking a session.

The plugin also ships a **skill** that teaches when consulting the index is
worth it — before a version bump, when pinning or removing a shared dependency —
and how to read pinning quality, since a SHA-pinned consumer will not receive
your change at all while an unpinned one gets it immediately.

---

## How the alert filtering works

Advisories are matched against what your pins can **actually resolve to**.

| Your pin | Advisory fixed in 4.17.21 | Why |
|---|---|---|
| `4.17.21` | not affected | exact, at the fix |
| `^4.17.20` | **affected** | may still resolve to `.20` |
| `^4.17.21` | not affected | floor already fixed |
| `latest` | **kept** | unknowable — see below |

**Lockfiles make it exact.** A manifest says `^5.2.0`, which permits 5.2.0 and
therefore every advisory affecting it. `package-lock.json` says `5.4.19`, which
permits none of them. On the fixture corpus that is the difference between 13
vite alerts and 6. Reads `package-lock.json` (v1 and v2/v3) and `yarn.lock`;
pnpm needs a YAML parser and is not covered.

**Uncertainty keeps the alert.** A floating tag, a digest, a git ref, or an
advisory with no usable range data all resolve to *unknown*, and unknown is
treated as affected. Hiding a possible vulnerability is a far worse failure than
showing one that turns out not to apply.

Severity comes from the CVSS v3.1 vector computed with the real formula, because
OSV reports a vector far more often than a number. Only ecosystems OSV genuinely
covers are monitored — GitHub Actions and npm. Docker images, Terraform modules
and Helm charts are indexed but never reported as "no known CVEs", which would
be a lie.

---

## Extraction quality is measured, not asserted

Since extraction is delegated to a model, quality is the thing worth proving.
`fixtures/` builds six local repositories that share artifacts and pin them
inconsistently, with the hard cases planted on purpose: multi-stage stage
aliases, `ARG`-templated bases, a `FROM` inside a heredoc, a registry with a
port, local module sources, `workspace:` and `github:` protocols, and `redis`
appearing as three different artifact types across three repos.

```bash
./fixtures/make-fixtures.sh
./run-capture.sh                 # six headless sessions via `claude -p`
python3 fixtures/grade.py
```

```
recall  39/39  (100%)
specs   39/39  (100% kept intact)
traps   0 false positive(s)
```

- **recall** — of the artifacts genuinely present, how many were found
- **traps** — stage aliases, local paths and heredoc text wrongly recorded
- **specs** — how many version strings survived intact

**`specs` is the one that matters.** A model that quietly normalises `^18.2.0` to
`18.2.0` scores full recall while destroying the exact signal the tool reports
on. `grade.py` exits non-zero on a miss, a trap, *or* a stripped operator —
all three, because the number that only gets printed is the number that stops
being read.

Scoring a real run needs Claude, so it stays a local step. What CI does check
is everything around it: `fixtures/check-corpus.py` generates the corpus and
fails if `make-fixtures.sh` and `expected.json` have drifted apart, and
`tests/test_grader.py` scores a synthetic index built from the ground truth so
the grader cannot quietly start reporting a number nobody can check.

## Limitations

- **npm cross-repo impact is weaker than infrastructure.** Packages install
  independently per repo, so a shared npm dependency is a drift and
  CVE-exposure signal rather than a breakage signal. Terraform modules, Actions
  and base images are where a shared artifact genuinely *is* the same thing.
- **pnpm lockfiles are not read.**
- **The index only knows repos you have opened** with BlastRadius installed.

## Status

Early, but complete across all four lanes and verified end to end on two
machines. **305 tests**, run on Python 3.11–3.13 in CI, which also builds the
distributions and installs the wheel on a machine that has never seen the
source.

Next: pnpm lockfiles, and measuring what capture costs in context the way
injection already is.

Deliberately not built: a web viewer. The read-side UI is what made the original
BlastRadius something you had to deploy, and a local tool that answers through
the agent does not need one.

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest -q      # `python -m` beats a global pytest shadowing the venv

python scripts/check-packaging.py   # version agrees across all three manifests
python fixtures/check-corpus.py     # generator and ground truth still match
claude plugin validate .            # marketplace + plugin manifests
```

Releases are cut by tag — `git tag v0.1.0 && git push origin v0.1.0` — which
builds, checks the tag against the packaged version, and publishes to PyPI
through a trusted publisher. There is no API token anywhere in the repo.

Two things that bite, both now detected automatically:

**After `git pull`, run `pip install .` again.** A plain install copies the
package, so pulling updates the source and leaves the running code untouched —
silently. `doctor` detects this and `run-capture.sh` refuses to run against a
stale build.

**Prefer a plain install over editable when testing.** An editable install puts
only a `.pth` in site-packages and resolves imports through `src/` at runtime, so
anything disturbing that path produces `ModuleNotFoundError: No module named
'blastradius'` while the console script sits there looking fine.

When a hook stays quiet — which it does by design — `BLASTRADIUS_DEBUG=1`
narrates every decision to stderr rather than passing through silently.

## License

MIT
