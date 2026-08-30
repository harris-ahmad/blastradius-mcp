# BlastRadius

**Cross-repo infrastructure memory for coding agents.** It remembers what every repository you open depends on, tells your agent who else is affected *before* it changes one, and watches those dependencies for vulnerabilities while nobody is asking.

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
git clone https://github.com/harris-ahmad/blastradius-mcp
cd blastradius-mcp && pip install .

blastradius install    # wires hooks + MCP server into Claude Code
blastradius link       # puts the CLI on PATH, no venv activation needed
blastradius doctor     # verifies it — by running the hooks for real
```

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
| `blastradius watch` | Poll on an interval |
| `blastradius repos` / `stats` / `doctor` | Index and wiring state |

The MCP tools are `blast_radius`, `hygiene` and `record_dependencies`. `type`
disambiguates names shared across ecosystems: `node` is both a Docker image and
an npm package, and they are different rows with different blast radii.

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
on. `grade.py` exits non-zero on any miss or trap, so it works as a CI
regression test on extraction quality.

## Limitations

- **npm cross-repo impact is weaker than infrastructure.** Packages install
  independently per repo, so a shared npm dependency is a drift and
  CVE-exposure signal rather than a breakage signal. Terraform modules, Actions
  and base images are where a shared artifact genuinely *is* the same thing.
- **pnpm lockfiles are not read.**
- **Reusable workflow identifiers are not canonicalised** —
  `org/.github/.github/workflows/ci.yml@v2` records as written rather than
  collapsing to `org/.github`, so it will not match across repos.
- **The index only knows repos you have opened** with BlastRadius installed.

## Status

Early, but complete across all four lanes and verified end to end on two
machines. **207 tests.**

Next: plugin marketplace packaging, pnpm lockfiles, workflow identifier
canonicalisation.

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest -q      # `python -m` beats a global pytest shadowing the venv
```

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
