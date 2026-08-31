# Changelog

Notable changes to BlastRadius. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[semantic versioning](https://semver.org/spec/v2.0.0.html).

Extraction quality is a user-visible property of this tool, so a release that
changes it says so, with the score. Numbers come from `fixtures/grade.py` over
the six-repository corpus in `fixtures/`, which has 39 required artifacts and
19 deliberate traps.

## [Unreleased]

### Fixed

- **Injection printed the resolved version in place of the declared range.**
  A consumer declaring `^18.2.0` with a lockfile at `18.3.1` rendered as
  `18.3.1 partial` — the caret gone, the resolved number shown as if it were
  the pin. This is the failure the whole tool is built to prevent, committed
  by the tool itself. A real session read it and concluded a React 19 bump
  would leave two repos on mixed majors, when the caret caps that consumer at
  18 and the bump cannot reach it: the opposite conclusion, from a dropped
  operator. Consumers now render as `^18.2.0→18.3.1`, and as the spec alone
  when no lockfile narrows it. Costs about two tokens per consumer.

## [0.2.1] — 2026-08-30

One correctness fix, on the mechanism the whole tool rests on.

### Fixed

- **Injection missed anything the agent did through the shell.** The
  `PreToolUse` matcher was `Read|Edit`, so `cat package.json` and
  `npm install react@19` — which rewrites the manifest without going through
  `Edit` — produced no injection at all, while `doctor` reported the tool
  healthy. Found by running an ordinary "bump react to 19" against an indexed
  corpus and getting zero recorded injections for that repository. The matcher
  now includes `Bash`, and the hook resolves the manifest from the command
  string, inferring `package.json` for package-manager invocations that imply
  it. A command naming no manifest returns before the config or the index is
  touched. Re-run of the same scenario after the change: injection fires on
  `acme/web:package.json`, ~42 tokens, and the agent surfaces the other
  consumer unprompted.
- `blastradius cost | head` raised `BrokenPipeError` instead of ending quietly.

## [0.2.0] — 2026-08-30

Bootstrapping. Before this, the index only learned a repository when you
happened to open it, which made a fresh install correct and completely silent
for days.

### Added

- **`blastradius index <dir>`** — walk a directory of repositories and fill the
  index without waiting to open each one. Runs one headless Claude session per
  repository and lets the existing `Stop` hook capture, so the result is the
  index the hooks would have built. `--dry-run` lists what it would read,
  `--limit` caps the run, `--force` re-reads what is already indexed. Sessions
  deny `Write`, `Edit` and `Bash`, so a bootstrap cannot modify a repository it
  was only asked to look at. Scored on the fixture corpus from empty: 43
  references across six sessions, **39/39 recall, 39/39 specs, 0 traps** —
  identical to the hook-driven path.
- `scripts/check-packaging.py --set-version` writes the version to all three
  files that carry it. A half-done bump ships differently to each audience: pip
  users get the release while plugin users stay put, because the marketplace
  entry's version is what gates a plugin update.
- PyPI version and supported-Python badges in the README, read from published
  metadata rather than hand-written.

### Fixed

- **A manifest that declares nothing could never be marked as read.** Whether a
  file had been examined was inferred from whether it had produced rows, so a
  local Terraform module holding a single variable — which correctly yields
  nothing, forever — was re-flagged at every `Stop` and cost a fresh session on
  every bootstrap. Repositories now carry a scan timestamp, and a manifest
  counts as unread only if the index holds nothing from it *and* it changed
  since that scan. New and edited manifests are still caught.

### Changed

- The capture hook and `blastradius index` now decide "what is still unread"
  through one shared helper. They have to answer that question identically —
  the hook re-flags what it flags every session, and the bootstrap spends a
  paid session on whatever it believes is unread.

### Internal

- Schema: `repositories.last_scanned_at`, added by the existing additive
  migration. Older indexes upgrade in place and are treated as unscanned once.
- Test isolation: fixtures patching `store.DEFAULT_DB_PATH` had no effect — it
  is a default argument bound at import — so those tests were reading and
  writing the developer's real index. The suite is now checked to leave
  `~/.blastradius/index.db` untouched.

## [0.1.0] — 2026-08-30

First public release. Four lanes — inject, capture, monitor, report — verified
end to end on two machines.

### Added

- **Cross-repo injection.** A `PreToolUse` hook pushes impact into the session
  when a manifest is read: who else depends on this artifact, at which versions,
  and any open advisories. An MCP tool is model-elective; a hook is executed by
  the harness, which is the whole reason the push side is a hook. ~40 tokens per
  injection, suppressed for repeats within a configurable window.
- **Capture.** A `Stop` hook flags manifests the index has not seen and has the
  model record them. Extraction stays the model's job — it handles multi-stage
  aliases, `ARG`-templated bases and `FROM` inside a heredoc that regex parsing
  gets wrong.
- **CVE monitoring** against OSV, filtered to what your pins can actually
  resolve to, with lockfile resolution (`package-lock.json` v1/v2/v3,
  `yarn.lock`) narrowing it further. On the fixture corpus: 43 advisories become
  9. Severity from the CVSS v3.1 vector computed with the real formula, since
  OSV reports a vector far more often than a score. Unknown resolves toward
  affected — hiding a real vulnerability is worse than showing one that does not
  apply.
- **Five artifact types**: Docker images, Terraform modules, GitHub Actions,
  Helm charts, npm packages.
- `install` / `doctor` / `uninstall` / `link`, a background watcher via launchd
  or systemd, and reporting through `stats`, `repos`, `consumers`, `hygiene`,
  `alerts`, `cost` and `resolve`.
- **Distribution**: PyPI as `blastradius-mcp`, and a Claude Code plugin
  marketplace in the same repository.
- **CI** on Python 3.11–3.13, plus jobs that install the wheel on a machine
  that has never seen the source, check the fixture corpus against its ground
  truth, and fail if the generated assets drift from their generator.

### Fixed

Relative to the original BlastRadius this replaces:

- Terraform `source` read before `version`, so modules recorded unversioned.
- npm carets stripped at capture, so `^18.2.0` was indexed as `18.2.0` and every
  advisory affecting `18.2.0` was silently dropped.
- Artifacts keyed by identifier alone, so `node` the Docker image and `node` the
  npm package merged into one blast radius with no error. Now keyed by
  `(type, identifier)`.
- Reusable workflow identifiers recorded in full
  (`acme/.github/.github/workflows/deploy.yml`), so the same workflow called
  from two repositories produced two unrelated artifacts, neither with a blast
  radius. GitHub Action identifiers are now truncated to `owner/repo`.

### Known limitations

- npm cross-repo impact is weaker than infrastructure: packages install
  independently per repository, so a shared npm dependency is a drift and
  CVE-exposure signal rather than a breakage signal.
- pnpm lockfiles are not read.
- The index only knows repositories you have opened — see `blastradius index` in
  0.2.0.

[Unreleased]: https://github.com/harris-ahmad/blastradius-mcp/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/harris-ahmad/blastradius-mcp/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/harris-ahmad/blastradius-mcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/harris-ahmad/blastradius-mcp/releases/tag/v0.1.0
