# Fixtures

A local corpus for exercising extraction, plus ground truth so the result is a
number rather than an impression.

```bash
./fixtures/make-fixtures.sh              # builds ~/br-fixtures
cd ~/br-fixtures/payments && claude      # work, then end the session
python3 fixtures/grade.py
```

## What it builds

Six repos that share artifacts with each other and pin them inconsistently on
purpose, so the inject hook has something to say from the second repo onward.

| Repo | Carries | Planted case |
|---|---|---|
| `acme/payments` | Go, Docker, Actions, Terraform | multi-stage `FROM builder AS test`; SHA-pinned action; registry module with `source` before `version` |
| `acme/checkout` | Node, Docker, Actions | `ARG`-templated base; a `FROM` inside a heredoc; caret/tilde/compound ranges; `workspace:` and `github:` protocols |
| `acme/web` | Node, Docker, Actions | shares `react` and `lodash` with checkout at different specs |
| `acme/platform-infra` | Terraform, Actions | `git::` source with `ref`; submodule paths; local `../modules/tags` |
| `acme/notifications` | Helm, Docker, Node | chart deps; `file://` local chart; image on a registry **with a port** |
| `acme/legacy-cron` | Docker, Actions | everything floats — `latest`, `main`, untagged |

## The three numbers

`grade.py` reports, per repo and overall:

- **recall** — of the artifacts genuinely present, how many were found
- **traps** — stage aliases, local paths and heredoc text wrongly recorded
- **specs** — of those found, how many kept the version string intact

**`specs` is the one to watch.** A model that quietly normalises `^18.2.0` to
`18.2.0` scores full recall while destroying the exact signal the tool exists to
report. That is the bug that made the original BlastRadius call 128 of 129 npm
packages exactly pinned.

## Ground truth

`expected.json` splits each repo three ways:

- `required` — must be extracted; missing one is a recall failure
- `forbidden` — must **not** be extracted; finding one is a false positive
- `optional` — defensible either way, so neither rewarded nor penalised

`identifier` and `version_spec` accept a list where more than one form is fair
(`bitnami/redis` or plain `redis` for a Helm dependency, say). Where two entries
could legitimately share an identifier, matched rows are consumed so one
expectation cannot be scored against another's row.

## The type-collision case

`redis` appears three times across the corpus, deliberately:

- a **Docker image** in `legacy-cron`
- an **npm package** in `checkout`
- a **Helm chart** in `notifications`

`blastradius consumers redis` should show all three. `blastradius consumers redis
--type npm_package` should show only `acme/checkout`. If the unfiltered call
merges them into one blast radius, the `(type, identifier)` key has regressed.
