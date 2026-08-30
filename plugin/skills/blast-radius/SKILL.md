---
name: blast-radius
description: Check who else depends on an artifact before changing it. Use when upgrading, downgrading, pinning, unpinning, replacing or removing a Docker base image, Terraform module, GitHub Action, Helm chart or npm package — and when asked which dependencies are unpinned, drifting, or carrying known vulnerabilities across repositories.
---

# Cross-repo dependency impact

BlastRadius indexes what every repository the user has opened depends on. That
index answers questions a single working directory cannot: who else uses this
artifact, how tightly each of them pins it, and whether it carries advisories
that reach their pinned versions.

## When to consult it

Before any change to a shared artifact:

- upgrading, downgrading or replacing a base image, module, action or package
- pinning something currently floating, or loosening an exact pin
- removing a dependency — removal here does not remove exposure elsewhere
- answering "is it safe to bump X"

And whenever the user asks about pinning discipline, version drift, or
vulnerability exposure across more than one repository.

## Tools

`blast_radius(identifier, type?, exclude_repository?)`
: Every consuming repository, with file:line references, how tightly each pins
  it, the spread of versions in use, and open advisories.

`hygiene(type?, min_consumers?)`
: All shared artifacts ranked worst-pinned first, flagging where repositories
  disagree about the version of the same thing.

`record_dependencies(repository, dependencies, root_path?)`
: Write path. Pass `root_path` whenever known — lockfiles found there pin down
  which version is actually installed, which makes vulnerability matching exact
  rather than conservative.

## Reading the answer

**Pinning quality**, worst to best:

| | Means |
|---|---|
| `unpinned` | floating tag or range with no floor — takes every upstream change immediately |
| `partial` | a range or moving major (`^1.2.0`, `v4`, `~> 5.0`) — absorbs some changes |
| `exact` | a single version — will not move on its own |
| `sha` | digest or commit — immune until someone explicitly updates it |
| `unknown` | no version data captured for this reference |

A SHA-pinned consumer will not receive your change at all. An unpinned one gets
it the moment it lands. That difference usually decides whether a bump is safe
to make unilaterally.

**Always pass `type` when the name is ambiguous.** `node`, `redis` and
`postgres` exist as both Docker images and npm packages, and they are unrelated
artifacts with unrelated blast radii.

## Two cautions

Context may already have been injected for you. A `PreToolUse` hook surfaces
cross-repo impact when you open a manifest, so check what you were given before
calling `blast_radius` for the same artifact.

The index only knows repositories that have been opened with BlastRadius
installed. A small consumer count means "none that I have seen", not "none
exist" — say so rather than implying the answer is exhaustive.
