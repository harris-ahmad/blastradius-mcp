"""MCP server — the pull lane.

Capture and injection happen in hooks, deterministically. These tools exist for
when the agent actively wants to ask something.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Annotated, Any, Literal

from mcp.server import MCPServer
from pydantic import Field

from .lockfile import npm_resolved_versions
from .scoring import QUALITY_RANK, classify_pinning, worst_quality
from .store import ARTIFACT_TYPES, Dependency, Store

ArtifactType = Literal["docker_image", "terraform_module", "github_action",
                       "helm_chart", "npm_package"]

server = MCPServer(
    "blastradius",
    version="0.1.0",
    instructions=(
        "BlastRadius indexes infrastructure dependencies across every repository "
        "you open. Call blast_radius before changing a shared artifact to see who "
        "else consumes it and how tightly they pin it."
    ),
)

_store: Store | None = None


def store() -> Store:
    global _store
    if _store is None:
        _store = Store()
    return _store


@server.tool()
def blast_radius(
    identifier: Annotated[str, Field(description="e.g. 'actions/checkout', 'alpine', 'react'. No version.")],
    type: Annotated[ArtifactType | None, Field(
        description="Disambiguates a name shared across ecosystems — 'node' is both "
                    "a Docker image and an npm package."
    )] = None,
    exclude_repository: Annotated[str | None, Field(
        description="Omit the repo you are working in, to show only other consumers."
    )] = None,
) -> dict[str, Any]:
    """Who else depends on this artifact, and exactly where.

    Use this before changing, upgrading, or deprecating a shared dependency.
    Returns every consuming repository with file:line references, how tightly
    each one pins the version, and any open CVEs against the artifact.
    """
    rows = store().consumers(identifier, type, exclude_repository)

    if not rows:
        return {
            "identifier": identifier,
            "consumer_count": 0,
            "note": "Not in the index. Either nothing uses it, or those repos have "
                    "not been opened with BlastRadius installed yet.",
        }

    by_repo: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        key = (row["type"], row["repository"])
        entry = by_repo.setdefault(key, {
            "repository": row["repository"],
            "type": row["type"],
            "owner": row["owner"],
            "version_spec": row["version_spec"],
            "pinning": classify_pinning(row["version_spec"], row["type"]),
            "references": [],
        })
        entry["references"].append(f"{row['file_path']}:{row['line_number']}")

    consumers = sorted(
        by_repo.values(),
        key=lambda c: (-QUALITY_RANK.get(c["pinning"], 2), c["repository"]),
    )

    return {
        "identifier": identifier,
        "consumer_count": len(consumers),
        "reference_count": len(rows),
        "worst_pinning": worst_quality([c["pinning"] for c in consumers]),
        "version_spread": sorted({c["version_spec"] or "(none)" for c in consumers}),
        "open_cves": store().alerts_for(identifier, type),
        "consumers": consumers,
    }


@server.tool()
def record_dependencies(
    repository: Annotated[str, Field(description="Canonical 'owner/name'.")],
    dependencies: Annotated[list[dict], Field(
        description="Each item needs: type (one of docker_image, terraform_module, "
                    "github_action, helm_chart, npm_package), identifier, "
                    "version_spec, file_path, line_number. Pass version_spec EXACTLY "
                    "as written in the file — '^18.2.0', '~> 5.0', 'v4'. Do not strip "
                    "range operators; they are the whole signal. Pass identifier "
                    "exactly as written too: a Terraform submodule keeps its '//path' "
                    "suffix, so 'terraform-aws-modules/vpc/aws//modules/vpc-endpoints' "
                    "is recorded in full and not shortened to its parent module."
    )],
    owner: str | None = None,
    root_path: Annotated[str | None, Field(
        description="Absolute path to the repository root. Pass it whenever you know "
                    "it — lockfiles found there pin down which version is actually "
                    "installed, which makes vulnerability matching exact instead of "
                    "conservative."
    )] = None,
) -> dict[str, Any]:
    """Record what a repository depends on.

    The capture hook does this automatically at end of session. Call it directly
    when you have just read manifests the hook would not have seen, or after
    changing a dependency so the index stays current.
    """
    # Lockfiles are machine-generated and schema-stable, so they are parsed
    # here rather than left to extraction. The model reports what the manifest
    # asks for; this records what is actually installed.
    resolved = npm_resolved_versions(root_path) if root_path else {}

    deps = [
        Dependency(
            type=d["type"],
            identifier=d["identifier"],
            version_spec=d.get("version_spec"),
            file_path=d["file_path"],
            line_number=int(d["line_number"]),
            resolved_version=(
                d.get("resolved_version")
                or (resolved.get(d["identifier"]) if d["type"] == "npm_package" else None)
            ),
        )
        for d in dependencies
    ]
    result = store().record(repository, deps, root_path=root_path, owner=owner)
    locked = sum(1 for d in deps if d.resolved_version)
    return {
        "recorded": result["recorded"],
        "resolved_from_lockfile": locked,
        "index": store().stats(),
    }


@server.tool()
def hygiene(
    type: ArtifactType | None = None,
    min_consumers: Annotated[int, Field(
        description="Only report artifacts used by at least this many repositories."
    )] = 1,
) -> dict[str, Any]:
    """Pinning report across every indexed repo, worst first.

    Shows which shared artifacts float, and which repositories disagree about the
    version of the same thing.
    """
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in store().all_dependencies():
        if type and row["type"] != type:
            continue
        grouped[(row["type"], row["identifier"])].append(row)

    artifacts: list[dict[str, Any]] = []
    summary = {q: 0 for q in ("sha", "exact", "partial", "unknown", "unpinned")}

    for (art_type, identifier), rows in grouped.items():
        repos = {r["repository"] for r in rows}
        if len(repos) < min_consumers:
            continue
        worst = worst_quality([classify_pinning(r["version_spec"], art_type) for r in rows])
        summary[worst] += 1
        specs = sorted({r["version_spec"] or "(none)" for r in rows})
        artifacts.append({
            "type": art_type,
            "identifier": identifier,
            "consumer_count": len(repos),
            "worst_pinning": worst,
            "version_spread": specs,
            "drifting": len(specs) > 1,
        })

    artifacts.sort(key=lambda a: (
        -QUALITY_RANK.get(a["worst_pinning"], 2), -a["consumer_count"], a["identifier"]
    ))
    return {"summary": {**summary, "total": len(artifacts)}, "artifacts": artifacts}


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
