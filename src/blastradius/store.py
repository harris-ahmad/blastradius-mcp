"""Local index of infrastructure dependencies across every repo the agent sees.

Two schema changes from the original BlastRadius, both load-bearing:

1. Artifacts are keyed by (type, identifier), not identifier alone. `node` the
   Docker image and `node` the npm package are different rows. The original
   merged them silently, which meant a blast radius could span two unrelated
   dependency sets with no error.

2. The version lives on the dependency edge, not the artifact. A version is a
   property of "this repo pins this artifact here", not of the artifact itself.
   That also removes the duplicate-artifact problem the original had to write a
   migration for, since artifacts no longer carry a nullable version in their
   uniqueness constraint.
"""
from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator

DEFAULT_DB_PATH = Path(os.environ.get("BLASTRADIUS_DB", Path.home() / ".blastradius" / "index.db"))

ARTIFACT_TYPES = (
    "docker_image", "terraform_module", "github_action", "helm_chart", "npm_package",
)


@dataclass(frozen=True)
class Dependency:
    """One reference to one artifact at one place in one repo."""
    type: str
    identifier: str
    version_spec: str | None
    file_path: str
    line_number: int

    def __post_init__(self) -> None:
        # An absent version arrives as null, "" or "   " depending on who is
        # writing. Normalise at the boundary so nothing downstream has to guess.
        cleaned = (self.version_spec or "").strip()
        object.__setattr__(self, "version_spec", cleaned or None)
        object.__setattr__(self, "identifier", self.identifier.strip())


def _now() -> str:
    return datetime.now(UTC).isoformat()


class Store:
    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            # WAL lets the CVE daemon read while a capture hook writes.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=10000")
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS repositories (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    name          TEXT NOT NULL UNIQUE,
                    root_path     TEXT,
                    owner         TEXT,
                    last_seen_at  TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS artifacts (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    type        TEXT NOT NULL,
                    identifier  TEXT NOT NULL,
                    UNIQUE(type, identifier)
                );

                CREATE TABLE IF NOT EXISTS dependencies (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
                    artifact_id   INTEGER NOT NULL REFERENCES artifacts(id)    ON DELETE CASCADE,
                    version_spec  TEXT,
                    file_path     TEXT NOT NULL,
                    line_number   INTEGER NOT NULL,
                    recorded_at   TEXT NOT NULL,
                    UNIQUE(repository_id, artifact_id, file_path, line_number)
                );

                CREATE TABLE IF NOT EXISTS cve_alerts (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    artifact_id         INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
                    osv_id              TEXT NOT NULL,
                    cve_id              TEXT,
                    severity            TEXT NOT NULL,
                    summary             TEXT NOT NULL,
                    url                 TEXT,
                    first_seen_at       TEXT NOT NULL,
                    acknowledged_at     TEXT,
                    applies_to          TEXT,
                    UNIQUE(artifact_id, osv_id)
                );

                CREATE INDEX IF NOT EXISTS idx_deps_artifact ON dependencies(artifact_id);
                CREATE INDEX IF NOT EXISTS idx_deps_repo     ON dependencies(repository_id);
                CREATE INDEX IF NOT EXISTS idx_deps_path     ON dependencies(file_path);
                CREATE INDEX IF NOT EXISTS idx_artifacts_id  ON artifacts(identifier);
                """
            )
            self._ensure_column(conn, "cve_alerts", "applies_to", "TEXT")

    @staticmethod
    def _ensure_column(conn: sqlite3.Connection, table: str, column: str, sql_type: str) -> None:
        """Additive migration for indexes created by an earlier version."""
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}")

    # ── Write path (the capture hook) ─────────────────────────────────────────

    def record(
        self,
        repository: str,
        dependencies: list[Dependency],
        root_path: str | None = None,
        owner: str | None = None,
    ) -> dict[str, int]:
        """Record what a repository depends on. Idempotent per (repo, artifact, file, line)."""
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO repositories (name, root_path, owner, last_seen_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    root_path    = COALESCE(excluded.root_path, repositories.root_path),
                    owner        = COALESCE(excluded.owner, repositories.owner),
                    last_seen_at = excluded.last_seen_at
                """,
                (repository, root_path, owner, _now()),
            )
            repo_id = conn.execute(
                "SELECT id FROM repositories WHERE name = ?", (repository,)
            ).fetchone()["id"]

            new_edges = 0
            for dep in dependencies:
                conn.execute(
                    "INSERT OR IGNORE INTO artifacts (type, identifier) VALUES (?, ?)",
                    (dep.type, dep.identifier),
                )
                artifact_id = conn.execute(
                    "SELECT id FROM artifacts WHERE type = ? AND identifier = ?",
                    (dep.type, dep.identifier),
                ).fetchone()["id"]

                cur = conn.execute(
                    """
                    INSERT INTO dependencies
                        (repository_id, artifact_id, version_spec, file_path, line_number, recorded_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(repository_id, artifact_id, file_path, line_number)
                    DO UPDATE SET version_spec = excluded.version_spec,
                                  recorded_at  = excluded.recorded_at
                    """,
                    (repo_id, artifact_id, dep.version_spec, dep.file_path, dep.line_number, _now()),
                )
                new_edges += cur.rowcount or 0

            return {"repository_id": repo_id, "recorded": len(dependencies), "edges": new_edges}

    def forget_repository(self, repository: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM repositories WHERE name = ?", (repository,))
            return cur.rowcount > 0

    # ── Read path (MCP tools + the injection hook) ────────────────────────────

    def consumers(
        self,
        identifier: str,
        artifact_type: str | None = None,
        exclude_repository: str | None = None,
    ) -> list[dict]:
        """Who uses this artifact, and exactly where.

        `artifact_type` disambiguates a name shared across ecosystems. Omitting
        it returns every type that matches, each as its own group.
        """
        sql = """
            SELECT a.type, a.identifier, r.name AS repository, r.owner,
                   d.version_spec, d.file_path, d.line_number
            FROM dependencies d
            JOIN artifacts    a ON a.id = d.artifact_id
            JOIN repositories r ON r.id = d.repository_id
            WHERE a.identifier = ?
        """
        params: list[object] = [identifier]
        if artifact_type:
            sql += " AND a.type = ?"
            params.append(artifact_type)
        if exclude_repository:
            sql += " AND r.name != ?"
            params.append(exclude_repository)
        sql += " ORDER BY a.type, r.name, d.file_path, d.line_number"

        with self._conn() as conn:
            return [dict(row) for row in conn.execute(sql, params)]

    def artifacts_in_file(self, repository: str, file_path: str) -> list[dict]:
        """Every artifact referenced by one file — the injection hook's query."""
        with self._conn() as conn:
            return [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT a.type, a.identifier, d.version_spec, d.line_number
                    FROM dependencies d
                    JOIN artifacts    a ON a.id = d.artifact_id
                    JOIN repositories r ON r.id = d.repository_id
                    WHERE r.name = ? AND d.file_path = ?
                    ORDER BY d.line_number
                    """,
                    (repository, file_path),
                )
            ]

    def all_dependencies(self) -> list[dict]:
        with self._conn() as conn:
            return [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT a.type, a.identifier, r.name AS repository,
                           d.version_spec, d.file_path, d.line_number
                    FROM dependencies d
                    JOIN artifacts    a ON a.id = d.artifact_id
                    JOIN repositories r ON r.id = d.repository_id
                    ORDER BY a.type, a.identifier
                    """
                )
            ]

    def monitorable_artifacts(self) -> list[dict]:
        """Artifacts OSV can actually answer for."""
        with self._conn() as conn:
            return [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT DISTINCT a.id, a.type, a.identifier
                    FROM artifacts a
                    JOIN dependencies d ON d.artifact_id = a.id
                    WHERE a.type IN ('github_action', 'npm_package')
                    """
                )
            ]

    def stats(self) -> dict[str, int]:
        with self._conn() as conn:
            return {
                "repositories": conn.execute("SELECT COUNT(*) c FROM repositories").fetchone()["c"],
                "artifacts":    conn.execute("SELECT COUNT(*) c FROM artifacts").fetchone()["c"],
                "references":   conn.execute("SELECT COUNT(*) c FROM dependencies").fetchone()["c"],
                "open_alerts":  conn.execute(
                    "SELECT COUNT(*) c FROM cve_alerts WHERE acknowledged_at IS NULL"
                ).fetchone()["c"],
            }

    # ── CVE alerts (the daemon) ───────────────────────────────────────────────

    def seen_osv_ids(self, artifact_id: int) -> set[str]:
        with self._conn() as conn:
            return {
                row["osv_id"]
                for row in conn.execute(
                    "SELECT osv_id FROM cve_alerts WHERE artifact_id = ?", (artifact_id,)
                )
            }

    def add_alert(self, artifact_id: int, cve: dict, applies_to: list[str] | None = None) -> bool:
        """Returns True if this alert is new.

        `applies_to` records which of the pinned specs this advisory actually
        covers, so a reader can see it affects two of five consumers rather
        than assuming all of them.
        """
        with self._conn() as conn:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO cve_alerts
                    (artifact_id, osv_id, cve_id, severity, summary, url,
                     first_seen_at, applies_to)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact_id,
                    str(cve.get("id", "")),
                    cve.get("cve_id"),
                    str(cve.get("severity", "unknown")),
                    str(cve.get("summary", ""))[:500],
                    cve.get("url"),
                    _now(),
                    ", ".join(applies_to) if applies_to else None,
                ),
            )
            return cur.rowcount > 0

    def specs_for_artifact(self, artifact_id: int) -> list[str | None]:
        """Every distinct version spec pinned against one artifact."""
        with self._conn() as conn:
            return [
                row["version_spec"]
                for row in conn.execute(
                    "SELECT DISTINCT version_spec FROM dependencies WHERE artifact_id = ?",
                    (artifact_id,),
                )
            ]

    def alerts_for(self, identifier: str, artifact_type: str | None = None) -> list[dict]:
        sql = """
            SELECT c.osv_id, c.cve_id, c.severity, c.summary, c.url, c.first_seen_at,
                   c.applies_to
            FROM cve_alerts c
            JOIN artifacts a ON a.id = c.artifact_id
            WHERE a.identifier = ? AND c.acknowledged_at IS NULL
        """
        params: list[object] = [identifier]
        if artifact_type:
            sql += " AND a.type = ?"
            params.append(artifact_type)
        with self._conn() as conn:
            return [dict(row) for row in conn.execute(sql, params)]
