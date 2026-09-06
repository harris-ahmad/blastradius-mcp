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

3. GitHub Action identifiers are truncated to owner/repo on the way in. A
   reusable workflow is written in full, so the same workflow called from two
   repos produced two unrelated artifacts and neither had a blast radius. See
   `canonical_identifier`.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator

from .scoring import classify_pinning

DEFAULT_DB_PATH = Path(os.environ.get("BLASTRADIUS_DB", Path.home() / ".blastradius" / "index.db"))

ARTIFACT_TYPES = (
    "docker_image", "terraform_module", "github_action", "helm_chart", "npm_package",
    "python_package",
)


@dataclass(frozen=True)
class Dependency:
    """One reference to one artifact at one place in one repo."""
    type: str
    identifier: str
    version_spec: str | None
    file_path: str
    line_number: int
    # What the lockfile says is actually installed. A spec permits a range; this
    # is the single version that range resolved to.
    resolved_version: str | None = None

    def __post_init__(self) -> None:
        # An absent version arrives as null, "" or "   " depending on who is
        # writing. Normalise at the boundary so nothing downstream has to guess.
        cleaned = (self.version_spec or "").strip()
        object.__setattr__(self, "version_spec", cleaned or None)
        resolved = (self.resolved_version or "").strip()
        object.__setattr__(self, "resolved_version", resolved or None)
        object.__setattr__(self, "identifier",
                           canonical_identifier(self.type, self.identifier.strip()))


def _now() -> str:
    return datetime.now(UTC).isoformat()


def canonical_identifier(artifact_type: str, identifier: str) -> str:
    """Reduce an artifact name to the thing that is actually shared across repos.

    A GitHub Action lives at owner/repo; anything after that is a path inside
    it. A reusable workflow written in full —
    `acme/.github/.github/workflows/deploy.yml` — names the same repository as
    `acme/.github`, and recording the long form means the two never match and
    OSV is queried for a package that cannot exist.

    Only github_action is truncated. Docker images legitimately carry deeper
    paths (`gcr.io/distroless/static-debian12`), as do Terraform submodules.
    """
    if artifact_type != "github_action":
        return identifier
    parts = [p for p in identifier.split("/") if p]
    if len(parts) <= 2:
        return identifier
    return f"{parts[0]}/{parts[1]}"


def identifier_candidates(identifier: str, artifact_type: str | None = None) -> list[str]:
    """Every stored form a lookup for `identifier` should match.

    Recording canonicalises, but a caller asks with whatever the file said. A
    query for `acme/.github/.github/workflows/deploy.yml` has to find the row
    stored as `acme/.github`, or the reusable workflow looks unused.

    The truncated form is only offered when the type permits it — for
    docker_image, `gcr.io/distroless/static-debian12` must not also match a
    row named `gcr.io/distroless`.
    """
    candidates = [identifier]
    if artifact_type in (None, "github_action"):
        truncated = canonical_identifier("github_action", identifier)
        if truncated != identifier:
            candidates.append(truncated)
    return candidates


class Store:
    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path).expanduser()
        # Thread-local, not a single shared handle. sqlite3 forbids using a
        # connection from a thread other than the one that created it, and the
        # MCP server caches one Store globally while the SDK runs tool handlers
        # on a worker pool — a shared handle would fail there on the second
        # call to land on a different thread.
        self._local = threading.local()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        """One connection per Store, opened once and reused.

        A single inject() asks the index a dozen questions, and each one used
        to open a fresh connection and re-run three PRAGMAs. Reusing the
        connection keeps WAL and the busy timeout exactly as they were — they
        are set once, on the same connection — while cutting thirteen opens
        to one. The connection closes with the process, which for a hook is
        milliseconds later; long-lived callers get close().
        """
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            conn.row_factory = sqlite3.Row
            # WAL lets the CVE daemon read while a capture hook writes.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=10000")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
        try:
            yield conn
            conn.commit()
        except Exception:
            # A failed write must not leave a half-applied statement visible
            # to the next caller, which now shares this connection.
            conn.rollback()
            raise

    def close(self) -> None:
        """Close this thread's connection. Other threads keep their own."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

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
                    resolved_version TEXT,
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

                CREATE TABLE IF NOT EXISTS injections (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id  TEXT,
                    repository  TEXT NOT NULL,
                    file_path   TEXT NOT NULL,
                    characters  INTEGER NOT NULL,
                    artifacts   INTEGER NOT NULL,
                    suppressed  INTEGER NOT NULL DEFAULT 0,
                    created_at  TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS captures (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id  TEXT,
                    repository  TEXT NOT NULL,
                    manifests   INTEGER NOT NULL,
                    characters  INTEGER NOT NULL,
                    created_at  TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_captures_time ON captures(created_at);
                CREATE INDEX IF NOT EXISTS idx_injections_session
                    ON injections(session_id, file_path);
                CREATE INDEX IF NOT EXISTS idx_injections_time ON injections(created_at);
                CREATE INDEX IF NOT EXISTS idx_deps_artifact ON dependencies(artifact_id);
                CREATE INDEX IF NOT EXISTS idx_deps_repo     ON dependencies(repository_id);
                CREATE INDEX IF NOT EXISTS idx_deps_path     ON dependencies(file_path);
                CREATE INDEX IF NOT EXISTS idx_artifacts_id  ON artifacts(identifier);
                """
            )
            self._ensure_column(conn, "cve_alerts", "applies_to", "TEXT")
            self._ensure_column(conn, "dependencies", "resolved_version", "TEXT")
            self._ensure_column(conn, "repositories", "last_scanned_at", "TEXT")
            self._ensure_column(conn, "dependencies", "pinning", "TEXT")
            self._ensure_column(conn, "artifacts", "consumer_count", "INTEGER")
            self._ensure_column(conn, "artifacts", "version_spread", "INTEGER")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_deps_null_pinning "
                         "ON dependencies(pinning)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_deps_pinning "
                         "ON dependencies(artifact_id, pinning)")
            self._backfill_pinning(conn)
            if conn.execute("SELECT 1 FROM artifacts WHERE consumer_count IS NULL "
                            "LIMIT 1").fetchone() is not None:
                self._refresh_artifact_stats(conn)

    @staticmethod
    def _refresh_artifact_stats(conn: sqlite3.Connection,
                                artifact_ids: "set[int] | None" = None) -> None:
        """Recompute the cached per-artifact counts.

        These were computed on every injection with COUNT(DISTINCT ...) over
        the joined tables — 200ms of a 260ms hook at 90,000 rows, and growing
        with the index. They change only when something is recorded or
        forgotten, so they are maintained on write and read as plain columns.

        `artifact_ids` limits the work to what a write touched; None recomputes
        everything, which is what the migration needs.
        """
        scope, params = "", []
        if artifact_ids is not None:
            if not artifact_ids:
                return
            scope = f"WHERE a.id IN ({', '.join('?' * len(artifact_ids))})"
            params = list(artifact_ids)
        conn.execute(
            f"""
            WITH counts AS (
                SELECT a.id AS artifact_id,
                       COUNT(DISTINCT d.repository_id) AS consumers,
                       COUNT(DISTINCT COALESCE(d.resolved_version, d.version_spec, ''))
                           AS spread
                FROM artifacts a
                LEFT JOIN dependencies d ON d.artifact_id = a.id
                {scope}
                GROUP BY a.id
            )
            UPDATE artifacts
               SET consumer_count = (SELECT consumers FROM counts
                                     WHERE counts.artifact_id = artifacts.id),
                   version_spread = (SELECT spread FROM counts
                                     WHERE counts.artifact_id = artifacts.id)
             WHERE id IN (SELECT artifact_id FROM counts)
            """,
            params,
        )

    @staticmethod
    def _backfill_pinning(conn: sqlite3.Connection) -> None:
        """Classify rows written before the column existed.

        Without this an index built by an earlier version has NULL pinning
        everywhere, which sorts as one undifferentiated bucket — so the "worst
        pinned first" ordering would silently become arbitrary for exactly the
        users who have the most data.
        """
        from .scoring import classify_pinning

        # Indexed probe. Scanning for NULLs on every Store() would put a
        # full-table read in front of every hook, which is the opposite of
        # what this whole change is for.
        if conn.execute("SELECT 1 FROM dependencies WHERE pinning IS NULL "
                        "LIMIT 1").fetchone() is None:
            return

        rows = conn.execute(
            """SELECT d.id, d.version_spec, a.type
               FROM dependencies d JOIN artifacts a ON a.id = d.artifact_id
               WHERE d.pinning IS NULL"""
        ).fetchall()
        if not rows:
            return
        conn.executemany(
            "UPDATE dependencies SET pinning = ? WHERE id = ?",
            [(classify_pinning(r["version_spec"], r["type"]), r["id"]) for r in rows],
        )

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
            # A manifest that declares nothing external — a local Terraform
            # module holding one variable, say — produces no rows however
            # carefully it is read. Without a record of *when we looked*, it
            # stays "not yet indexed" forever, and every later pass pays to
            # read it again. The scan stamp is what makes "looked at, nothing
            # there" distinguishable from "never looked at".
            conn.execute("UPDATE repositories SET last_scanned_at = ? WHERE name = ?",
                         (_now(), repository))
            repo_id = conn.execute(
                "SELECT id FROM repositories WHERE name = ?", (repository,)
            ).fetchone()["id"]

            new_edges = 0
            touched: set[int] = set()
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
                        (repository_id, artifact_id, version_spec, resolved_version,
                         file_path, line_number, recorded_at, pinning)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(repository_id, artifact_id, file_path, line_number)
                    DO UPDATE SET version_spec     = excluded.version_spec,
                                  resolved_version = excluded.resolved_version,
                                  recorded_at      = excluded.recorded_at,
                                  pinning          = excluded.pinning
                    """,
                    (repo_id, artifact_id, dep.version_spec, dep.resolved_version,
                     dep.file_path, dep.line_number, _now(),
                     classify_pinning(dep.version_spec, dep.type)),
                )
                new_edges += cur.rowcount or 0
                touched.add(artifact_id)

            self._refresh_artifact_stats(conn, touched)
            return {"repository_id": repo_id, "recorded": len(dependencies), "edges": new_edges}

    def forget_repository(self, repository: str) -> bool:
        with self._conn() as conn:
            # Which artifacts this repository touched, before the cascade takes
            # the rows away — their cached counts are about to be wrong.
            affected = {
                row["artifact_id"] for row in conn.execute(
                    """SELECT DISTINCT d.artifact_id FROM dependencies d
                       JOIN repositories r ON r.id = d.repository_id
                       WHERE r.name = ?""", (repository,))
            }
            cur = conn.execute("DELETE FROM repositories WHERE name = ?", (repository,))
            self._refresh_artifact_stats(conn, affected)
            return cur.rowcount > 0

    # ── Read path (MCP tools + the injection hook) ────────────────────────────

    # Worst-pinned first. Mirrors scoring.QUALITY_RANK, in SQL so the cut can
    # happen in the query rather than after fetching everything.
    _PINNING_ORDER = ("CASE d.pinning WHEN 'unpinned' THEN 4 WHEN 'partial' THEN 3 "
                      "WHEN 'unknown' THEN 2 WHEN 'exact' THEN 1 WHEN 'sha' THEN 0 "
                      "ELSE 2 END")

    def top_consumer_repositories(self, identifier: str, artifact_type: str | None,
                                  exclude_repository: str | None, limit: int) -> list[str]:
        """The `limit` repositories whose pinning of this artifact is worst.

        Injection shows a handful of consumers out of however many exist. Doing
        that cut in Python meant fetching every row first — 1,499 of them to
        render 5, then classifying each one — which is most of what a large
        index costs on a manifest read.

        A repository is ranked by its *worst* reference, not its first: a repo
        that pins an artifact loosely anywhere is loose, whatever its other
        files say.
        """
        names = identifier_candidates(identifier, artifact_type)
        sql = f"""
            SELECT r.name AS repository, MAX({self._PINNING_ORDER}) AS worst
            FROM dependencies d
            JOIN artifacts    a ON a.id = d.artifact_id
            JOIN repositories r ON r.id = d.repository_id
            WHERE a.identifier IN ({", ".join("?" * len(names))})
        """
        params: list[object] = list(names)
        if artifact_type:
            sql += " AND a.type = ?"
            params.append(artifact_type)
        if exclude_repository:
            sql += " AND r.name != ?"
            params.append(exclude_repository)
        sql += " GROUP BY r.name ORDER BY worst DESC, r.name LIMIT ?"
        params.append(limit)

        with self._conn() as conn:
            return [row["repository"] for row in conn.execute(sql, params)]

    def consumers(
        self,
        identifier: str,
        artifact_type: str | None = None,
        exclude_repository: str | None = None,
        repositories: list[str] | None = None,
    ) -> list[dict]:
        """Who uses this artifact, and exactly where.

        `artifact_type` disambiguates a name shared across ecosystems. Omitting
        it returns every type that matches, each as its own group.

        `repositories` narrows to a known set — used with
        top_consumer_repositories to fetch only the rows that will be shown.
        """
        sql = """
            SELECT a.type, a.identifier, r.name AS repository, r.owner,
                   d.version_spec, d.resolved_version, d.file_path, d.line_number,
                   d.pinning
            FROM dependencies d
            JOIN artifacts    a ON a.id = d.artifact_id
            JOIN repositories r ON r.id = d.repository_id
            WHERE a.identifier IN ({placeholders})
        """
        names = identifier_candidates(identifier, artifact_type)
        sql = sql.format(placeholders=", ".join("?" * len(names)))
        params: list[object] = list(names)
        if artifact_type:
            sql += " AND a.type = ?"
            params.append(artifact_type)
        if exclude_repository:
            sql += " AND r.name != ?"
            params.append(exclude_repository)
        if repositories is not None:
            if not repositories:
                return []
            sql += f" AND r.name IN ({', '.join('?' * len(repositories))})"
            params.extend(repositories)
        # Worst pinning first within each repository, so a caller taking the
        # first row per repo gets that repository's loosest reference.
        sql += (f" ORDER BY a.type, r.name, {self._PINNING_ORDER} DESC,"
                " d.file_path, d.line_number")

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

    # ── Injection accounting ──────────────────────────────────────────────────

    def record_injection(self, session_id: str | None, repository: str, file_path: str,
                         characters: int, artifacts: int, suppressed: bool = False) -> None:
        """Log what injection cost. It is the one price this tool charges on
        every session, and until it is measured it cannot be argued about."""
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO injections
                    (session_id, repository, file_path, characters, artifacts,
                     suppressed, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (session_id, repository, file_path, characters, artifacts,
                 int(suppressed), _now()),
            )

    def already_injected(self, session_id: str | None, repository: str,
                         file_path: str, within_minutes: int = 120) -> bool:
        """Has this exact file already been covered, recently, in this session?

        Agents re-read files constantly — before an edit, after an edit, when
        re-checking — and the second injection tells the model nothing it was
        not told ten seconds ago.

        The time bound matters because a session id cannot be fully trusted to
        be unique. Observed in practice: six separate `claude -p` runs all
        reported the same id. Without a window, one early injection would
        silence that file forever.
        """
        if not session_id or within_minutes <= 0:
            return False        # zero means "never suppress"
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT 1 FROM injections
                WHERE session_id = ? AND repository = ? AND file_path = ?
                  AND suppressed = 0
                  AND created_at >= datetime('now', ?)
                LIMIT 1
                """,
                (session_id, repository, file_path, f"-{int(within_minutes)} minutes"),
            ).fetchone()
        return row is not None

    def record_capture(self, session_id: str | None, repository: str,
                       manifests: int, characters: int) -> None:
        """Log what the Stop hook asked for.

        Injection has been measured to the token since the beginning; capture
        never was, which left the larger of the two costs as the one number
        this project took on faith. What is recorded here is the block the
        hook puts into context — not the reads and the tool call it then
        provokes, which are the model's and cannot be seen from inside a hook.
        """
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO captures
                       (session_id, repository, manifests, characters, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (session_id, repository, manifests, characters, _now()),
            )

    def capture_stats(self, days: int | None = None) -> dict:
        where, params = "", []
        if days:
            where = "WHERE created_at >= datetime('now', ?)"
            params = [f"-{int(days)} days"]

        with self._conn() as conn:
            totals = conn.execute(
                f"""
                SELECT COUNT(*) AS prompts,
                       COALESCE(SUM(characters), 0) AS chars,
                       COALESCE(SUM(manifests), 0)  AS manifests,
                       COUNT(DISTINCT session_id)   AS sessions
                FROM captures {where}
                """,
                params,
            ).fetchone()
            by_repo = conn.execute(
                f"""
                SELECT repository, COUNT(*) AS prompts,
                       COALESCE(SUM(characters), 0) AS chars
                FROM captures {where}
                GROUP BY repository ORDER BY chars DESC
                """,
                params,
            ).fetchall()

        return {
            "prompts": int(totals["prompts"]),
            "characters": int(totals["chars"]),
            "manifests": int(totals["manifests"]),
            "sessions": int(totals["sessions"]),
            "by_repository": [dict(r) for r in by_repo],
        }

    def injection_stats(self, days: int | None = None) -> dict:
        where, params = "", []
        if days:
            where = "WHERE created_at >= datetime('now', ?)"
            params = [f"-{int(days)} days"]

        with self._conn() as conn:
            totals = conn.execute(
                f"""
                SELECT
                    COUNT(*) FILTER (WHERE suppressed = 0)              AS sent,
                    COUNT(*) FILTER (WHERE suppressed = 1)              AS suppressed,
                    COALESCE(SUM(characters) FILTER (WHERE suppressed = 0), 0) AS chars,
                    COALESCE(SUM(characters) FILTER (WHERE suppressed = 1), 0) AS saved,
                    COUNT(DISTINCT session_id)                          AS sessions
                FROM injections {where}
                """,
                params,
            ).fetchone()

            by_repo = conn.execute(
                f"""
                SELECT repository,
                       COUNT(*) FILTER (WHERE suppressed = 0) AS sent,
                       COALESCE(SUM(characters) FILTER (WHERE suppressed = 0), 0) AS chars
                FROM injections {where}
                GROUP BY repository
                HAVING sent > 0
                ORDER BY chars DESC
                """,
                params,
            ).fetchall()

            by_file = conn.execute(
                f"""
                SELECT repository, file_path,
                       COUNT(*) FILTER (WHERE suppressed = 0) AS sent,
                       COALESCE(SUM(characters) FILTER (WHERE suppressed = 0), 0) AS chars
                FROM injections {where}
                GROUP BY repository, file_path
                HAVING sent > 0
                ORDER BY chars DESC
                LIMIT 10
                """,
                params,
            ).fetchall()

        return {
            "sent": totals["sent"], "suppressed": totals["suppressed"],
            "characters": totals["chars"], "characters_saved": totals["saved"],
            "sessions": totals["sessions"],
            "by_repository": [dict(r) for r in by_repo],
            "by_file": [dict(r) for r in by_file],
        }

    def impact_summary(self, keys: list[tuple[str, str]],
                       exclude_repository: str | None = None) -> dict[tuple[str, str], dict]:
        """Cross-repo impact for a batch of artifacts, in two queries.

        The injection hook runs inside a 5-second timeout on every manifest
        read, and a package.json can carry fifty dependencies. Ranking them
        one query at a time would be the slowest thing in the hot path.
        """
        if not keys:
            return {}

        clause = " OR ".join(["(a.type = ? AND a.identifier = ?)"] * len(keys))
        flat: list[object] = [part for key in keys for part in key]

        summary: dict[tuple[str, str], dict] = {
            key: {"other_consumers": 0, "version_spread": 0, "worst_severity": None}
            for key in keys
        }

        with self._conn() as conn:
            # Cached columns, not COUNT(DISTINCT) over the joined tables. The
            # caller is asking from inside a repository that consumes these
            # artifacts, so "other" is the stored total minus itself — exact,
            # and it costs one indexed lookup per artifact instead of a scan.
            rows = conn.execute(
                f"""
                SELECT a.type, a.identifier, a.consumer_count, a.version_spread,
                       EXISTS (SELECT 1 FROM dependencies d
                               JOIN repositories r ON r.id = d.repository_id
                               WHERE d.artifact_id = a.id AND r.name = ?) AS mine
                FROM artifacts a
                WHERE {clause}
                """,
                [exclude_repository or "", *flat],
            ).fetchall()
            for row in rows:
                total = int(row["consumer_count"] or 0)
                summary[(row["type"], row["identifier"])].update(
                    other_consumers=max(0, total - (1 if row["mine"] else 0)),
                    version_spread=int(row["version_spread"] or 0),
                )

            alert_rows = conn.execute(
                f"""
                SELECT a.type, a.identifier, c.severity
                FROM cve_alerts c
                JOIN artifacts a ON a.id = c.artifact_id
                WHERE c.acknowledged_at IS NULL AND ({clause})
                """,
                flat,
            ).fetchall()

        rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
        for row in alert_rows:
            key = (row["type"], row["identifier"])
            current = summary[key]["worst_severity"]
            if current is None or rank.get(row["severity"], 0) > rank.get(current, 0):
                summary[key]["worst_severity"] = row["severity"]

        return summary

    def indexed_files(self, repository: str) -> set[str]:
        """Which of one repository's files the index already holds rows from.

        Both hooks ask this on every session. Loading every dependency row in
        the index and filtering in Python cost 27ms at 8,000 rows and grew
        with the whole index rather than with the repository being asked
        about — so it got slower for everyone who indexed more repos.
        idx_deps_repo already existed to answer this.
        """
        with self._conn() as conn:
            return {row["file_path"] for row in conn.execute(
                """SELECT DISTINCT d.file_path
                   FROM dependencies d
                   JOIN repositories r ON r.id = d.repository_id
                   WHERE r.name = ?""",
                (repository,),
            )}

    def last_scanned(self, repository: str) -> str | None:
        """When this repository's manifests were last read, if ever."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT last_scanned_at FROM repositories WHERE name = ?",
                (repository,),
            ).fetchone()
        return row["last_scanned_at"] if row else None

    def all_dependencies(self) -> list[dict]:
        with self._conn() as conn:
            return [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT a.type, a.identifier, r.name AS repository,
                           d.version_spec, d.resolved_version, d.file_path, d.line_number
                    FROM dependencies d
                    JOIN artifacts    a ON a.id = d.artifact_id
                    JOIN repositories r ON r.id = d.repository_id
                    ORDER BY a.type, a.identifier
                    """
                )
            ]

    def monitorable_artifacts(self) -> list[dict]:
        """Artifacts OSV can actually answer for.

        Derived from osv.ECOSYSTEMS rather than restated here. The two were
        separate lists of the same fact, so adding an ecosystem in one place
        left this query silently excluding it — which is how a newly supported
        type gets indexed and never monitored.
        """
        # Imported here, not at module scope: osv pulls in httpx, and the
        # hooks' hot path must not pay for an HTTP client it never uses.
        from .osv import ECOSYSTEMS

        types = sorted(ECOSYSTEMS)
        placeholders = ", ".join("?" * len(types))
        with self._conn() as conn:
            return [
                dict(row)
                for row in conn.execute(
                    f"""
                    SELECT DISTINCT a.id, a.type, a.identifier
                    FROM artifacts a
                    JOIN dependencies d ON d.artifact_id = a.id
                    WHERE a.type IN ({placeholders})
                    """,
                    types,
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

    def list_alerts(self, severity: str | None = None,
                    identifier: str | None = None) -> list[dict]:
        """Every open alert, with the artifact it belongs to."""
        sql = """
            SELECT a.type, a.identifier, c.osv_id, c.cve_id, c.severity,
                   c.summary, c.url, c.applies_to, c.first_seen_at
            FROM cve_alerts c
            JOIN artifacts a ON a.id = c.artifact_id
            WHERE c.acknowledged_at IS NULL
        """
        params: list[object] = []
        if severity:
            sql += " AND c.severity = ?"
            params.append(severity)
        if identifier:
            names = identifier_candidates(identifier)
            sql += f" AND a.identifier IN ({', '.join('?' * len(names))})"
            params.extend(names)
        sql += " ORDER BY a.identifier, c.severity"
        with self._conn() as conn:
            return [dict(row) for row in conn.execute(sql, params)]

    def clear_alerts(self) -> int:
        """Drop every recorded alert so they can be re-evaluated.

        Needed whenever the applicability rules change: advisories already in
        the table are skipped as 'seen', so a new filter never gets to judge
        them. Clearing is cheaper than re-capturing the whole index.
        """
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM cve_alerts")
            return int(cur.rowcount)

    def specs_for_artifact(self, artifact_id: int) -> list[tuple[str | None, str | None]]:
        """(spec, resolved) for every distinct pin against one artifact.

        The spec is what the manifest says and permits a range; the resolved
        version is what a lockfile says is installed. Callers testing
        applicability should prefer the resolved one — it is a point, not a
        range, so the answer is exact rather than conservative.
        """
        with self._conn() as conn:
            return [
                (row["version_spec"], row["resolved_version"])
                for row in conn.execute(
                    "SELECT DISTINCT version_spec, resolved_version "
                    "FROM dependencies WHERE artifact_id = ?",
                    (artifact_id,),
                )
            ]

    def apply_resolved_versions(self, repository: str, resolved: dict[str, str]) -> int:
        """Backfill lockfile versions onto an already-captured repository."""
        updated = 0
        with self._conn() as conn:
            for name, version in resolved.items():
                cur = conn.execute(
                    """
                    UPDATE dependencies
                    SET resolved_version = ?
                    WHERE artifact_id IN (
                        SELECT id FROM artifacts WHERE type='npm_package' AND identifier = ?
                    )
                    AND repository_id = (SELECT id FROM repositories WHERE name = ?)
                    """,
                    (version, name, repository),
                )
                updated += cur.rowcount or 0
        return updated

    def alerts_for(self, identifier: str, artifact_type: str | None = None) -> list[dict]:
        sql = """
            SELECT c.osv_id, c.cve_id, c.severity, c.summary, c.url, c.first_seen_at,
                   c.applies_to
            FROM cve_alerts c
            JOIN artifacts a ON a.id = c.artifact_id
            WHERE a.identifier IN ({placeholders}) AND c.acknowledged_at IS NULL
        """
        names = identifier_candidates(identifier, artifact_type)
        sql = sql.format(placeholders=", ".join("?" * len(names)))
        params: list[object] = list(names)
        if artifact_type:
            sql += " AND a.type = ?"
            params.append(artifact_type)
        with self._conn() as conn:
            return [dict(row) for row in conn.execute(sql, params)]
