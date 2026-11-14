"""SQLite ledger: schema and connection."""

from __future__ import annotations

import sqlite3
from pathlib import Path

# Each entry migrates from user_version == index to index + 1. Append only.
MIGRATIONS: list[str] = [
    """
    CREATE TABLE snapshots (
        id          INTEGER PRIMARY KEY,
        project     TEXT NOT NULL,
        sha         TEXT NOT NULL,
        ref         TEXT,
        created_at  TEXT NOT NULL,
        indexed_at  TEXT,
        UNIQUE (project, sha)
    );

    -- Stable identity of a piece of code across snapshots.
    CREATE TABLE units (
        id       INTEGER PRIMARY KEY,
        project  TEXT NOT NULL,
        key      TEXT NOT NULL,
        kind     TEXT NOT NULL CHECK (kind IN ('file', 'function')),
        path     TEXT NOT NULL,
        symbol   TEXT,
        UNIQUE (project, key)
    );

    -- A unit as it exists in one snapshot.
    CREATE TABLE unit_versions (
        snapshot_id   INTEGER NOT NULL REFERENCES snapshots(id),
        unit_id       INTEGER NOT NULL REFERENCES units(id),
        content_hash  TEXT NOT NULL,
        area          TEXT NOT NULL,
        priority      INTEGER NOT NULL,
        start_line    INTEGER NOT NULL,
        end_line      INTEGER NOT NULL,
        PRIMARY KEY (snapshot_id, unit_id)
    );

    -- A lens is identified by name *and* content: editing it is a new version.
    CREATE TABLE lenses (
        id             INTEGER PRIMARY KEY,
        project        TEXT NOT NULL,
        name           TEXT NOT NULL,
        content_hash   TEXT NOT NULL,
        registered_at  TEXT NOT NULL,
        UNIQUE (project, name, content_hash)
    );

    CREATE TABLE runs (
        id           INTEGER PRIMARY KEY,
        project      TEXT NOT NULL,
        kind         TEXT NOT NULL CHECK (kind IN ('sweep', 'dive', 'verify', 'change')),
        snapshot_id  INTEGER REFERENCES snapshots(id),
        lens_id      INTEGER REFERENCES lenses(id),
        status       TEXT NOT NULL CHECK (status IN ('started', 'recorded', 'abandoned')),
        model        TEXT,
        inputs       TEXT,   -- JSON: hashes of threat model, agent/skill files, etc.
        started_at   TEXT NOT NULL,
        finished_at  TEXT,
        summary      TEXT
    );

    CREATE TABLE run_targets (
        run_id      INTEGER NOT NULL REFERENCES runs(id),
        unit_id     INTEGER REFERENCES units(id),
        finding_id  INTEGER REFERENCES findings(id),
        CHECK ((unit_id IS NULL) != (finding_id IS NULL))
    );
    CREATE INDEX run_targets_run ON run_targets(run_id);

    -- "Unit U, as it read at content_hash, was examined under lens L by run R."
    CREATE TABLE coverage (
        unit_id       INTEGER NOT NULL REFERENCES units(id),
        content_hash  TEXT NOT NULL,
        lens_id       INTEGER REFERENCES lenses(id),
        run_id        INTEGER NOT NULL REFERENCES runs(id),
        status        TEXT NOT NULL CHECK (status IN ('clean', 'hypotheses', 'partial')),
        note          TEXT,
        PRIMARY KEY (unit_id, run_id)
    );
    CREATE INDEX coverage_lookup ON coverage(unit_id, content_hash, lens_id);

    CREATE TABLE findings (
        id             INTEGER PRIMARY KEY,
        project        TEXT NOT NULL,
        slug           TEXT NOT NULL UNIQUE,
        title          TEXT NOT NULL,
        status         TEXT NOT NULL,
        claim          TEXT NOT NULL,
        auditor_notes  TEXT,
        confidence     TEXT,
        property       TEXT,
        attacker       TEXT,
        cwe            TEXT,
        severity       TEXT,
        duplicate_of   TEXT,
        snapshot_id    INTEGER REFERENCES snapshots(id),
        origin_run_id  INTEGER REFERENCES runs(id),
        created_at     TEXT NOT NULL,
        updated_at     TEXT NOT NULL
    );

    CREATE TABLE finding_locations (
        finding_id  INTEGER NOT NULL REFERENCES findings(id),
        path        TEXT NOT NULL,
        start_line  INTEGER NOT NULL,
        end_line    INTEGER,
        symbol      TEXT,
        unit_id     INTEGER REFERENCES units(id)
    );

    CREATE TABLE finding_events (
        id           INTEGER PRIMARY KEY,
        finding_id   INTEGER NOT NULL REFERENCES findings(id),
        run_id       INTEGER REFERENCES runs(id),
        at           TEXT NOT NULL,
        from_status  TEXT,
        to_status    TEXT NOT NULL,
        note         TEXT
    );
    """,
    # v2: suspected defects in external (reference) components, for later filing.
    """
    CREATE TABLE upstream_notes (
        id             INTEGER PRIMARY KEY,
        project        TEXT NOT NULL,
        run_id         INTEGER NOT NULL REFERENCES runs(id),
        component      TEXT NOT NULL,
        component_url  TEXT,
        component_sha  TEXT,
        title          TEXT NOT NULL,
        description    TEXT NOT NULL,
        locations      TEXT NOT NULL,   -- JSON list of Location
        status         TEXT NOT NULL DEFAULT 'noted',
        created_at     TEXT NOT NULL
    );
    """,
    # v3: findings carried in from another ledger ("<ledger>:<slug>").
    """
    ALTER TABLE findings ADD COLUMN carried_from TEXT;
    """,
    # v4: triage after verification. A cluster is a set of verified findings one
    # fix closes: the unit of a fix PR and of an advisory. Its track (advisory /
    # plain-fix) is a recorded human decision; finding_scope is the evidence for
    # it, from blaming each finding's lines against the release tags.
    """
    CREATE TABLE clusters (
        id          INTEGER PRIMARY KEY,
        project     TEXT NOT NULL,
        slug        TEXT NOT NULL UNIQUE,
        title       TEXT NOT NULL,
        rationale   TEXT,
        track       TEXT CHECK (track IN ('advisory', 'plain-fix')),
        track_note  TEXT,
        created_at  TEXT NOT NULL,
        updated_at  TEXT NOT NULL
    );
    ALTER TABLE findings ADD COLUMN cluster_id INTEGER REFERENCES clusters(id);

    CREATE TABLE finding_scope (
        finding_id      INTEGER NOT NULL REFERENCES findings(id),
        snapshot_id     INTEGER NOT NULL REFERENCES snapshots(id),
        latest_release  TEXT,   -- newest release tag that is an ancestor of the snapshot
        verdict         TEXT NOT NULL
                        CHECK (verdict IN ('released', 'post-release', 'mixed', 'unknown')),
        as_is_since     TEXT,   -- first release holding every released flagged line as it reads now
        detail          TEXT NOT NULL,   -- JSON: per location, blamed commits and their releases
        scoped_at       TEXT NOT NULL,
        PRIMARY KEY (finding_id, snapshot_id)
    );
    """,
    # v5: write-up and export. A write-up is a versioned advisory draft for one
    # cluster (validated agent output); a human approves a version, and an
    # export writes that version to analysis/exports/ for zepsec.
    """
    CREATE TABLE writeups (
        id             INTEGER PRIMARY KEY,
        cluster_id     INTEGER NOT NULL REFERENCES clusters(id),
        version        INTEGER NOT NULL,
        content        TEXT NOT NULL,   -- JSON: the validated write-up plus cvss_score
        members        TEXT NOT NULL,   -- JSON: member slugs it was written for
        model          TEXT,
        inputs         TEXT,            -- JSON: agent file hash, brief hash
        created_at     TEXT NOT NULL,
        approved_at    TEXT,
        approval_note  TEXT,
        UNIQUE (cluster_id, version)
    );

    CREATE TABLE exports (
        id            INTEGER PRIMARY KEY,
        cluster_id    INTEGER NOT NULL REFERENCES clusters(id),
        writeup_id    INTEGER NOT NULL REFERENCES writeups(id),
        path          TEXT NOT NULL,
        content_hash  TEXT NOT NULL,
        exported_at   TEXT NOT NULL
    );
    """,
    # v6: status back from zepsec. Each change of an export's status.json, as
    # read by `sdive sync-status`: the zepsec-side state of a cluster.
    """
    CREATE TABLE cluster_status (
        id          INTEGER PRIMARY KEY,
        cluster_id  INTEGER NOT NULL REFERENCES clusters(id),
        export_id   INTEGER NOT NULL REFERENCES exports(id),
        state       TEXT NOT NULL,
        ghsa_id     TEXT,
        cve_id      TEXT,
        content     TEXT NOT NULL,   -- status.json as read (JSON)
        updated_at  TEXT NOT NULL,   -- zepsec's timestamp
        synced_at   TEXT NOT NULL
    );
    """,
    # v7: ranking. Signals (JSON hit counts) and the queue score per unit
    # version; which recorded builds compile each file; the ranker agent's
    # reach judgements (latest per unit wins).
    """
    ALTER TABLE unit_versions ADD COLUMN signals TEXT;
    ALTER TABLE unit_versions ADD COLUMN score REAL;

    CREATE TABLE builds (
        id           INTEGER PRIMARY KEY,
        snapshot_id  INTEGER NOT NULL REFERENCES snapshots(id),
        name         TEXT NOT NULL,
        board        TEXT,
        config       TEXT,   -- JSON: the build definition (overlay, extra args)
        status       TEXT NOT NULL CHECK (status IN ('ok', 'failed')),
        files        INTEGER,
        log          TEXT,
        built_at     TEXT NOT NULL,
        UNIQUE (snapshot_id, name)
    );

    CREATE TABLE file_builds (
        snapshot_id  INTEGER NOT NULL REFERENCES snapshots(id),
        path         TEXT NOT NULL,
        build_id     INTEGER NOT NULL REFERENCES builds(id),
        PRIMARY KEY (snapshot_id, path, build_id)
    );

    CREATE TABLE unit_reach (
        id           INTEGER PRIMARY KEY,
        snapshot_id  INTEGER NOT NULL REFERENCES snapshots(id),
        unit_id      INTEGER NOT NULL REFERENCES units(id),
        reach        INTEGER NOT NULL CHECK (reach BETWEEN 0 AND 3),
        attacker     TEXT,
        reason       TEXT,
        model        TEXT,
        created_at   TEXT NOT NULL
    );
    CREATE INDEX unit_reach_lookup ON unit_reach(snapshot_id, unit_id);
    """,
    # v8: what enables each source file, from the build system (Zephyr's
    # CMakeLists *_ifdef(CONFIG_...) chain); JSON list of conditions, ANDed.
    """
    CREATE TABLE file_conditions (
        snapshot_id  INTEGER NOT NULL REFERENCES snapshots(id),
        path         TEXT NOT NULL,
        conditions   TEXT NOT NULL,
        PRIMARY KEY (snapshot_id, path)
    );
    """,
]


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    migrate(conn)
    return conn


def migrate(conn: sqlite3.Connection) -> None:
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > len(MIGRATIONS):
        raise RuntimeError(f"database schema v{version} is newer than this sdive")
    for i in range(version, len(MIGRATIONS)):
        conn.executescript(f"BEGIN;\n{MIGRATIONS[i]}\nPRAGMA user_version = {i + 1};\nCOMMIT;")
