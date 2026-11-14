"""Write-up and export: from a tracked cluster to a local file set for zepsec.

A **write-up** is the advisory draft for one cluster, written by the
`sdive-writer` subagent from a brief (the members' claims, auditor notes,
verifier reasoning and release-scoping blame) and validated here: the CVSS
vector is scored by sdive (the band must match `severity`), `reportable` must
agree with the cluster's track, cited components must exist in the snapshot,
and no absolute path may appear in the text. Each recording is a new
**version**; a human **approves** one.

An **export** writes the approved version to `<ledger>/exports/<p>/<cluster>/`:
`cluster.json` (zepsec's MCUboot `result.json` fields at top level, plus the
members, scope and provenance) and `cluster.md` (the same, readable). The
member findings move to `exported`. zepsec reads the directory locally and
writes `status.json` beside it; the export never leaves this machine and
never contains truth-set content (it is built from the ledger alone).

A write-up belongs to the member set it was written for: if the cluster's
membership changes afterwards it is **stale** and must be redone.
"""

from __future__ import annotations

import json
import math
import re
import sqlite3
import subprocess
from pathlib import Path

from pydantic import ValidationError

from . import repo, triage
from .config import Config
from .ledger import LedgerError, _event, _finding_locations, file_hash, now
from .schemas import ExportDocument, WriteupResult, ZepsecStatus

AGENT = "sdive-writer"
EXPORT_SCHEMA = "sdive-export/1"

# --- CVSS 3.1 base score -----------------------------------------------------

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss31(vector: str) -> float:
    """Base score of a CVSS 3.1 vector (the specification's formula)."""
    parts = vector.split("/")
    if parts[0] != "CVSS:3.1":
        raise LedgerError(f"{vector!r}: only CVSS:3.1 base vectors are accepted")
    m = {}
    for p in parts[1:]:
        k, _, v = p.partition(":")
        m[k] = v
    if tuple(m) != _METRICS:
        raise LedgerError(f"{vector!r}: need exactly {'/'.join(_METRICS)}, in that order")
    try:
        scope = {"U": "U", "C": "C"}[m["S"]]
        iss = 1 - math.prod(1 - _W["CIA"][m[k]] for k in ("C", "I", "A"))
        impact = (6.42 * iss if scope == "U"
                  else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15)
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * _PR[scope][m["PR"]] \
            * _W["UI"][m["UI"]]
    except KeyError as e:
        raise LedgerError(f"{vector!r}: bad metric value {e}") from None
    if impact <= 0:
        return 0.0
    total = impact + expl if scope == "U" else 1.08 * (impact + expl)
    return _roundup(min(total, 10.0))


def severity_band(score: float) -> str:
    """GitHub's advisory severity for a CVSS score."""
    if score == 0:
        return "none"
    return "low" if score < 4 else "moderate" if score < 7 else "high" if score < 9 \
        else "critical"


# --- brief -----------------------------------------------------------------


def _cluster_snapshot(conn: sqlite3.Connection, members: list[sqlite3.Row]) -> sqlite3.Row:
    snaps = {m["snapshot_id"] for m in members}
    if len(snaps) != 1:
        raise LedgerError("cluster members are at different snapshots; re-verify at one")
    return conn.execute("SELECT * FROM snapshots WHERE id = ?", (snaps.pop(),)).fetchone()


def _verifications(conn: sqlite3.Connection, cfg: Config, finding: sqlite3.Row) -> list[dict]:
    """The recorded verify runs on a finding, with the verifier's reasoning."""
    out = []
    for r in conn.execute(
            "SELECT r.id, r.model FROM run_targets t JOIN runs r ON r.id = t.run_id "
            "WHERE t.finding_id = ? AND r.kind = 'verify' AND r.status = 'recorded' "
            "ORDER BY r.id", (finding["id"],)):
        rec = cfg.run_record_path(finding["project"], r["id"])
        try:
            data = json.loads(rec.read_text())
        except (OSError, json.JSONDecodeError):
            data = {}
        out.append({"run_id": r["id"], "model": r["model"], "verdict": data.get("verdict"),
                    "reasoning": data.get("reasoning")})
    return out


def _scope(conn: sqlite3.Connection, finding: sqlite3.Row) -> dict | None:
    s = conn.execute("SELECT * FROM finding_scope WHERE finding_id = ? AND snapshot_id = ?",
                     (finding["id"], finding["snapshot_id"])).fetchone()
    if s is None:
        return None
    return {"verdict": s["verdict"], "latest_release": s["latest_release"],
            "as_is_since": s["as_is_since"], "locations": json.loads(s["detail"])}


def _active_cluster(conn: sqlite3.Connection, slug: str) -> tuple[sqlite3.Row, list]:
    c = triage._cluster(conn, slug)
    members = triage.cluster_members(conn, c["id"])
    if not members:
        raise LedgerError(f"cluster {slug} has no members")
    if not c["track"]:
        raise LedgerError(f"cluster {slug} has no track; decide it first (/sdive-triage)")
    return c, members


def brief_path(cfg: Config, slug: str) -> Path:
    return cfg.staging / f"writeup-{slug}.brief.json"


def result_path(cfg: Config, slug: str) -> Path:
    return cfg.staging / f"writeup-{slug}.json"


def latest(conn: sqlite3.Connection, cluster_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM writeups WHERE cluster_id = ? ORDER BY version DESC",
                        (cluster_id,)).fetchone()


def threat_model_labels(path: Path | None) -> tuple[set[str], set[str]]:
    """The property (P*) and attacker-class (A*) labels a threat model defines,
    from its `- **P1 Name**` / `- **A1 Name**` list items."""
    if path is None or not path.is_file():
        return set(), set()
    found = re.findall(r"^- \*\*([PA][1-9])\b", path.read_text(), re.M)
    return {x for x in found if x[0] == "P"}, {x for x in found if x[0] == "A"}


def guidance_path(project) -> Path:
    """Per-project guidance for the writer (attack vectors, surfaces, configs)."""
    return project.defdir / "writer.md"


def brief(conn: sqlite3.Connection, cfg: Config, slug: str,
          feedback: str | None = None) -> dict:
    """Everything the writer needs for one cluster, written to staging."""
    c, members = _active_cluster(conn, slug)
    project = cfg.project(c["project"])
    snap = _cluster_snapshot(conn, members)
    tree = cfg.snapshot_path(project.name, snap["sha"])
    out: dict = {
        "kind": "writeup",
        "project": project.name,
        "agent": AGENT,
        "cluster": {k: c[k] for k in ("slug", "title", "rationale", "track", "track_note")},
        "snapshot": {"sha": snap["sha"], "ref": snap["ref"], "path": str(tree)},
        "threat_model": str(project.threat_model) if project.threat_model else None,
        "writer_guidance": (str(guidance_path(project)) if guidance_path(project).is_file()
                            else None),
        "members": [],
        "brief_path": str(brief_path(cfg, slug)),
        "result_path": str(result_path(cfg, slug)),
        "result_schema": "writeup",
        "record_command": f"uv run sdive --ledger {cfg.ledger} writeup record {slug}",
    }
    refs = repo.read_marker(tree).get("references", [])
    if refs:
        out["references"] = [{"path": str(tree / r["path"]), "repo_path": r["path"],
                              "name": r["name"], "sha": r["sha"]} for r in refs]
    for m in members:
        out["members"].append({
            "slug": m["slug"], "title": m["title"], "claim": m["claim"],
            "auditor_notes": m["auditor_notes"], "property": m["property"],
            "attacker": m["attacker"], "cwe": m["cwe"], "cvss_vector": m["severity"],
            "confidence": m["confidence"], "locations": _finding_locations(conn, m["id"]),
            "verification": _verifications(conn, cfg, m), "scope": _scope(conn, m),
        })
    prev = latest(conn, c["id"])
    if prev is not None:
        out["previous_writeup"] = {"version": prev["version"],
                                   "content": json.loads(prev["content"])}
    if feedback:
        out["feedback"] = feedback
    path = brief_path(cfg, slug)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=2) + "\n")
    return out


# --- record ----------------------------------------------------------------

_ABSOLUTE = re.compile(r"(^|[\s`'\"(])(/Users/|/home/|/private/|/tmp/|/var/folders/)"
                       r"|work/snapshots/|\.worktrees/")


def _strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    return []


def validate(conn: sqlite3.Connection, cfg: Config, slug: str, data: dict) -> dict:
    """Check a writer result against the cluster; return the content to store."""
    c, members = _active_cluster(conn, slug)
    try:
        w = WriteupResult.model_validate(data)
    except ValidationError as e:
        raise LedgerError(f"result does not match the WriteupResult schema:\n{e}") from None
    problems = []
    props, attackers = threat_model_labels(cfg.project(c["project"]).threat_model)
    if props and w.property_violated and w.property_violated not in props:
        problems.append(f"property {w.property_violated} is not defined by the threat model "
                        f"({', '.join(sorted(props))})")
    if attackers and w.attacker_class and w.attacker_class not in attackers:
        problems.append(f"attacker class {w.attacker_class} is not defined by the threat model "
                        f"({', '.join(sorted(attackers))})")
    if w.cluster != slug:
        problems.append(f"result is for cluster {w.cluster!r}, not {slug!r}")
    if c["track"] == "advisory" and not w.reportable:
        problems.append("the cluster's track is advisory, so reportable must be true")
    if c["track"] == "plain-fix" and w.reportable:
        problems.append("the cluster's track is plain-fix (never released), so reportable "
                        "must be false with a post-release-only reason")
    score = None
    if w.cvss_vector:
        try:
            score = cvss31(w.cvss_vector)
            if severity_band(score) != w.severity:
                problems.append(f"{w.cvss_vector} scores {score} ({severity_band(score)}), "
                                f"but severity is {w.severity}")
        except LedgerError as e:
            problems.append(str(e))
    elif w.severity != "none":
        problems.append("a severity other than none needs a cvss_vector")
    tree = cfg.snapshot_path(c["project"], _cluster_snapshot(conn, members)["sha"])
    for comp in w.affected_components:
        p = comp.split(":", 1)[0].rstrip("/")
        if p.startswith("/") or ".." in Path(p).parts or not (tree / p).exists():
            problems.append(f"affected component {comp!r} is not a path in the snapshot")
    leaks = sorted({s[:60] for s in _strings(data) if _ABSOLUTE.search(s)})
    if leaks:
        problems.append("absolute or local paths in the text (cite repo-relative paths): "
                        + "; ".join(leaks))
    if problems:
        raise LedgerError("write-up rejected:\n- " + "\n- ".join(problems))
    content = w.model_dump()
    content["cvss_score"] = score
    return content


def record(conn: sqlite3.Connection, cfg: Config, slug: str,
           path: Path | None = None) -> dict:
    path = path or result_path(cfg, slug)
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        raise LedgerError(f"no result at {path}") from None
    except json.JSONDecodeError as e:
        raise LedgerError(f"{path} is not valid JSON: {e}") from None
    content = validate(conn, cfg, slug, data)
    c, members = _active_cluster(conn, slug)
    prev = latest(conn, c["id"])
    version = (prev["version"] if prev else 0) + 1
    inputs = {}
    agent = cfg.agent_path(AGENT)
    if agent.is_file():
        inputs["agent"] = file_hash(agent)
    bp = brief_path(cfg, slug)
    if bp.is_file():
        inputs["brief"] = file_hash(bp)
    with conn:
        conn.execute(
            "INSERT INTO writeups (cluster_id, version, content, members, model, inputs, "
            "created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (c["id"], version, json.dumps(content), json.dumps(sorted(m["slug"] for m in members)),
             content["model"], json.dumps(inputs), now()))
    bp.unlink(missing_ok=True)
    path.unlink(missing_ok=True)
    return {"cluster": slug, "version": version, "severity": content["severity"],
            "cvss_score": content["cvss_score"], "summary": content["advisory_summary"]}


def get(conn: sqlite3.Connection, slug: str, version: int | None = None) -> sqlite3.Row:
    c = triage._cluster(conn, slug)
    row = (latest(conn, c["id"]) if version is None else conn.execute(
        "SELECT * FROM writeups WHERE cluster_id = ? AND version = ?",
        (c["id"], version)).fetchone())
    if row is None:
        raise LedgerError(f"cluster {slug} has no write-up"
                          + (f" version {version}" if version else ""))
    return row


def approve(conn: sqlite3.Connection, slug: str, version: int | None, note: str | None) -> int:
    row = get(conn, slug, version)
    c, members = _active_cluster(conn, slug)
    if json.loads(row["members"]) != sorted(m["slug"] for m in members):
        raise LedgerError(f"write-up v{row['version']} of {slug} was written for other "
                          "members; write it again")
    with conn:
        conn.execute("UPDATE writeups SET approved_at = ?, approval_note = ? WHERE id = ?",
                     (now(), note, row["id"]))
    return row["version"]


# --- status ----------------------------------------------------------------


def _score(vector: str | None) -> float | None:
    try:
        return cvss31(vector) if vector else None
    except LedgerError:
        return None


def status(conn: sqlite3.Connection, project: str) -> list[dict]:
    """Per tracked cluster: where it stands between triage and export, in
    priority order.

    state: needs-writeup | stale (membership changed since the latest write-up) |
    draft (latest not approved) | approved (latest approved, not exported at that
    version) | exported.

    Priority is the CVSS score: the latest write-up's, else the highest of the
    members' verifier vectors; ties go to the weaker attacker class (A1 first),
    then to the older cluster."""
    out = []
    for c in conn.execute("SELECT * FROM clusters WHERE project = ? AND track IS NOT NULL "
                          "ORDER BY id", (project,)):
        rows = triage.cluster_members(conn, c["id"])
        if not rows:
            continue
        members = sorted(m["slug"] for m in rows)
        w = latest(conn, c["id"])
        content = json.loads(w["content"]) if w else None
        exp = conn.execute(
            "SELECT e.*, w.version FROM exports e JOIN writeups w ON w.id = e.writeup_id "
            "WHERE e.cluster_id = ? ORDER BY e.id DESC", (c["id"],)).fetchone()
        scores = [s for s in (_score(m["severity"]) for m in rows) if s is not None]
        score = content["cvss_score"] if content else (max(scores) if scores else None)
        attacker = (content or {}).get("attacker_class") or min(
            (m["attacker"] for m in rows if m["attacker"]), default=None)
        zs = conn.execute("SELECT state, ghsa_id FROM cluster_status WHERE cluster_id = ? "
                          "ORDER BY id DESC", (c["id"],)).fetchone()
        row = {"cluster": c["slug"], "title": c["title"], "track": c["track"],
               "members": len(members), "score": score, "attacker": attacker,
               "zepsec": zs["state"] if zs else None, "ghsa_id": zs["ghsa_id"] if zs else None,
               "version": w["version"] if w else None,
               "exported_version": exp["version"] if exp else None,
               "severity": content["severity"] if content else None}
        if w is None:
            row["state"] = "needs-writeup"
        elif json.loads(w["members"]) != members:
            row["state"] = "stale"
        elif not w["approved_at"]:
            row["state"] = "draft"
        elif exp is None or exp["writeup_id"] != w["id"]:
            row["state"] = "approved"
        else:
            row["state"] = "exported"
        out.append(row)
    # Stable sort: cluster id order breaks the remaining ties.
    out.sort(key=lambda r: (-(r["score"] or 0), r["attacker"] or "A9"))
    return out


# --- export ----------------------------------------------------------------


def _sdive_commit(cfg: Config) -> str | None:
    proc = subprocess.run(["git", "-C", str(cfg.root), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=False)
    return proc.stdout.strip() or None


def _analysis_models(conn: sqlite3.Connection, members: list[sqlite3.Row]) -> list[str]:
    """Models that found and verified the members (for the advisory's credit):
    the runs that raised them and the verify runs on them, not the writer."""
    ids = [m["id"] for m in members]
    marks = ",".join("?" * len(ids))
    rows = conn.execute(
        f"SELECT DISTINCT r.model FROM runs r WHERE r.model IS NOT NULL AND r.status = "
        f"'recorded' AND (r.id IN (SELECT origin_run_id FROM findings WHERE id IN ({marks})) "
        f"OR r.id IN (SELECT run_id FROM run_targets WHERE finding_id IN ({marks})))",
        ids + ids).fetchall()
    return sorted(r["model"] for r in rows)


def document(conn: sqlite3.Connection, cfg: Config, slug: str,
             row: sqlite3.Row | None = None) -> dict:
    """The export document for a cluster's write-up (default: the latest)."""
    c, members = _active_cluster(conn, slug)
    row = row or get(conn, slug)
    content = json.loads(row["content"])
    snap = _cluster_snapshot(conn, members)
    doc = {"schema": EXPORT_SCHEMA, "source": "security-dive", "project": c["project"],
           "cluster": slug, "title": c["title"], "track": c["track"],
           "track_note": c["track_note"], "sha": snap["sha"]}
    doc.update({k: v for k, v in content.items() if k not in ("cluster", "model")})
    doc["members"] = []
    for m in members:
        verifs = _verifications(conn, cfg, m)
        doc["members"].append({
            "slug": m["slug"], "title": m["title"], "claim": m["claim"],
            "property": m["property"], "attacker": m["attacker"], "cwe": m["cwe"],
            "cvss_vector": m["severity"], "confidence": m["confidence"],
            "locations": _finding_locations(conn, m["id"]),
            "carried_from": m["carried_from"],
            "verification": [{"run_id": v["run_id"], "model": v["model"],
                              "verdict": v["verdict"]} for v in verifs],
            "scope": {k: v for k, v in (_scope(conn, m) or {}).items() if k != "locations"},
        })
    doc["scope"] = triage.combine([m["scope"] for m in members])
    doc["provenance"] = {
        "ledger": cfg.ledger, "snapshot": {"sha": snap["sha"], "ref": snap["ref"]},
        "writeup_version": row["version"], "written_by": row["model"],
        "written_at": row["created_at"], "approved_at": row["approved_at"],
        "approval_note": row["approval_note"],
        "origin_runs": sorted({m["origin_run_id"] for m in members if m["origin_run_id"]}),
        "analysis_models": _analysis_models(conn, members),
        "sdive_commit": _sdive_commit(cfg),
    }
    return doc


def render_md(doc: dict) -> str:
    """cluster.md: the export, readable."""
    score = f" ({doc['cvss_score']})" if doc.get("cvss_score") is not None else ""
    lines = [
        f"# {doc.get('advisory_summary') or doc['title']}", "",
        f"- **Cluster:** `{doc['cluster']}` ({len(doc['members'])} finding"
        f"{'s' if len(doc['members']) != 1 else ''}), track **{doc['track']}**"
        f" ({doc.get('track_note') or ''})",
        f"- **Severity:** {doc['severity']}{score} `{doc.get('cvss_vector') or ''}`",
        f"- **Property / attacker:** {doc.get('property_violated')} / "
        f"{doc.get('attacker_class')}; {doc.get('cwe')}; {doc.get('vuln_class')}",
        f"- **Reportable:** {doc['reportable']}"
        + (f" ({doc['reportable_reason']})" if doc.get("reportable_reason") else ""),
        f"- **Affected versions:** {doc.get('affected_versions')}",
        f"- **Introduced by:** {doc.get('introduced_by')}",
        f"- **Components:** {', '.join(f'`{x}`' for x in doc['affected_components'])}",
        f"- **Functions:** {', '.join(f'`{x}`' for x in doc['affected_functions'])}",
        f"- **Configurations:** {', '.join(f'`{x}`' for x in doc['affected_configurations'])}",
        f"- **Reachable surface:** {', '.join(doc['reachable_surface'])} "
        f"(reachable: {doc['attacker_reachable']}; confidence {doc['confidence']})",
        f"- **Snapshot:** `{doc['sha'][:12]}`",
        "", "## Advisory description", "", doc.get("advisory_description") or "(none)",
        "", "## Recommended fix", "", doc["recommended_fix"],
        "", "## Rationale", "", doc["rationale"],
        "", "## Evidence", "", *[f"- {e}" for e in doc["evidence"]],
    ]
    if doc.get("open_questions"):
        lines += ["", "## Open questions", "", *[f"- {q}" for q in doc["open_questions"]]]
    lines += ["", "## Findings", ""]
    for m in doc["members"]:
        scope = m.get("scope") or {}
        lines += [f"### {m['title']}", "",
                  f"`{m['slug']}`: {m['property']} / {m['attacker']}, {m['cwe']}, "
                  f"`{m['cvss_vector']}`; scope {scope.get('verdict')}, as-is since "
                  f"{scope.get('as_is_since')}"
                  + (f"; carried from `{m['carried_from']}`" if m.get("carried_from") else ""),
                  "", m["claim"], ""]
    p = doc["provenance"]
    lines += ["## Provenance", "",
              f"Write-up v{p['writeup_version']} by {p['written_by']} at {p['written_at']}, "
              f"approved {p['approved_at']}"
              + (f" ({p['approval_note']})" if p.get("approval_note") else "")
              + f"; found and verified by {', '.join(p['analysis_models']) or 'unrecorded models'}"
              + f"; ledger `{p['ledger']}`, sdive `{(p['sdive_commit'] or '')[:12]}`.", ""]
    return "\n".join(lines)


def export(conn: sqlite3.Connection, cfg: Config, slug: str) -> Path:
    """Write the cluster's approved write-up to its export directory and move
    the members to `exported`."""
    c, members = _active_cluster(conn, slug)
    row = get(conn, slug)
    if json.loads(row["members"]) != sorted(m["slug"] for m in members):
        raise LedgerError(f"{slug}: write-up v{row['version']} is stale (membership changed)")
    if not row["approved_at"]:
        raise LedgerError(f"{slug}: write-up v{row['version']} is not approved")
    bad = [m["slug"] for m in members if m["status"] not in ("verified", "exported")]
    if bad:
        raise LedgerError(f"{slug}: members not verified: {', '.join(bad)}")
    doc = document(conn, cfg, slug, row)
    doc["provenance"]["exported_at"] = now()
    try:   # the export is a contract with zepsec: never write one that breaks it
        ExportDocument.model_validate(doc)
    except ValidationError as e:
        raise LedgerError(f"{slug}: export does not match sdive-export/1:\n{e}") from None
    out = cfg.export_dir(c["project"]) / slug
    out.mkdir(parents=True, exist_ok=True)
    (out / "cluster.json").write_text(json.dumps(doc, indent=2) + "\n")
    (out / "cluster.md").write_text(render_md(doc))
    with conn:
        conn.execute("INSERT INTO exports (cluster_id, writeup_id, path, content_hash, "
                     "exported_at) VALUES (?, ?, ?, ?, ?)",
                     (c["id"], row["id"], str(out), file_hash(out / "cluster.json"),
                      doc["provenance"]["exported_at"]))
        for m in members:
            if m["status"] == "verified":
                conn.execute("UPDATE findings SET status = 'exported', updated_at = ? "
                             "WHERE id = ?", (now(), m["id"]))
                _event(conn, m["id"], None, "verified", "exported",
                       f"exported with cluster {slug}, write-up v{row['version']}")
    return out


# --- status back from zepsec -----------------------------------------------


def _member_rows(conn: sqlite3.Connection, cluster_id: int) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM findings WHERE cluster_id = ? ORDER BY id",
                        (cluster_id,)).fetchall()


def sync_status(conn: sqlite3.Connection, cfg: Config, project: str) -> list[dict]:
    """Read every export's status.json (written by zepsec) and record changes.

    A status names the export it refers to by hash; one sdive never wrote is
    refused. Effects on the members: `duplicate` (of an existing advisory)
    moves exported findings to `duplicate`, with the GHSA id as duplicate_of;
    `fix-merged` and `published` (with fix SHAs) move them to `fixed`; every
    other state change is noted in their history. Unchanged files are skipped.
    """
    out = []
    root = cfg.export_dir(project)
    for path in sorted(root.glob("*/status.json")) if root.is_dir() else []:
        slug = path.parent.name
        rep = {"cluster": slug, "action": "unchanged", "problems": []}
        out.append(rep)
        try:
            raw = path.read_text()
            st = ZepsecStatus.model_validate(json.loads(raw))
        except (OSError, json.JSONDecodeError, ValidationError) as e:
            rep["action"], rep["problems"] = "refused", [f"invalid status.json: {e}"]
            continue
        if (st.project, st.cluster) != (project, slug):
            rep["action"] = "refused"
            rep["problems"].append(f"status is for {st.project}/{st.cluster}, "
                                   f"found in {project}/{slug}")
            continue
        c = conn.execute("SELECT * FROM clusters WHERE slug = ? AND project = ?",
                         (slug, project)).fetchone()
        exp = c and conn.execute(
            "SELECT e.*, w.version FROM exports e JOIN writeups w ON w.id = e.writeup_id "
            "WHERE e.cluster_id = ? AND e.content_hash = ? ORDER BY e.id DESC",
            (c["id"], st.export_hash)).fetchone()
        if not exp:
            rep["action"] = "refused"
            rep["problems"].append(f"export_hash {st.export_hash} matches no export of "
                                   f"{slug} that sdive wrote")
            continue
        if exp["version"] != st.writeup_version:
            rep["problems"].append(f"writeup_version {st.writeup_version} but that export "
                                   f"is v{exp['version']}")
        last_exp = conn.execute("SELECT id FROM exports WHERE cluster_id = ? ORDER BY id DESC",
                                (c["id"],)).fetchone()
        if last_exp["id"] != exp["id"]:
            rep["problems"].append("status refers to an older export; zepsec has not "
                                   "picked up the latest")
        content = st.model_dump(by_alias=True)
        prev = conn.execute("SELECT content FROM cluster_status WHERE cluster_id = ? "
                            "ORDER BY id DESC", (c["id"],)).fetchone()
        if prev and json.loads(prev["content"]) == content:
            continue
        rep["action"] = st.state
        with conn:
            conn.execute(
                "INSERT INTO cluster_status (cluster_id, export_id, state, ghsa_id, cve_id, "
                "content, updated_at, synced_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (c["id"], exp["id"], st.state, st.ghsa_id, st.cve_id, json.dumps(content),
                 st.updated_at, now()))
            refs = ", ".join(x for x in (st.ghsa_id, st.cve_id) if x)
            for m in _member_rows(conn, c["id"]):
                if st.state == "duplicate" and m["status"] == "exported":
                    # Stays in its cluster: the cluster is what was exported and matched.
                    conn.execute("UPDATE findings SET status = 'duplicate', duplicate_of = ?, "
                                 "updated_at = ? WHERE id = ?",
                                 (st.dedup.advisory, now(), m["id"]))
                    _event(conn, m["id"], None, "exported", "duplicate",
                           f"zepsec: duplicate of {st.dedup.advisory}")
                elif st.state in ("fix-merged", "published") and st.fix_shas \
                        and m["status"] == "exported":
                    conn.execute("UPDATE findings SET status = 'fixed', updated_at = ? "
                                 "WHERE id = ?", (now(), m["id"]))
                    _event(conn, m["id"], None, "exported", "fixed",
                           f"zepsec: fixed by {', '.join(s[:12] for s in st.fix_shas)}"
                           + (f" ({refs})" if refs else ""))
                else:
                    _event(conn, m["id"], None, m["status"], m["status"],
                           f"zepsec: {st.state}" + (f" ({refs})" if refs else ""))
    return out
