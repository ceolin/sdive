"""Write-up validation, versions, approval and export."""

import json

import pytest

from security_dive import ledger, triage, writeup

from .test_triage import add_finding, scoped  # noqa: F401  (fixture)


def test_cvss31():
    assert writeup.cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert writeup.cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert writeup.cvss31("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H") == 7.8
    assert writeup.cvss31("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") == 4.6
    assert writeup.cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
    with pytest.raises(ledger.LedgerError, match="3.1"):
        writeup.cvss31("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    with pytest.raises(ledger.LedgerError, match="in that order"):
        writeup.cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")
    assert [writeup.severity_band(s) for s in (0, 3.9, 4.0, 8.9, 9.0)] == [
        "none", "low", "moderate", "high", "critical"]


def result(**over):
    r = {
        "cluster": "parse-len", "model": "test-model", "is_vulnerability": "yes",
        "property_violated": "P6", "attacker_class": "A2", "vuln_class": "bounds",
        "cwe": "CWE-787", "severity": "high",
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "attacker_reachable": "yes", "reachable_surface": ["image-parser"],
        "affected_components": ["src/parser.c"], "affected_functions": ["parse"],
        "introduced_by": "first commit, first released in v1.0.0",
        "affected_versions": "v1.0.0", "reportable": True, "reportable_reason": None,
        "advisory_summary": "Out-of-bounds write in parse", "advisory_description": "Text.",
        "confidence": "high", "evidence": ["src/parser.c:3 — the copy"],
        "rationale": "Because.", "affected_configurations": ["FAST"],
        "recommended_fix": "Check `len` in `parse()`.", "open_questions": [],
    }
    r.update(over)
    return r


def stage(cfg, data):
    p = writeup.result_path(cfg, "parse-len")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data))


def test_writeup_flow(cfg, scoped):  # noqa: F811
    conn, snap, mirror = scoped
    add_finding(conn, snap, "a", [("src/parser.c", 3, 6)])
    add_finding(conn, snap, "b", [("src/parser.c", 5, 5)])
    rel = triage.Releases(mirror)
    for i in triage.scope_targets(conn, "demo", [], redo=False):
        triage.scope_finding(conn, mirror, rel, i)
    triage.new_cluster(conn, "demo", "parse-len", "Parser length", "one check", ["a"])

    with pytest.raises(ledger.LedgerError, match="no track"):
        writeup.brief(conn, cfg, "parse-len")
    triage.set_track(conn, "parse-len", "advisory", "released: in v1.0.0")
    b = writeup.brief(conn, cfg, "parse-len")
    assert b["agent"] == "sdive-writer" and b["members"][0]["slug"] == "a"
    assert b["members"][0]["scope"]["verdict"] == "released"
    assert "auditor_notes" in b["members"][0] and "previous_writeup" not in b

    for bad, msg in [
        (result(severity="moderate"), "scores 7.8"),
        (result(reportable=False, reportable_reason="post-release-only: x"), "advisory"),
        (result(affected_components=["src/nope.c"]), "not a path"),
        (result(advisory_description="See /Users/x/work/snapshots/demo/src/parser.c"),
         "local paths"),
        (result(cluster="other"), "not 'parse-len'"),
        (result(cvss_vector=None), "needs cvss_vector"),
    ]:
        stage(cfg, bad)
        with pytest.raises(ledger.LedgerError, match=msg):
            writeup.record(conn, cfg, "parse-len")

    stage(cfg, result())
    r = writeup.record(conn, cfg, "parse-len")
    assert (r["version"], r["cvss_score"]) == (1, 7.8)
    assert not writeup.result_path(cfg, "parse-len").exists()
    state = lambda: writeup.status(conn, "demo")[0]["state"]  # noqa: E731
    assert state() == "draft"
    with pytest.raises(ledger.LedgerError, match="not approved"):
        writeup.export(conn, cfg, "parse-len")

    stage(cfg, result(advisory_summary="Out-of-bounds write in parse()"))
    assert writeup.record(conn, cfg, "parse-len")["version"] == 2
    assert writeup.brief(conn, cfg, "parse-len", "shorter")["previous_writeup"]["version"] == 2
    assert writeup.approve(conn, "parse-len", None, "fine") == 2
    assert state() == "approved"

    out = writeup.export(conn, cfg, "parse-len")
    assert out == cfg.export_dir("demo") / "parse-len"
    doc = json.loads((out / "cluster.json").read_text())
    assert (doc["schema"], doc["advisory_summary"], doc["cvss_score"]) == (
        "sdive-export/1", "Out-of-bounds write in parse()", 7.8)
    assert doc["reportable"] is True and doc["sha"] and doc["members"][0]["slug"] == "a"
    assert doc["provenance"]["writeup_version"] == 2 and doc["provenance"]["exported_at"]
    assert doc["provenance"]["analysis_models"] == []   # fixture findings have no runs
    fid = conn.execute("SELECT id FROM findings WHERE slug = 'a'").fetchone()[0]
    for model, status in (("model-v", "recorded"), ("model-x", "abandoned")):
        run = conn.execute("INSERT INTO runs (project, kind, snapshot_id, status, model, "
                           "started_at) VALUES ('demo', 'verify', ?, ?, ?, 'now')",
                           (snap, status, model)).lastrowid
        conn.execute("INSERT INTO run_targets (run_id, finding_id) VALUES (?, ?)", (run, fid))
    conn.commit()
    assert writeup.document(conn, cfg, "parse-len")["provenance"]["analysis_models"] == [
        "model-v"]
    assert "# Out-of-bounds write in parse()" in (out / "cluster.md").read_text()
    assert conn.execute("SELECT status FROM findings WHERE slug = 'a'").fetchone()[0] == \
        "exported"
    assert state() == "exported"

    # A membership change makes the write-up stale: no approval, no export.
    triage.add_to_cluster(conn, "parse-len", ["b"])   # clears the track too
    assert writeup.status(conn, "demo") == []
    triage.set_track(conn, "parse-len", "advisory", "released: in v1.0.0")
    assert state() == "stale"
    with pytest.raises(ledger.LedgerError, match="other members"):
        writeup.approve(conn, "parse-len", None, None)


def test_shared_fix_hands_back_to_triage(cfg, scoped):  # noqa: F811
    conn, snap, mirror = scoped
    add_finding(conn, snap, "a", [("src/parser.c", 3, 6)])
    add_finding(conn, snap, "b", [("src/parser.c", 5, 5)])
    add_finding(conn, snap, "c", [("src/util.c", 3, 3)])
    rel = triage.Releases(mirror)
    for i in triage.scope_targets(conn, "demo", [], redo=False):
        triage.scope_finding(conn, mirror, rel, i)
    for slug, f in (("parse-len", "a"), ("parse-other", "b"), ("util", "c")):
        triage.new_cluster(conn, "demo", slug, slug.title(), "fix", [f])
        triage.set_track(conn, slug, "plain-fix" if slug == "util" else "advisory", "scoped")

    # The brief names the related cluster in detail and the rest by title.
    b = writeup.brief(conn, cfg, "parse-len")
    assert [r["slug"] for r in b["related_clusters"]] == ["parse-other"]
    assert b["related_clusters"][0]["shared"] == ["src/parser.c:5"]
    assert b["related_clusters"][0]["members"] == [{"slug": "b", "title": "B"}]
    assert b["other_clusters"] == [{"slug": "util", "title": "Util"}]

    for bad, msg in [([{"cluster": "parse-len", "reason": "x"}], "itself"),
                     ([{"cluster": "nope", "reason": "x"}], "not a demo cluster")]:
        stage(cfg, result(shared_fix=bad))
        with pytest.raises(ledger.LedgerError, match=msg):
            writeup.record(conn, cfg, "parse-len")
    stage(cfg, result(shared_fix=[{"cluster": "parse-other", "reason": "same check"}]))
    assert writeup.record(conn, cfg, "parse-len")["shared_fix"][0]["cluster"] == "parse-other"
    state = lambda: {r["cluster"]: r["state"]  # noqa: E731
                     for r in writeup.status(conn, "demo")}["parse-len"]
    assert state() == "needs-triage"
    st = triage.status(conn, "demo")
    assert st["next"]["step"] == "overlaps"   # the a/b pair is undecided too
    assert [f["cluster"] for f in st["shared-fix"]] == ["parse-len"]
    with pytest.raises(ledger.LedgerError, match="also closes parse-other"):
        writeup.approve(conn, "parse-len", None, None)
    assert "shared_fix" not in writeup.document(conn, cfg, "parse-len")

    # Separating the clusters settles the flag; the draft must be redone,
    # and the next brief carries the decision.
    triage.mark_separate(conn, "demo", "parse-len", "parse-other", "two checks",
                         clusters=True)
    assert state() == "stale" and triage.status(conn, "demo")["next"] is None
    assert writeup.brief(conn, cfg, "parse-len")["related_clusters"][0]["separate"] == [
        "two checks"]
    stage(cfg, result())
    writeup.record(conn, cfg, "parse-len")
    assert state() == "draft"

    # A merge settles it too (the write-up is stale by membership).
    stage(cfg, result(shared_fix=[{"cluster": "util", "reason": "one helper"}]))
    writeup.record(conn, cfg, "parse-len")
    assert state() == "needs-triage"
    triage.add_to_cluster(conn, "parse-len", ["c"], move=True)
    triage.set_track(conn, "parse-len", "advisory", "released: in v1.0.0")
    triage.drop_cluster(conn, "util")
    assert state() == "stale" and not triage.status(conn, "demo")["shared-fix"]


def test_plain_fix_needs_unreportable(cfg, scoped):  # noqa: F811
    conn, snap, _ = scoped
    add_finding(conn, snap, "a", [("src/parser.c", 3, 6)])
    triage.new_cluster(conn, "demo", "parse-len", "P", None, ["a"])
    triage.set_track(conn, "parse-len", "plain-fix", "post-release")
    stage(cfg, result())
    with pytest.raises(ledger.LedgerError, match="plain-fix"):
        writeup.record(conn, cfg, "parse-len")
    stage(cfg, result(reportable=False, reportable_reason="post-release-only: since v1.0.0"))
    assert writeup.record(conn, cfg, "parse-len")["version"] == 1


def test_status_priority(scoped):  # noqa: F811
    conn, snap, _ = scoped
    for slug, vec, atk in [("low", "CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "A3"),
                           ("high", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "A2"),
                           ("tie3", "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "A3"),
                           ("tie1", "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "A1")]:
        add_finding(conn, snap, slug, [("src/parser.c", 3, 6)])
        conn.execute("UPDATE findings SET severity = ?, attacker = ? WHERE slug = ?",
                     (vec, atk, slug))
        triage.new_cluster(conn, "demo", f"c-{slug}", slug, None, [slug])
        triage.set_track(conn, f"c-{slug}", "advisory", "released")
    conn.commit()
    rows = writeup.status(conn, "demo")
    assert [r["cluster"] for r in rows] == ["c-high", "c-tie1", "c-tie3", "c-low"]
    assert (rows[0]["score"], rows[0]["attacker"]) == (7.8, "A2")


def test_contract_files_current(cfg):
    from security_dive.schemas import CONTRACT_FILES, contract_schema
    root = writeup.Path(__file__).resolve().parents[1] / "schemas"
    for kind, name in CONTRACT_FILES.items():
        committed = json.loads((root / name).read_text())
        assert committed == contract_schema(kind), f"run `sdive schema --write` ({name})"


def exported(cfg, conn, snap, mirror, slug, finding):
    add_finding(conn, snap, finding, [("src/parser.c", 3, 6)])
    rel = triage.Releases(mirror)
    for i in triage.scope_targets(conn, "demo", [], redo=False):
        triage.scope_finding(conn, mirror, rel, i)
    triage.new_cluster(conn, "demo", slug, slug.upper(), None, [finding])
    triage.set_track(conn, slug, "advisory", "released")
    p = writeup.result_path(cfg, slug)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(result(cluster=slug)))
    writeup.record(conn, cfg, slug)
    writeup.approve(conn, slug, None, None)
    return writeup.export(conn, cfg, slug)


def test_sync_status(cfg, scoped):  # noqa: F811
    conn, snap, mirror = scoped
    out = exported(cfg, conn, snap, mirror, "aa", "fa")
    out2 = exported(cfg, conn, snap, mirror, "bb", "fb")
    h = ledger.file_hash(out / "cluster.json")
    status = lambda d, **kw: d.joinpath("status.json").write_text(json.dumps({  # noqa: E731
        "schema": "zepsec-status/1", "project": "demo", "cluster": d.name,
        "export_hash": ledger.file_hash(d / "cluster.json"), "writeup_version": 1,
        "state": "received", "updated_at": "2026-11-13T00:00:00Z", **kw}))
    sync = lambda: {r["cluster"]: r for r in writeup.sync_status(conn, cfg, "demo")}  # noqa: E731
    fstatus = lambda s: conn.execute(  # noqa: E731
        "SELECT status, duplicate_of FROM findings WHERE slug = ?", (s,)).fetchone()

    status(out, export_hash="0" * 32)
    assert sync()["aa"]["action"] == "refused"
    status(out, state="drafted")   # no ghsa_id
    assert "ghsa_id" in sync()["aa"]["problems"][0]
    status(out, cluster="bb")
    assert sync()["aa"]["action"] == "refused"

    status(out, state="drafted", ghsa_id="GHSA-abcd-efgh-ijkl", unit="sdive-aa")
    assert sync()["aa"]["action"] == "drafted"
    assert sync()["aa"]["action"] == "unchanged"
    assert writeup.status(conn, "demo")[0]["zepsec"] == "drafted"
    note = conn.execute("SELECT note FROM finding_events ORDER BY id DESC").fetchone()[0]
    assert note == "zepsec: drafted (GHSA-abcd-efgh-ijkl)" and fstatus("fa")[0] == "exported"

    # A new version re-exported: a status still naming the first export is old.
    stage_slug = writeup.result_path(cfg, "aa")
    stage_slug.write_text(json.dumps(result(cluster="aa", advisory_summary="Revised")))
    writeup.record(conn, cfg, "aa")
    writeup.approve(conn, "aa", None, None)
    writeup.export(conn, cfg, "aa")
    status(out, export_hash=h, state="fix-open", ghsa_id="GHSA-abcd-efgh-ijkl",
           fix_prs=["https://example.invalid/pull/1"])
    r = sync()["aa"]
    assert r["action"] == "fix-open" and "older export" in r["problems"][0]

    status(out, state="fix-merged", ghsa_id="GHSA-abcd-efgh-ijkl", writeup_version=2,
           fix_prs=["https://example.invalid/pull/1"], fix_shas=["a" * 40])
    r = sync()["aa"]
    assert (r["action"], r["problems"]) == ("fix-merged", [])
    assert fstatus("fa")[0] == "fixed"

    status(out2, state="duplicate", dedup={"match": "duplicate",
                                           "advisory": "GHSA-wxyz-wxyz-wxyz"})
    assert sync()["bb"]["action"] == "duplicate"
    assert tuple(fstatus("fb")) == ("duplicate", "GHSA-wxyz-wxyz-wxyz")
    assert conn.execute("SELECT cluster_id FROM findings WHERE slug = 'fb'").fetchone()[0]



def test_labels_checked_against_threat_model(cfg, scoped):  # noqa: F811
    conn, snap, _mirror = scoped
    add_finding(conn, snap, "a", [("src/parser.c", 3, 6)])
    triage.new_cluster(conn, "demo", "parse-len", "Parser length", "one check", ["a"])
    triage.set_track(conn, "parse-len", "advisory", "released")
    cfg.project("demo").threat_model.write_text(
        "# tm\n\n- **P1 Integrity** — x\n- **P6 Availability** — y\n"
        "- **A1 Remote** — z\n- **A2 Adjacent** — w\n")
    assert writeup.threat_model_labels(cfg.project("demo").threat_model) == (
        {"P1", "P6"}, {"A1", "A2"})
    for bad, msg in [(result(attacker_class="A4"), "attacker class A4 is not defined"),
                     (result(property_violated="P3"), "property P3 is not defined")]:
        stage(cfg, bad)
        with pytest.raises(ledger.LedgerError, match=msg):
            writeup.record(conn, cfg, "parse-len")
    stage(cfg, result())
    writeup.record(conn, cfg, "parse-len")
    (cfg.project("demo").defdir / "writer.md").write_text("# guidance\n")
    assert writeup.brief(conn, cfg, "parse-len")["writer_guidance"].endswith("writer.md")
