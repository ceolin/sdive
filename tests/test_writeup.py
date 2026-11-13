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
