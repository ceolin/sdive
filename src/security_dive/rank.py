"""Ranking: the order in which work is handed out.

Zephyr's attack surfaces alone are ~30x MCUboot's core, so the queue must put
the likeliest code first. A unit's **score** is its area priority plus:

- a bonus for **signals** in its text (deterministic, computed at indexing):
  packet and PDU accessors, copies, length arithmetic, syscall verification,
  assertion-only checks, reference counting, handler-like names;
- an adjustment for **builds** (`sdive build`), once any are recorded: code no
  recorded build compiles sinks;
- an adjustment for **reach**, the cheap `sdive-ranker` agent's judgement of
  how directly an attacker reaches the function (`/sdive-rank`).

Queues order by score (then path and line), so area priority stays the main
key and the rest orders work within and across neighbouring bands.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from .config import Config, Project
from .schemas import RankResult


class RankError(Exception):
    pass

# name, pattern, weight per hit, cap on hits counted
SIGNALS: list[tuple[str, re.Pattern[str], float, int]] = [
    ("parse", re.compile(
        r"\b(?:net_buf_(?:simple_)?(?:pull|remove)\w*|net_pkt_(?:read|skip|get_data|cursor_)\w*"
        r"|NET_PKT_DATA_ACCESS\w*|sys_get_(?:le|be)\d+|zcbor_\w+_(?:decode|get)\w*"
        r"|json_\w*parse\w*|coap_\w+_(?:get|find)\w*|bt_\w+_pull\w*)\s*\("), 0.15, 6),
    ("copy", re.compile(
        r"\b(?:memcpy|memmove|strcpy|strncpy|strcat|strncat|sprintf|net_buf_(?:simple_)?add_mem"
        r"|net_pkt_write\w*|k_usermode_\w*copy)\s*\("), 0.1, 6),
    ("len_arith", re.compile(
        r"\b\w*(?:len|size|offset|off|count|cnt|remaining)\w*\s*-[^>=-]|-\s*sizeof\b"
        r"|\b\w*(?:len|size)\w*\s*\+=", re.IGNORECASE), 0.1, 6),
    ("syscall", re.compile(r"\b(?:K_SYSCALL_\w+|z_vrfy_\w+|k_usermode_\w+|K_OOPS)\b"), 0.25, 4),
    ("assert_check", re.compile(
        r"__ASSERT(?:_NO_MSG)?\s*\([^;]*\b\w*(?:len|size|idx|index|count)\w*", re.IGNORECASE),
     0.15, 3),
    ("lifetime", re.compile(
        r"\b(?:\w+_unref|\w+_ref|k_work_cancel\w*|k_free|k_heap_free|net_pkt_frag_unref"
        r"|k_object_free)\s*\("), 0.05, 6),
]
HANDLER_NAME = re.compile(
    r"(?:^|_)(?:recv|rx|input|handle|handler|parse|process|decode|req|rsp|ind|cb|"
    r"setup|vendor_request|class_request|event)(?:_|$)|^z_vrfy_", re.IGNORECASE)
MAX_SIGNAL_BONUS = 1.5
UNBUILT = -1.5
REACH_ADJ = {0: -2.0, 1: -0.5, 2: 0.5, 3: 1.5}


def signals(text: str, name: str | None) -> dict[str, int]:
    """Signal hit counts for one function's source text (comments included;
    cheap and good enough for ordering)."""
    out = {k: len(p.findall(text)) for k, p, _w, _cap in SIGNALS}
    out = {k: v for k, v in out.items() if v}
    if name and HANDLER_NAME.search(name):
        out["handler"] = 1
    return out


def signal_bonus(sig: dict[str, int]) -> float:
    weights = {k: (w, cap) for k, _p, w, cap in SIGNALS}
    total = sum(w * min(sig.get(k, 0), cap) for k, (w, cap) in weights.items())
    total += 0.2 * sig.get("handler", 0)
    return min(MAX_SIGNAL_BONUS, round(total, 3))


def score(priority: int, sig: dict[str, int], built: bool | None, reach: int | None) -> float:
    s = priority + signal_bonus(sig)
    if built is False:
        s += UNBUILT
    if reach is not None:
        s += REACH_ADJ[reach]
    return round(s, 3)


def rescore(conn: sqlite3.Connection, snap: int) -> int:
    """Recompute every unit's score in `snap` from its priority, signals,
    the snapshot's recorded builds (if any) and recorded reach. Returns the
    number of units scored."""
    have_builds = conn.execute(
        "SELECT 1 FROM file_builds WHERE snapshot_id = ? LIMIT 1", (snap,)).fetchone() is not None
    built_paths = {r[0] for r in conn.execute(
        "SELECT DISTINCT path FROM file_builds WHERE snapshot_id = ?", (snap,))}
    reach = {r["unit_id"]: r["reach"] for r in conn.execute(
        """SELECT unit_id, reach FROM unit_reach WHERE snapshot_id = ?
           AND id IN (SELECT max(id) FROM unit_reach WHERE snapshot_id = ? GROUP BY unit_id)""",
        (snap, snap))}
    rows = conn.execute(
        """SELECT uv.unit_id, uv.priority, uv.signals, u.path FROM unit_versions uv
           JOIN units u ON u.id = uv.unit_id WHERE uv.snapshot_id = ?""", (snap,)).fetchall()
    with conn:
        conn.executemany(
            "UPDATE unit_versions SET score = ? WHERE snapshot_id = ? AND unit_id = ?",
            [(score(r["priority"], json.loads(r["signals"] or "{}"),
                    (r["path"] in built_paths) if have_builds else None,
                    reach.get(r["unit_id"])), snap, r["unit_id"]) for r in rows])
    return len(rows)


# --- the ranker agent ------------------------------------------------------
#
# `/sdive-rank` hands batches of the top-scored files whose functions have no
# reach judgement yet to the cheap `sdive-ranker` subagent. Rank briefs are
# not ledger runs (no coverage, no findings): a brief in staging leases its
# units until it is recorded or deleted.

RANK_MAX_FUNCTIONS = 120


def _outstanding(cfg: Config) -> set[str]:
    keys: set[str] = set()
    for f in cfg.staging.glob("rank-*.brief.json"):
        try:
            b = json.loads(f.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        keys.update(fn["key"] for file in b.get("files", []) for fn in file["functions"])
    return keys


def unranked(conn: sqlite3.Connection, snap: int, min_priority: int = 0) -> list[sqlite3.Row]:
    """Function units in `snap` with no reach judgement, best score first."""
    return conn.execute(
        """SELECT u.id, u.key, u.path, u.symbol, uv.area, uv.priority, uv.score,
                  uv.start_line, uv.end_line, uv.signals
           FROM unit_versions uv JOIN units u ON u.id = uv.unit_id
           WHERE uv.snapshot_id = ? AND u.kind = 'function' AND uv.priority >= ?
             AND NOT EXISTS (SELECT 1 FROM unit_reach r
                             WHERE r.snapshot_id = uv.snapshot_id AND r.unit_id = uv.unit_id)
           ORDER BY uv.score DESC, u.path, uv.start_line""", (snap, min_priority)).fetchall()


def write_brief(conn: sqlite3.Connection, cfg: Config, project: Project, snap: int,
                max_functions: int = RANK_MAX_FUNCTIONS, min_priority: int = 0) -> dict | None:
    """A rank brief for the best unranked files (whole files, by their best
    function's score, up to `max_functions`), or None when nothing is left."""
    leased = _outstanding(cfg)
    rows = [r for r in unranked(conn, snap, min_priority) if r["key"] not in leased]
    if not rows:
        return None
    files: dict[str, list] = {}
    for r in rows:
        files.setdefault(r["path"], []).append(r)
    batch, n = [], 0
    for path, fns in files.items():
        if batch and n + len(fns) > max_functions:
            break
        fns = sorted(fns, key=lambda r: r["start_line"])
        batch.append({"path": path, "area": fns[0]["area"], "functions": [
            {"key": r["key"], "symbol": r["symbol"], "start_line": r["start_line"],
             "end_line": r["end_line"], "signals": json.loads(r["signals"] or "{}")}
            for r in fns]})
        n += len(fns)
    sha = conn.execute("SELECT sha FROM snapshots WHERE id = ?", (snap,)).fetchone()[0]
    brief_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")
    staging = cfg.staging
    staging.mkdir(parents=True, exist_ok=True)
    b = {
        "brief_id": brief_id,
        "kind": "rank",
        "project": project.name,
        "snapshot": {"sha": sha, "path": str(cfg.snapshot_path(project.name, sha))},
        "threat_model": str(project.threat_model) if project.threat_model else None,
        "agent": "sdive-ranker",
        "brief_path": str(staging / f"rank-{brief_id}.brief.json"),
        "result_path": str(staging / f"rank-{brief_id}.json"),
        "result_schema": "rank",
        "record_command": f"uv run sdive --ledger {cfg.ledger} rank record {brief_id}",
        "files": batch,
    }
    Path(b["brief_path"]).write_text(json.dumps(b, indent=2) + "\n")
    return b


def record(conn: sqlite3.Connection, cfg: Config, brief_id: str,
           result_path: Path | None = None) -> int:
    """Validate a ranker result against its brief, store the judgements,
    rescore the snapshot. Returns the number of units judged."""
    bpath = cfg.staging / f"rank-{brief_id}.brief.json"
    if not bpath.is_file():
        raise RankError(f"no rank brief {brief_id} in {cfg.staging}")
    b = json.loads(bpath.read_text())
    rpath = result_path or Path(b["result_path"])
    if not rpath.is_file():
        raise RankError(f"no result file {rpath}")
    try:
        result = RankResult.model_validate_json(rpath.read_text())
    except ValidationError as e:
        raise RankError(f"result does not match the RankResult schema:\n{e}") from None
    if result.brief_id != brief_id:
        raise RankError(f"result is for brief {result.brief_id}, not {brief_id}")
    wanted = {fn["key"] for f in b["files"] for fn in f["functions"]}
    got = {u.key for u in result.units}
    if got - wanted:
        raise RankError(f"units not in the brief: {sorted(got - wanted)[:5]}")
    if wanted - got:
        raise RankError(f"{len(wanted - got)} brief units have no judgement, e.g. "
                        f"{sorted(wanted - got)[:5]}")
    snap = conn.execute(
        "SELECT id FROM snapshots WHERE project = ? AND sha = ?",
        (b["project"], b["snapshot"]["sha"])).fetchone()[0]
    ids = {r["key"]: r["id"] for r in conn.execute(
        "SELECT id, key FROM units WHERE project = ?", (b["project"],))}
    ts = datetime.now(UTC).isoformat(timespec="seconds")
    with conn:
        conn.executemany(
            "INSERT INTO unit_reach (snapshot_id, unit_id, reach, attacker, reason, model, "
            "created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(snap, ids[u.key], u.reach, u.attacker, u.reason, result.model, ts)
             for u in result.units])
    rescore(conn, snap)
    out = cfg.ledger_dir / "rank" / b["project"] / f"rank-{brief_id}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(rpath.read_text())
    bpath.unlink()
    rpath.unlink(missing_ok=True)
    return len(result.units)
