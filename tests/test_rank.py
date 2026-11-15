import json

import pytest

from security_dive import rank
from security_dive.units import extract_source

from .test_flow import indexed  # noqa: F401  (fixture)


def test_signals_and_bonus():
    src = """\
int l2cap_recv(struct net_buf *buf)
{
    struct hdr *h = net_buf_pull_mem(buf, sizeof(*h));
    uint16_t len = sys_le16_to_cpu(h->len);
    __ASSERT(len <= buf->len, "bad len");
    memcpy(dst, buf->data, len - 4);
    net_buf_unref(buf);
    return 0;
}
"""
    sig = rank.signals(src, "l2cap_recv")
    assert sig == {"parse": 1, "copy": 1, "len_arith": 1, "assert_check": 1, "lifetime": 1,
                   "handler": 1}
    assert rank.signal_bonus(sig) == pytest.approx(0.15 + 0.1 + 0.1 + 0.15 + 0.05 + 0.2)
    assert rank.signal_bonus({"parse": 100, "copy": 100, "syscall": 100,
                              "len_arith": 100}) == rank.MAX_SIGNAL_BONUS
    assert rank.score(5, {}, built=False, reach=0) == 5 + rank.UNBUILT - 2.0
    assert rank.score(4, {}, built=None, reach=3) == 5.5


def test_units_carry_signals():
    src = b"int z_vrfy_x(int *p) { K_OOPS(K_SYSCALL_MEMORY_READ(p, 4)); }\n"
    units = extract_source("a.c", src,
                           "a", 4)
    fn = [u for u in units if u.kind == "function"][0]
    assert json.loads(fn.signals) == {"syscall": 3, "handler": 1}  # name included


def test_rank_brief_record_rescore(cfg, indexed):  # noqa: F811
    p, conn, snap, _sha, _tree = indexed
    b = rank.write_brief(conn, cfg, p, snap, max_functions=3)
    assert [f["path"] for f in b["files"]] == ["src/parser.c"]
    keys = [fn["key"] for fn in b["files"][0]["functions"]]
    assert keys == ["src/parser.c::check_len", "src/parser.c::parse", "src/parser.c::parse@2"]
    # Its functions are leased: the next brief takes the next file.
    b2 = rank.write_brief(conn, cfg, p, snap)
    assert [f["path"] for f in b2["files"]] == ["src/util.c"]
    res = {"brief_id": b["brief_id"], "model": "m", "units": [
        {"key": k, "reach": r, "attacker": "A1" if r else None, "reason": "x"}
        for k, r in zip(keys, (0, 3, 3), strict=True)]}
    with open(b["result_path"], "w") as f:
        json.dump({**res, "units": res["units"][:2]}, f)
    with pytest.raises(rank.RankError, match="no judgement"):
        rank.record(conn, cfg, b["brief_id"])
    with open(b["result_path"], "w") as f:
        json.dump(res, f)
    assert rank.record(conn, cfg, b["brief_id"]) == 3
    scores = dict(conn.execute(
        "SELECT u.key, uv.score FROM unit_versions uv JOIN units u ON u.id = uv.unit_id "
        "WHERE uv.snapshot_id = ? AND u.kind = 'function'", (snap,)).fetchall())
    assert scores["src/parser.c::check_len"] == 5 - 2.0
    assert scores["src/parser.c::parse"] == pytest.approx(5 + 0.2 + 1.5)
    assert rank.unranked(conn, snap)[0]["key"] == "src/util.c::helper"
    # The recorded brief is timed for `sdive todo`.
    from security_dive import ledger
    assert conn.execute("SELECT functions FROM rank_briefs").fetchone()[0] == 3
    assert ledger.run_minutes([conn], p.name)["rank"][1] == 1


def test_batches_whole_files():
    rows = [{"path": p} for p in ["a", "a", "b", "c", "c", "c", "d"]]
    out = [[(path, len(fns)) for path, fns in b] for b in rank.batches(rows, 3)]
    # A file never splits; one larger than the limit gets a brief of its own.
    assert out == [[("a", 2), ("b", 1)], [("c", 3)], [("d", 1)]]
    assert [[p for p, _ in b] for b in rank.batches(rows, 2)] == [["a"], ["b"], ["c"], ["d"]]
