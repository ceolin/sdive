import json
import textwrap

from security_dive import build, ledger, rank
from security_dive.kconfig import file_conditions

from .test_flow import indexed  # noqa: F401  (fixture)


def test_scenarios_pick_usable_platforms(tmp_path):
    suite = tmp_path / "tests" / "drivers" / "build_all" / "uart"
    suite.mkdir(parents=True)
    (suite / "tests.yaml").write_text(textwrap.dedent("""\
        common:
          build_only: true
          integration_platforms: [native_sim, frdm_k64f]
        tests:
          drivers.uart.build:
            extra_configs: [CONFIG_SERIAL=y, "arch:arm:CONFIG_X=y"]
            extra_args: DTC_OVERLAY_FILE="a.overlay"
          drivers.uart.native_only:
            integration_platforms: []
            platform_allow: [native_sim, native_sim/native/64]
          drivers.uart.default:
            integration_platforms: []
            extra_conf_files: [a.conf, b.conf]
          drivers.uart.skipped:
            skip: true
        """))
    defs = {d.name: d for d in build.scenarios(tmp_path, "tests/drivers/build_all", "qemu_x86")}
    assert set(defs) == {"drivers.uart.build", "drivers.uart.default",
                         "drivers.uart.native_only"}
    assert defs["drivers.uart.native_only"].board == "qemu_x86"
    b = defs["drivers.uart.build"]
    assert (b.board, b.app) == ("frdm_k64f", "tests/drivers/build_all/uart")
    assert b.args == ["-DDTC_OVERLAY_FILE=a.overlay", "-DCONFIG_SERIAL=y"]
    assert defs["drivers.uart.default"].board == "qemu_x86"
    assert defs["drivers.uart.default"].args == ["-DEXTRA_CONF_FILE=a.conf;b.conf"]


def test_compiled_files(tmp_path):
    tree = tmp_path / "ws" / "zephyr"
    bdir = tmp_path / "b"
    bdir.mkdir()
    (bdir / "compile_commands.json").write_text(json.dumps([
        {"directory": str(bdir), "file": str(tree / "subsys/net/ip/tcp.c")},
        {"directory": str(tree / "kernel"), "file": "sched.c"},
        {"directory": str(bdir), "file": str(tmp_path / "ws/modules/hal/x.c")},
        {"directory": str(bdir), "file": str(bdir / "zephyr/misc/generated.c")},
    ]))
    tree.mkdir(parents=True)
    assert build.compiled_files(bdir, tree) == ["kernel/sched.c", "subsys/net/ip/tcp.c"]


def test_recorded_builds_demote_unbuilt_c_files(cfg, indexed):  # noqa: F811
    p, conn, snap, _sha, _tree = indexed
    def score(key):
        return conn.execute("SELECT uv.score FROM unit_versions uv JOIN units u ON "
                            "u.id = uv.unit_id WHERE uv.snapshot_id = ? AND u.key = ?",
                            (snap, key)).fetchone()[0]
    before = score("src/util.c::helper")
    d = build.BuildDef("b1", "board", "app")
    build.record(conn, snap, build.Outcome(d, False, [], "boom"))
    rank.rescore(conn, snap)
    assert score("src/util.c::helper") == before          # a failed build proves nothing
    build.record(conn, snap, build.Outcome(d, True, ["src/parser.c"], ""))
    rank.rescore(conn, snap)
    assert score("src/util.c::helper") == before + rank.UNBUILT
    assert score("src/parser.c::parse") > score("src/util.c::helper")
    assert conn.execute("SELECT count(*) FROM builds").fetchone()[0] == 1   # replaced


def test_kconfig_file_conditions(tmp_path):
    (tmp_path / "CMakeLists.txt").write_text(
        "add_subdirectory(subsys)\nadd_subdirectory_ifdef(CONFIG_FOO drivers/foo)\n")
    (tmp_path / "subsys").mkdir()
    (tmp_path / "subsys" / "CMakeLists.txt").write_text(textwrap.dedent("""\
        # a comment (CONFIG_IGNORED)
        zephyr_library_sources(core.c)
        if(CONFIG_NET)
          zephyr_library_sources_ifdef(CONFIG_TCP tcp.c
                                       tcp_extra.c)
        else()
          zephyr_library_sources(stub.c ${GEN}/gen.c)
        endif()
        """))
    (tmp_path / "drivers" / "foo").mkdir(parents=True)
    (tmp_path / "drivers" / "foo" / "CMakeLists.txt").write_text(
        "zephyr_library_sources_ifdef(CONFIG_FOO_BAR ../foo/bar.c)\n")
    (tmp_path / "lost").mkdir()
    (tmp_path / "lost" / "CMakeLists.txt").write_text("zephyr_sources_ifdef(CONFIG_L l.c)\n")
    m = file_conditions(tmp_path)
    assert m["subsys/core.c"] == []
    assert m["subsys/tcp.c"] == m["subsys/tcp_extra.c"] == ["CONFIG_NET", "CONFIG_TCP"]
    assert m["subsys/stub.c"] == ["NOT (CONFIG_NET)"]
    assert "subsys/gen.c" not in m
    assert m["drivers/foo/bar.c"] == ["CONFIG_FOO", "CONFIG_FOO_BAR"]
    assert m["lost/l.c"] == ["(directory inclusion not traced)", "CONFIG_L"]


def test_briefs_carry_enabled_by(cfg, indexed):  # noqa: F811
    from security_dive.units import extract_tree
    p, conn, snap, _sha, tree = indexed
    ledger.index_units(conn, p.name, snap, extract_tree(p, tree),
                       {"src/parser.c": ["CONFIG_PARSER"], "elsewhere.c": ["CONFIG_X"]})
    run = ledger.next_unit_run(conn, p, snap, "dive", "memory")
    b = ledger.brief(conn, cfg, run)
    assert b["enabled_by"] == {"src/parser.c": ["CONFIG_PARSER"]}
    assert "Kconfig" in b["enabled_by_note"]
