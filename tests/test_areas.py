import textwrap

from security_dive import areas
from security_dive.config import Area, load_config
from security_dive.ledger import _batch

MAINTAINERS = textwrap.dedent("""\
    # comment
    Networking:
      status: maintained
      files:
        - subsys/net/
        - include/zephyr/net/
      files-exclude:
        - subsys/net/lib/lwm2m/
    "Networking: LwM2M":
      status: maintained
      files:
        - subsys/net/lib/lwm2m/
    Vendor Platforms:
      files:
        - soc/vendor/
      files-regex:
        - ^drivers/.*vendor
    GPIO Drivers:
      files:
        - drivers/gpio/
        - drivers/gpio/gpio_vendor.c
    """)


def test_from_maintainers_translates_entries():
    got = {a["name"]: a for a in areas.from_maintainers(MAINTAINERS)}
    assert list(got) == ["networking", "networking-lwm2m", "vendor-platforms", "gpio-drivers"]
    assert got["networking"]["globs"] == ["subsys/net/**", "include/zephyr/net/**"]
    assert got["networking"]["exclude"] == ["subsys/net/lib/lwm2m/**"]
    assert got["vendor-platforms"]["regexes"] == ["^drivers/.*vendor"]
    assert got["networking"]["description"] == "Networking (maintained)"


def test_specificity_picks_most_specific_area(tmp_path):
    (tmp_path / "projects" / "z").mkdir(parents=True)
    (tmp_path / "config.toml").write_text(
        '[projects.z]\ngithub = "a/z"\nupstream = "x"\n')
    (tmp_path / "projects" / "z" / "project.toml").write_text(textwrap.dedent("""\
        [scope]
        include = ["**"]
        [areas_source]
        file = "areas.toml"
        default_priority = 2
        [[priority]]
        priority = 5
        areas = ["networking*"]
        [[areas]]
        name = "hand"
        priority = 3
        globs = ["subsys/net/ip/tcp.c"]
        """))
    from security_dive.config import load_config as lc
    p = lc(tmp_path / "config.toml").project("z")
    (tmp_path / "projects" / "z" / "areas.toml").write_text(
        areas.render(p, "0" * 40, "MAINTAINERS.yml", areas.from_maintainers(MAINTAINERS)))
    p = load_config(tmp_path / "config.toml").project("z")
    assert p.area_for("subsys/net/ip/tcp.c").name == "hand"           # hand-written first
    assert p.area_for("subsys/net/ip/ipv6.c").name == "networking"
    assert p.area_for("subsys/net/lib/lwm2m/x.c").name == "networking-lwm2m"
    assert p.area_for("drivers/gpio/gpio_other.c").name == "gpio-drivers"
    assert p.area_for("drivers/gpio/gpio_vendor.c").name == "gpio-drivers"   # exact file
    assert p.area_for("drivers/spi/spi_vendor.c").name == "vendor-platforms"  # regex only
    assert p.area_for("lib/x.c").name == "unassigned"
    assert p.area_named("networking-lwm2m").priority == 5
    assert p.area_named("gpio-drivers").priority == 2


def test_area_regex_excludes():
    a = Area("a", 1, globs=("drivers/**",), regex_exclude=(r"_emul\.c$",))
    assert a.matches("drivers/x.c") and not a.matches("drivers/x_emul.c")


def test_oversized_area_sweeps_file_by_file():
    def row(path, start, end, area="big"):
        return {"path": path, "start_line": start, "end_line": end, "area": area}
    rows = [row("a.c", 1, 50), row("a.c", 60, 100), row("b.c", 1, 80), row("c.c", 1, 10)]
    assert [r["path"] for r in _batch(rows, "sweep", 40, 100)] == ["a.c", "a.c"]
    assert [r["path"] for r in _batch(rows, "sweep", 40, 10)] == ["a.c", "a.c"]
    assert len(_batch(rows, "sweep", 40, 1000)) == 4


def test_west_reference_exported(tmp_path, library):
    from security_dive import repo
    from security_dive.config import load_config

    from .conftest import commit, git
    lib_sha = git(library, "rev-parse", "HEAD")
    up = tmp_path / "zup"
    (up / "src").mkdir(parents=True)
    (up / "src" / "a.c").write_text("int a(void) { return 0; }\n")
    (up / "west.yml").write_text(textwrap.dedent(f"""\
        manifest:
          remotes:
            - name: upstream
              url-base: https://example.invalid
          projects:
            - name: lib
              url: {library}
              revision: {lib_sha}
              path: modules/lib/lib
            - name: other
              remote: upstream
              revision: main
        """))
    git(up, "init", "-q", "-b", "main")
    sha = commit(up)
    root = tmp_path / "r"
    (root / "projects" / "z").mkdir(parents=True)
    (root / "config.toml").write_text(
        f'[projects.z]\ngithub = "a/z"\nupstream = "{up}"\n')
    (root / "projects" / "z" / "project.toml").write_text(textwrap.dedent("""\
        [scope]
        include = ["**"]
        [[reference]]
        west = "lib"
        role = "A library"
        export = ["include"]
        [[reference]]
        west = "missing"
        """))
    cfg = load_config(root / "config.toml")
    p = cfg.project("z")
    assert p.is_reference("_west/lib/include/lib.h") and not p.in_scope("_west/lib/include/lib.h")
    wp = repo.west_projects(repo.ensure_mirror(cfg, p), sha)
    assert wp["other"].url == "https://example.invalid/other"
    assert wp["lib"].path == "modules/lib/lib"
    tree = repo.snapshot(cfg, p, sha)
    marker = repo.read_marker(tree)
    assert [(r["path"], r["sha"]) for r in marker["references"]] == [("_west/lib", lib_sha)]
    assert marker["absent_references"] == ["_west/missing"]
    assert (tree / "_west/lib/include/lib.h").is_file()
    assert not (tree / "_west/lib/library").exists()
