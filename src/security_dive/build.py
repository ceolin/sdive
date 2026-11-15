"""`sdive build`: which source files some legitimate configuration compiles.

Zephyr has no allyesconfig, so the answer is the union of many builds. Each
build is only *configured* (CMake, devicetree, Kconfig), never compiled:
Zephyr writes `compile_commands.json` at configure time, which lists every
source the build would compile, in about eight seconds per build.

Builds come from `projects/<p>/builds.toml`: hand-written wide builds
(`[[build]]`: board, app, extra conf files and CMake args) and **suites**
(`[[suite]]`: a directory whose `testcase.yaml` / `sample.yaml` /
`tests.yaml` scenarios are each configured on their first usable platform,
e.g. Zephyr's `tests/drivers/build_all`). They run in a west workspace under
`work/west/<p>/` (the project checked out from the private mirror at the
snapshot commit, modules at its `west.yml` revisions, cloned with the user's
workspace as `--path-cache` only), with the Python environment and SDK named
in config.toml. Results go to the ledger (`builds`, `file_builds`) and feed
the queue score: code no recorded build compiles sinks.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tomllib
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import repo
from .config import Config, ConfigError, Project

NATIVE = ("native_", "nrf52_bsim", "nrf5340bsim", "nrf54l15bsim", "unit_testing", "qemu_kvm")
SCENARIO_FILES = ("testcase.yaml", "sample.yaml", "tests.yaml")


class BuildError(Exception):
    pass


@dataclass(frozen=True)
class BuildEnv:
    python_bin: Path        # directory holding `west` and the Python build deps
    sdk: Path               # Zephyr SDK install dir
    module_cache: Path | None  # an existing west workspace, used as --path-cache only
    default_board: str = "qemu_cortex_m3"


@dataclass
class BuildDef:
    name: str
    board: str
    app: str                       # app directory, relative to the project tree
    args: list[str] = field(default_factory=list)   # extra CMake -D arguments
    source: str = "builds.toml"

    def as_config(self) -> str:
        return json.dumps({"app": self.app, "args": self.args, "source": self.source})


def build_env(cfg: Config, project: Project) -> BuildEnv:
    raw = cfg.build_settings.get(project.name)
    if not raw:
        raise ConfigError(f"no [projects.{project.name}.build] in config.toml "
                          "(python_bin, sdk, module_cache)")
    def path(key: str, required: bool = True) -> Path | None:
        v = raw.get(key)
        if not v:
            if required:
                raise ConfigError(f"projects.{project.name}.build: missing {key!r}")
            return None
        return Path(v).expanduser()
    return BuildEnv(path("python_bin"), path("sdk"), path("module_cache", False),
                    raw.get("default_board", "qemu_cortex_m3"))


# --- build definitions -------------------------------------------------------


def _usable(platform: str) -> bool:
    return not platform.startswith(NATIVE) and "bsim" not in platform


def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return v.split()
    return [str(x) for x in v]


def scenarios(tree: Path, suite: str, default_board: str) -> list[BuildDef]:
    """One BuildDef per scenario in the suite directory's scenario files.

    The board is the first usable entry of `integration_platforms`, then
    `platform_allow`, else `default_board`, which also stands in when every
    listed platform is a native/simulation host (Linux-only): many network
    and Bluetooth suites test only on native_sim, and their code should not
    count as unbuilt for that.
    Twister `filter` expressions are ignored; a scenario whose configuration
    fails is recorded as failed.
    """
    out = []
    root = tree / suite
    if not root.is_dir():
        raise BuildError(f"suite {suite!r} is not a directory at this snapshot")
    for f in sorted(p for name in SCENARIO_FILES for p in root.rglob(name)):
        try:
            data = yaml.safe_load(f.read_text()) or {}
        except yaml.YAMLError:
            continue
        common = data.get("common", {}) or {}
        app = f.parent.relative_to(tree).as_posix()
        for sname, sc in (data.get("tests", {}) or {}).items():
            sc = {**common, **(sc or {})}
            if sc.get("skip"):
                continue
            plats = (_as_list(sc.get("integration_platforms"))
                     + _as_list(sc.get("platform_allow")))
            usable = [p for p in plats if _usable(p)]
            board = usable[0] if usable else default_board
            args = [f"-D{a}" for a in _as_list(sc.get("extra_args")) if "=" in a]
            args += [f"-D{c}" for c in _as_list(sc.get("extra_configs"))
                     if c.startswith("CONFIG_")]
            for key, var in (("extra_conf_files", "EXTRA_CONF_FILE"),
                             ("extra_overlay_confs", "EXTRA_CONF_FILE"),
                             ("extra_dtc_overlay_files", "EXTRA_DTC_OVERLAY_FILE")):
                files = _as_list(sc.get(key))
                if files:
                    args.append(f"-D{var}={';'.join(files)}")
            out.append(BuildDef(sname, board, app, args, f"suite:{suite}"))
    return out


def load_defs(project: Project, tree: Path, env: BuildEnv) -> list[BuildDef]:
    path = project.defdir / "builds.toml"
    if not path.is_file():
        raise ConfigError(f"no {path}")
    spec = tomllib.loads(path.read_text())
    defs = []
    for b in spec.get("build", []):
        args = list(b.get("args", []))
        conf = [str((project.defdir / "builds" / c).resolve()) for c in b.get("conf", [])]
        if conf:
            args.append(f"-DEXTRA_CONF_FILE={';'.join(conf)}")
        overlays = [str((project.defdir / "builds" / o).resolve())
                    for o in b.get("overlays", [])]
        if overlays:
            args.append(f"-DEXTRA_DTC_OVERLAY_FILE={';'.join(overlays)}")
        defs.append(BuildDef(b["name"], b["board"], b["app"], args))
    for s in spec.get("suite", []):
        defs += scenarios(tree, s["path"], s.get("board", env.default_board))
    names = [d.name for d in defs]
    dups = sorted({n for n in names if names.count(n) > 1})
    if dups:
        # Scenario names are meant to be unique; disambiguate by app if not.
        for d in defs:
            if d.name in dups:
                d.name = f"{d.name}@{d.app}"
    return defs


# --- the workspace -----------------------------------------------------------


def _run(cmd: list[str], cwd: Path, env: dict, timeout: int = 900) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True,
                          timeout=timeout)


def _env(benv: BuildEnv) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in ("ZEPHYR_BASE", "VIRTUAL_ENV")}
    env.update(PATH=f"{benv.python_bin}:{env.get('PATH', '')}",
               ZEPHYR_SDK_INSTALL_DIR=str(benv.sdk),
               PYTHONDONTWRITEBYTECODE="1")   # never write into the user's venv
    return env


def workspace(cfg: Config, project: Project) -> Path:
    return cfg.work / "west" / project.name


def ensure_workspace(cfg: Config, project: Project, sha: str, benv: BuildEnv,
                     log: Callable[[str], None] = lambda s: None) -> Path:
    """The west workspace with the project at `sha` and its modules updated
    to that commit's west.yml. Returns the project's tree in it."""
    ws = workspace(cfg, project)
    tree = ws / project.name
    env = _env(benv)
    mirror = cfg.mirror_path(project.name)
    if not (tree / ".git").exists():
        ws.mkdir(parents=True, exist_ok=True)
        log(f"creating worktree {tree}")
        repo.git("-C", mirror, "worktree", "prune")
        repo.git("-C", mirror, "worktree", "add", "--detach", tree, sha)
    head = repo.git("-C", tree, "rev-parse", "HEAD")
    if head != sha:
        log(f"checking out {sha[:12]}")
        repo.git("-C", tree, "checkout", "--quiet", "--detach", sha)
    if not (ws / ".west").is_dir():
        r = _run(["west", "init", "-l", project.name], ws, env)
        if r.returncode:
            raise BuildError(f"west init failed: {r.stderr.strip()[-2000:]}")
    stamp = ws / ".sdive-west-yml"
    west_yml = repo.git("-C", tree, "rev-parse", "HEAD:west.yml")
    if not stamp.is_file() or stamp.read_text().strip() != west_yml:
        log("west update (modules at this commit's west.yml)")
        cmd = ["west", "update"]
        if benv.module_cache is not None:
            cmd += ["--path-cache", str(benv.module_cache)]
        r = _run(cmd, ws, env, timeout=3600)
        if r.returncode:
            raise BuildError(f"west update failed: {r.stderr.strip()[-2000:]}")
        stamp.write_text(west_yml + "\n")
    return tree


# --- running -----------------------------------------------------------------


@dataclass
class Outcome:
    build: BuildDef
    ok: bool
    files: list[str]
    log: str


def compiled_files(build_dir: Path, tree: Path) -> list[str]:
    """Project-relative paths of the sources a configured build compiles."""
    cc = build_dir / "compile_commands.json"
    if not cc.is_file():
        return []
    root = str(tree.resolve()) + os.sep
    out = set()
    for entry in json.loads(cc.read_text()):
        f = entry.get("file", "")
        if not os.path.isabs(f):
            f = os.path.join(entry.get("directory", ""), f)
        f = os.path.normpath(f)
        if f.startswith(root):
            out.add(f[len(root):].replace(os.sep, "/"))
    return sorted(out)


def configure(tree: Path, d: BuildDef, out_root: Path, benv: BuildEnv,
              keep: bool = False) -> Outcome:
    # ZEPHYR_BASE pinned to our tree: otherwise CMake's package registry could
    # resolve to the user's own registered checkout.
    bdir = out_root / d.name.replace("/", "_").replace("@", "_at_")
    if bdir.exists():
        shutil.rmtree(bdir)
    cmd = ["west", "build", "-p", "always", "-b", d.board, "-d", str(bdir),
           str(tree / d.app), "--cmake-only", "--", *d.args]
    try:
        r = _run(cmd, tree.parent, {**_env(benv), "ZEPHYR_BASE": str(tree)})
        ok = r.returncode == 0
        text = (r.stdout + r.stderr)
    except subprocess.TimeoutExpired:
        ok, text = False, "timed out"
    files = compiled_files(bdir, tree) if ok else []
    if not keep:
        shutil.rmtree(bdir, ignore_errors=True)
    return Outcome(d, ok and bool(files), files, text[-4000:])


def run_all(tree: Path, defs: list[BuildDef], out_root: Path, benv: BuildEnv, jobs: int,
            on_done: Callable[[Outcome], None], keep: bool = False) -> None:
    out_root.mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = [pool.submit(configure, tree, d, out_root, benv, keep) for d in defs]
        for fut in as_completed(futures):
            on_done(fut.result())


def record(conn, snap: int, o: Outcome) -> None:
    """Store one build's outcome (replacing an earlier one of the same name)."""
    from .ledger import now

    with conn:
        old = conn.execute("SELECT id FROM builds WHERE snapshot_id = ? AND name = ?",
                           (snap, o.build.name)).fetchone()
        if old:
            conn.execute("DELETE FROM file_builds WHERE build_id = ?", (old[0],))
            conn.execute("DELETE FROM builds WHERE id = ?", (old[0],))
        bid = conn.execute(
            "INSERT INTO builds (snapshot_id, name, board, config, status, files, log, built_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
            (snap, o.build.name, o.build.board, o.build.as_config(), "ok" if o.ok else "failed",
             len(o.files), None if o.ok else o.log, now())).fetchone()[0]
        conn.executemany("INSERT INTO file_builds (snapshot_id, path, build_id) VALUES (?, ?, ?)",
                         [(snap, f, bid) for f in o.files])
