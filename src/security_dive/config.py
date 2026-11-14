"""Configuration: `config.toml` at the repo root plus `projects/<name>/project.toml`."""

from __future__ import annotations

import dataclasses
import functools
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

CONFIG_NAME = "config.toml"
SOURCE_EXTS = (".c", ".h")


class ConfigError(Exception):
    pass


@functools.cache
def _glob_re(pattern: str) -> re.Pattern[str]:
    """Translate a path glob to a regex. `**` spans directories, `*` does not."""
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        elif pattern[i] == "[" and (j := pattern.find("]", i + 2)) != -1:
            body = pattern[i + 1 : j]
            if body.startswith("!"):
                body = "^" + body[1:]
            out.append("[" + body.replace("\\", "\\\\") + "]")
            i = j + 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def glob_match(pattern: str, path: str) -> bool:
    return _glob_re(pattern).match(path) is not None


@dataclass(frozen=True)
class Area:
    name: str
    priority: int
    globs: tuple[str, ...] = ()
    description: str = ""
    exclude: tuple[str, ...] = ()       # globs
    regexes: tuple[str, ...] = ()       # re.search anywhere in the path
    regex_exclude: tuple[str, ...] = ()
    generated: bool = False             # from areas_source (e.g. MAINTAINERS.yml)
    split: str | None = None            # subdivides this generated area (see area_for)

    def matches(self, path: str) -> bool:
        return self.specificity(path) is not None

    def specificity(self, path: str) -> int | None:
        """How specifically this area claims `path` (None: not at all).

        The longest literal prefix of a matching pattern, so `subsys/net/lib/`
        beats `subsys/net/`; an exact file path beats any directory. Used to
        pick one area among overlapping generated ones.
        """
        if any(glob_match(g, path) for g in self.exclude) or any(
                re.search(r, path) for r in self.regex_exclude):
            return None
        best = None
        for g in self.globs:
            if glob_match(g, path):
                n = _literal_prefix(g) + (10_000 if g == path else 0)
                best = n if best is None else max(best, n)
        for r in self.regexes:
            if re.search(r, path):
                n = _literal_prefix(r[1:], regex=True) if r.startswith("^") else 0
                best = n if best is None else max(best, n)
        return best


@functools.cache
def _literal_prefix(pattern: str, regex: bool = False) -> int:
    meta = "*?[" if not regex else ".*+?[](){}|\\^$"
    for i, ch in enumerate(pattern):
        if ch in meta:
            return i
    return len(pattern)


@dataclass(frozen=True)
class Reference:
    """A submodule exported into snapshots for agents to *consult* (API
    contracts), never indexed, covered, or the location of a finding."""

    path: str  # relative to the parent tree (the project, or the parent reference)
    role: str = ""
    export: tuple[str, ...] = ()  # subpaths to export; empty = the whole tree
    nested: tuple[Reference, ...] = ()
    # A west.yml project (Zephyr modules) instead of a submodule: exported to
    # WEST_DIR/<name> at the revision the snapshot's west.yml pins.
    west: str | None = None

    def as_dict(self) -> dict:
        d = {
            "path": self.path,
            "export": list(self.export),
            "nested": [n.as_dict() for n in self.nested],
        }
        if self.west:
            d["west"] = self.west
        return d


WEST_DIR = "_west"   # where west-project references go inside a snapshot


def _flat_reference_paths(refs: tuple[Reference, ...], prefix: str = "") -> list[str]:
    out = []
    for r in refs:
        out.append(prefix + r.path)
        out.extend(_flat_reference_paths(r.nested, prefix + r.path + "/"))
    return out


@dataclass(frozen=True)
class Project:
    name: str
    github: str
    upstream: str
    reference_repo: Path | None
    default_branch: str
    threat_model: Path | None
    defdir: Path
    include: tuple[str, ...]
    exclude: tuple[str, ...]
    areas: tuple[Area, ...]
    default_area: Area
    references: tuple[Reference, ...] = ()
    sweep_order: tuple[str, ...] = ()   # lens order for `sdive run` auto
    # Areas from a generated file (areas_source): matched after the
    # hand-written `areas`, the most specific claim winning.
    generated_areas: tuple[Area, ...] = ()
    areas_source: Path | None = None
    _area_cache: dict = dataclasses.field(default_factory=dict, compare=False, hash=False,
                                          repr=False)

    @property
    def lenses_dir(self) -> Path:
        return self.defdir / "lenses"

    @property
    def reference_paths(self) -> list[str]:
        return _flat_reference_paths(self.references)

    def is_reference(self, path: str) -> bool:
        return any(path == r or path.startswith(r + "/") for r in self.reference_paths)

    def in_scope(self, path: str) -> bool:
        if not path.endswith(SOURCE_EXTS) or self.is_reference(path):
            return False
        if not any(glob_match(g, path) for g in self.include):
            return False
        return not any(glob_match(g, path) for g in self.exclude)

    @property
    def all_areas(self) -> tuple[Area, ...]:
        return (*self.areas, *self.generated_areas)

    def area_for(self, path: str) -> Area:
        """Hand-written areas in order (first wins), then the generated area
        with the most specific claim (ties: first in file order), refined by
        the first hand-written area that `split`s it and matches."""
        hit = self._area_cache.get(path)
        if hit is not None:
            return hit
        hit = next((a for a in self.areas if a.split is None and a.matches(path)), None)
        if hit is None:
            best = None
            for area in self._candidates(path):
                n = area.specificity(path)
                if n is not None and (best is None or n > best):
                    best, hit = n, area
            if hit is not None:
                hit = next((a for a in self.areas if a.split == hit.name and a.matches(path)),
                           hit)
        hit = hit or self.default_area
        self._area_cache[path] = hit
        return hit

    def _candidates(self, path: str) -> list[Area]:
        """Generated areas that could claim `path`, in file order: those with
        a pattern whose literal prefix shares `path`'s first component (or
        has none, or is a regex)."""
        index = self._area_cache.get(None)
        if index is None:
            index = {}
            for i, area in enumerate(self.generated_areas):
                heads = {g[:_literal_prefix(g)].split("/", 1)[0] if "/" in g[:_literal_prefix(g)]
                         else "" for g in area.globs}
                if area.regexes:
                    heads.add("")
                for h in heads:
                    index.setdefault(h, []).append((i, area))
            self._area_cache[None] = index
        head = path.split("/", 1)[0]
        hits = index.get(head, []) + index.get("", [])
        return list(dict.fromkeys(a for _i, a in sorted(hits, key=lambda t: t[0])))

    def area_named(self, name: str) -> Area:
        for area in (*self.all_areas, self.default_area):
            if area.name == name:
                return area
        raise ConfigError(f"project {self.name}: unknown area {name!r}")


MAIN_LEDGER = "main"


@dataclass(frozen=True)
class Config:
    root: Path
    analysis: Path
    work: Path
    projects: dict[str, Project]
    # A ledger is an independent DB + dossiers + run records. "main" is the real
    # one (at the top of analysis/); others (e.g. benchmark rounds) live under
    # analysis/ledgers/<name>/ and can be thrown away.
    ledger: str = MAIN_LEDGER

    def project(self, name: str) -> Project:
        try:
            return self.projects[name]
        except KeyError:
            known = ", ".join(sorted(self.projects)) or "none"
            raise ConfigError(f"unknown project {name!r} (configured: {known})") from None

    def with_ledger(self, name: str) -> Config:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
            raise ConfigError(f"invalid ledger name {name!r}")
        return dataclasses.replace(self, ledger=name)

    @property
    def ledger_dir(self) -> Path:
        if self.ledger == MAIN_LEDGER:
            return self.analysis
        return self.analysis / "ledgers" / self.ledger

    @property
    def db_path(self) -> Path:
        return self.ledger_dir / "sdive.db"

    @property
    def staging(self) -> Path:
        return self.ledger_dir / "staging"

    @property
    def truth_dir(self) -> Path:
        """Benchmark ground truth. Must never be readable by analysis agents."""
        return self.analysis / "truth"

    def mirror_path(self, project: str) -> Path:
        return self.work / "mirrors" / f"{project}.git"

    def snapshot_path(self, project: str, sha: str) -> Path:
        return self.work / "snapshots" / project / sha

    def dossier_path(self, project: str, area: str) -> Path:
        return self.ledger_dir / "dossiers" / project / f"{area}.md"

    def export_dir(self, project: str) -> Path:
        """Cluster exports for zepsec (one directory per cluster)."""
        return self.ledger_dir / "exports" / project

    def run_record_path(self, project: str, run_id: int) -> Path:
        return self.ledger_dir / "runs" / project / f"run-{run_id}.json"

    def agent_path(self, name: str) -> Path:
        return self.root / ".claude" / "agents" / f"{name}.md"


def find_config(start: Path | None = None) -> Path:
    here = (start or Path.cwd()).resolve()
    for d in (here, *here.parents):
        if (d / CONFIG_NAME).is_file():
            return d / CONFIG_NAME
    raise ConfigError(f"no {CONFIG_NAME} found in {here} or its parents")


def _path(root: Path, value: str | None) -> Path | None:
    if not value:
        return None
    p = Path(value).expanduser()
    return p if p.is_absolute() else (root / p).resolve()


def _load_reference(raw: dict) -> Reference:
    if "west" in raw:
        if raw.get("nested"):
            raise ConfigError(f"west reference {raw['west']!r}: nested references unsupported")
        return Reference(path=f"{WEST_DIR}/{raw['west']}", role=raw.get("role", ""),
                         export=tuple(p.strip("/") for p in raw.get("export", ())),
                         west=raw["west"])
    return Reference(
        path=raw["path"].strip("/"),
        role=raw.get("role", ""),
        export=tuple(p.strip("/") for p in raw.get("export", ())),
        nested=tuple(_load_reference(n) for n in raw.get("nested", ())),
    )


def _load_area(a: dict, priority: int | None = None, generated: bool = False) -> Area:
    return Area(
        name=a["name"],
        priority=int(priority if priority is not None else a.get("priority", 1)),
        globs=tuple(a.get("globs", ())),
        description=a.get("description", ""),
        exclude=tuple(a.get("exclude", ())),
        regexes=tuple(a.get("regexes", ())),
        regex_exclude=tuple(a.get("regex_exclude", ())),
        generated=generated,
        split=a.get("split"),
    )


def _area_priority(rules: list[dict], name: str, default: int) -> int:
    """Priority from the first `[[priority]]` rule whose `areas` globs match."""
    for rule in rules:
        if any(glob_match(g, name) for g in rule.get("areas", ())):
            return int(rule["priority"])
    return default


def _load_generated(deffile: Path, spec: dict) -> tuple[Path | None, tuple[Area, ...]]:
    src = spec.get("areas_source")
    if not src:
        return None, ()
    path = deffile.parent / src["file"]
    if not path.is_file():
        return path, ()   # not generated yet: `sdive areas <p> --generate`
    gen = tomllib.loads(path.read_text())
    rules = spec.get("priority", [])
    default = int(src.get("default_priority", 1))
    return path, tuple(
        _load_area(a, _area_priority(rules, a["name"], default), generated=True)
        for a in gen.get("areas", ())
    )


def _load_project(root: Path, name: str, raw: dict) -> Project:
    defdir = root / "projects" / name
    deffile = defdir / "project.toml"
    spec = tomllib.loads(deffile.read_text()) if deffile.is_file() else {}
    scope = spec.get("scope", {})
    areas_source, generated = _load_generated(deffile, spec)
    by_name = {g.name: g for g in generated}
    areas = []
    for raw_area in spec.get("areas", ()):
        split = raw_area.get("split")
        if split is not None and generated and split not in by_name:
            raise ConfigError(f"{deffile}: area {raw_area['name']!r} splits unknown area "
                              f"{split!r}")
        # A split area inherits its parent's priority unless it sets one.
        default = by_name[split].priority if split in by_name else 1
        areas.append(_load_area(raw_area, raw_area.get("priority", default)))
    areas = tuple(areas)
    default = scope.get("default_area", {"name": "unassigned", "priority": 0})
    default_area = Area(
        name=default["name"],
        priority=int(default.get("priority", 0)),
        description=default.get("description", ""),
    )
    names = [a.name for a in (*areas, *generated, default_area)]
    if len(names) != len(set(names)):
        dups = sorted({n for n in names if names.count(n) > 1})
        raise ConfigError(f"{deffile}: duplicate area names: {', '.join(dups)}")
    for key in ("github", "upstream"):
        if key not in raw:
            raise ConfigError(f"projects.{name}: missing {key!r}")
    return Project(
        name=name,
        github=raw["github"],
        upstream=raw["upstream"],
        reference_repo=_path(root, raw.get("reference_repo")),
        default_branch=raw.get("default_branch", "main"),
        threat_model=_path(root, raw.get("threat_model")),
        defdir=defdir,
        include=tuple(scope.get("include", ())),
        exclude=tuple(scope.get("exclude", ())),
        areas=areas,
        default_area=default_area,
        references=tuple(_load_reference(r) for r in spec.get("reference", ())),
        sweep_order=tuple(spec.get("runs", {}).get("sweep_order", ())),
        generated_areas=generated,
        areas_source=areas_source,
    )


def load_config(path: Path | None = None) -> Config:
    path = path or find_config()
    root = path.parent.resolve()
    with path.open("rb") as f:
        raw = tomllib.load(f)
    paths = raw.get("paths", {})
    return Config(
        root=root,
        analysis=_path(root, paths.get("analysis", "analysis")),
        work=_path(root, paths.get("work", "work")),
        projects={
            name: _load_project(root, name, p) for name, p in raw.get("projects", {}).items()
        },
    )
