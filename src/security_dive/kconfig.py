"""Static file -> Kconfig map from a Zephyr tree's CMakeLists.txt files.

For each source file, the conditions under which the build system compiles
it: `*_sources_ifdef(CONFIG_X ...)`, `add_subdirectory_ifdef(CONFIG_X dir)`,
and enclosing `if(...)` blocks, accumulated along the `add_subdirectory`
chain from the tree's root. It is an approximation (variables, globs,
generator expressions and Kconfig `depends on` are not followed); briefs carry
it so agents can say what enables the code they examine, and verify it in
Kconfig when it matters.
"""

from __future__ import annotations

import re
from pathlib import Path

_COMMAND = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.S)
_SOURCES = re.compile(r"^(?:zephyr_library_sources|zephyr_sources|target_sources|kernel_sources"
                      r"|zephyr_library_sources_ifndef)$")
_SOURCES_IFDEF = re.compile(r"^(?:zephyr_library_sources_ifdef|zephyr_sources_ifdef"
                            r"|target_sources_ifdef|kernel_sources_ifdef)$")
_SOURCE_EXT = (".c", ".S", ".s", ".cpp")


def _strip_comments(text: str) -> str:
    out = []
    for line in text.splitlines():
        i = line.find("#")
        while i != -1 and line[:i].count('"') % 2 == 1:   # '#' inside a string
            i = line.find("#", i + 1)
        out.append(line if i == -1 else line[:i])
    return "\n".join(out)


def _commands(text: str):
    """(name, argument string) for each top-level command, in order."""
    text = _strip_comments(text)
    pos = 0
    while (m := _COMMAND.search(text, pos)):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += {"(": 1, ")": -1}.get(text[i], 0)
            i += 1
        yield m.group(1).lower(), text[m.end():i - 1].strip()
        pos = i


def _cond(args: str) -> str:
    return " ".join(args.split())


def _parse(cm: Path, rel_dir: str) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Files compiled and subdirectories added by one CMakeLists.txt, each with
    the local conditions that guard it. Paths are relative to the tree root."""
    files: dict[str, list[str]] = {}
    subdirs: dict[str, list[str]] = {}
    stack: list[list[str]] = []   # per open if(): conditions of the current branch

    def where(name: str) -> str | None:
        if "${" in name or "$<" in name or "*" in name:
            return None
        p = Path(rel_dir, name) if rel_dir else Path(name)
        parts: list[str] = []
        for part in p.parts:
            if part == "..":
                if not parts:
                    return None
                parts.pop()
            elif part != ".":
                parts.append(part)
        return "/".join(parts)

    def active() -> list[str]:
        return [c for frame in stack for c in frame]

    for name, args in _commands(cm.read_text(errors="replace")):
        if name == "if":
            stack.append([_cond(args)])
        elif name == "elseif" and stack:
            prev = stack[-1]
            stack[-1] = [f"NOT ({c})" for c in prev[-1:]] + [_cond(args)]
        elif name == "else" and stack:
            stack[-1] = [f"NOT ({c})" for c in stack[-1][-1:]]
        elif name == "endif" and stack:
            stack.pop()
        elif _SOURCES.match(name) or _SOURCES_IFDEF.match(name):
            toks = args.split()
            conds = active()
            if _SOURCES_IFDEF.match(name):
                if not toks:
                    continue
                conds = [*conds, toks[0]]
                toks = toks[1:]
            if name == "target_sources" or name == "target_sources_ifdef":
                toks = [t for t in toks[1:] if t not in ("PRIVATE", "PUBLIC", "INTERFACE")]
            if name == "zephyr_library_sources_ifndef" and toks:
                conds = [*active(), f"NOT {toks[0]}"]
                toks = toks[1:]
            for t in toks:
                t = t.strip('"')
                if t.endswith(_SOURCE_EXT) and (p := where(t)):
                    files.setdefault(p, conds)
        elif name in ("add_subdirectory", "add_subdirectory_ifdef"):
            toks = args.split()
            conds = active()
            if name == "add_subdirectory_ifdef":
                if len(toks) < 2:
                    continue
                conds = [*conds, toks[0]]
                toks = toks[1:]
            if toks and (p := where(toks[0].strip('"'))):
                subdirs.setdefault(p, conds)
    return files, subdirs


def file_conditions(tree: Path) -> dict[str, list[str]]:
    """Source path -> conditions (ANDed), following add_subdirectory from the
    root CMakeLists.txt; CMakeLists not reached that way contribute their
    local conditions only."""
    out: dict[str, list[str]] = {}
    seen: set[str] = set()
    queue: list[tuple[str, list[str]]] = [("", [])]
    while queue:
        rel, inherited = queue.pop(0)
        if rel in seen:
            continue
        seen.add(rel)
        cm = tree / rel / "CMakeLists.txt" if rel else tree / "CMakeLists.txt"
        if not cm.is_file():
            continue
        files, subdirs = _parse(cm, rel)
        for f, conds in files.items():
            out.setdefault(f, _tidy(inherited + conds))
        for d, conds in subdirs.items():
            queue.append((d, inherited + conds))
    for cm in sorted(tree.rglob("CMakeLists.txt")):
        rel = cm.parent.relative_to(tree).as_posix()
        rel = "" if rel == "." else rel
        if rel in seen or "/tests/" in f"/{rel}/" or "/samples/" in f"/{rel}/":
            continue
        files, _ = _parse(cm, rel)
        for f, conds in files.items():
            out.setdefault(f, ["(directory inclusion not traced)", *_tidy(conds)])
    return out


def _tidy(conds: list[str]) -> list[str]:
    """Kconfig conditions only, each once, in order."""
    return list(dict.fromkeys(c for c in conds if "CONFIG_" in c))
