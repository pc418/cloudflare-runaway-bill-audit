"""Source-location context for the reviewing agent (read-only, no source analysis).

`source_context` reuses the loaded wrangler configuration: which config files were read,
which entry / asset paths each Worker view declares and whether they exist on disk, and
the source identity of the scanned tree. A declared path is what the configuration says,
not a verified deployment, and the list is not exhaustive: routes, clients and background
work outside these paths are for the agent to find.

`source_identity` asks git, read-only, for HEAD and whether the work tree has changes. It
never writes to the target (no optional locks, fsmonitor and untracked cache off, no
prompt), reads no global or system git configuration, runs no content filter (status is
skipped when the repository's effective configuration defines one) and never serializes
the diff. Anything it could not read is an explicit unknown (`dirty: null`), never a
clean-tree claim.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .wrangler import Project, WorkerView

GIT_TIMEOUT_S = 20


def _declared_paths(w: WorkerView) -> list[tuple[str, str]]:
    """(kind, declared path) pairs of one Worker view, as the configuration states them."""
    out: list[tuple[str, str]] = []
    main = w.get("main")
    if isinstance(main, str) and main.strip():
        out.append(("main", main))
    assets = w.get("assets")
    if (isinstance(assets, dict) and w.ok("assets.directory") and isinstance(assets.get("directory"), str)
            and assets["directory"].strip()):  # a malformed directory is reported by its config check, not listed
        out.append(("assets", assets["directory"]))
    pages = w.get("pages_build_output_dir")
    if isinstance(pages, str) and pages.strip():
        out.append(("pages_build_output_dir", pages))
    return out


def _rel(root: Path, p: Path) -> str:
    try:
        return p.relative_to(root).as_posix()
    except ValueError:
        return os.path.relpath(p, root)


def _exists(p: Path) -> bool | None:
    """True / False when the filesystem answered, None when it could not be asked."""
    try:
        p.stat()
        return True
    except FileNotFoundError:
        return False
    except (OSError, ValueError):
        return None


def source_context(project: Project) -> dict[str, Any]:
    root = project.root.resolve()
    entries = []
    for w in project.workers:
        base = w.config.path.parent
        for kind, declared in _declared_paths(w):
            target = Path(os.path.normpath(base / declared))
            entries.append({"worker": w.name, "env": w.env, "kind": kind, "path": _rel(root, target),
                            "exists": _exists(target)})
    return {
        "configs": [c.rel for c in project.configs],
        "entries": entries,
        "source_identity": source_identity(root),
    }


def _git(root: Path, args: list[str]) -> tuple[int, str, str]:
    """(exit code, stdout, stderr); -1 when git could not be run at all."""
    git = shutil.which("git")
    if git is None:
        return -1, "", "git not found on PATH"
    # GIT_DIR, GIT_WORK_TREE, GIT_INDEX_FILE, GIT_CONFIG_* and the like would point git at another
    # repository or add configuration. Global and system configuration are not read at all, so the
    # only configuration git sees is the repository's own (local, worktree, included), which
    # source_identity inspects before it runs status.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat",
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": os.devnull, "GIT_CONFIG_GLOBAL": os.devnull})
    try:
        cp = subprocess.run([git, "--no-pager", "--no-optional-locks", "-c", "core.fsmonitor=false",
                             "-c", "core.untrackedCache=false", "-C", str(root), *args],
                            capture_output=True, text=True, timeout=GIT_TIMEOUT_S, env=env,
                            stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return -1, "", f"git timed out after {GIT_TIMEOUT_S} s"
    except (OSError, UnicodeError) as exc:
        return -1, "", f"git could not run ({type(exc).__name__})"
    return cp.returncode, cp.stdout, cp.stderr.strip()


def _last_line(text: str) -> str:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return lines[-1][:200] if lines else ""


def source_identity(root: Path) -> dict[str, Any]:
    """{vcs: git|none|unknown, head: sha|null, dirty: bool|null, detail}."""
    out: dict[str, Any] = {"vcs": "unknown", "head": None, "dirty": None, "detail": ""}
    code, stdout, stderr = _git(root, ["rev-parse", "--is-inside-work-tree"])
    if code != 0:
        if code > 0 and "not a git repository (or any of the parent directories)" in stderr:
            out["vcs"] = "none"
            out["detail"] = "not a git work tree: no source revision recorded"
        else:
            out["detail"] = "git state not read: " + (_last_line(stderr) or f"git exited {code}")
        return out
    if stdout.strip() != "true":
        out["detail"] = "git state not read: not inside a work tree (" + (stdout.strip() or "no answer") + ")"
        return out
    out["vcs"] = "git"
    code, stdout, stderr = _git(root, ["rev-parse", "--verify", "-q", "HEAD"])
    head = stdout.strip()
    if code == 0 and len(head) in (40, 64) and all(c in "0123456789abcdef" for c in head):
        out["head"] = head
    else:
        out["detail"] = "HEAD not read (no commit yet, or an unreadable ref)"
        return out
    # git status can run content filter commands (filter.<name>.clean / smudge / process). Read the
    # effective configuration status would use, includes and worktree config included, and do not
    # run status when it defines any filter key or cannot be read completely.
    code, stdout, stderr = _git(root, ["config", "--list", "--includes", "-z"])
    if code != 0 or (stdout and not stdout.endswith("\0")):
        out["detail"] = ("work-tree state not read: repository config unreadable ("
                         + (_last_line(stderr) or f"exit {code}") + ")")
        return out
    keys = [rec.split("\n", 1)[0].lower() for rec in stdout.split("\0") if rec]
    if any(k.startswith("filter.") for k in keys):
        out["detail"] = ("work-tree state not read: the repository's config (local, worktree or included) defines "
                         "content filters that git status could run")
        return out
    code, stdout, stderr = _git(root, ["status", "--porcelain", "--untracked-files=normal",
                                       "--ignore-submodules=all", "--", "."])
    if code != 0:
        out["detail"] = "work-tree state not read: git status failed (" + (_last_line(stderr) or f"exit {code}") + ")"
        return out
    if stderr:  # e.g. an unreadable directory: git exits 0 after a partial traversal
        out["detail"] = "work-tree state not read completely: git status warned (" + _last_line(stderr) + ")"
        return out
    changed = sum(1 for ln in stdout.splitlines() if ln.strip())
    out["dirty"] = changed > 0
    out["detail"] = (f"{changed} changed or untracked path(s) under the scanned directory (not recorded here)"
                     if changed else "no changed or untracked paths under the scanned directory; "
                                     "submodules not inspected")
    return out
