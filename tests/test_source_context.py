"""Source-location context and source identity in provider_info (read-only, no source analysis).

PIN (owner 2026-10-20, docs/261020-refactor-AGENT_LED_BILLING_AUDIT.md section 3 item 4 and the lead's
pinned shape): provider_info.cloudflare.source_context = {configs, entries, source_identity}; identity
comes from read-only git, and anything git could not read is an explicit unknown, never a clean tree.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import _util
from _util import copy_fixture, scan, tree_digest

GIT = shutil.which("git")


def git(root: Path, *args: str) -> str:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    cp = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "init.defaultBranch=main",
                         "-C", str(root), *args], capture_output=True, text=True, env=env, check=True)
    return cp.stdout.strip()


def committed_fixture(name: str = "clean") -> Path:
    proj = copy_fixture(name)
    git(proj, "init", "-q")
    git(proj, "add", ".")
    git(proj, "commit", "-q", "-m", "fixture")
    return proj


def context(doc: dict) -> dict:
    return doc["provider_info"]["cloudflare"]["source_context"]


class SourceIdentity(unittest.TestCase):
    def setUp(self):
        if GIT is None:
            self.skipTest("git is not installed")

    def test_non_git_project_is_none_not_clean(self):
        doc, _ = scan(copy_fixture("clean"))
        ident = context(doc)["source_identity"]
        self.assertEqual((ident["vcs"], ident["head"], ident["dirty"]), ("none", None, None))
        self.assertTrue(ident["detail"])

    def test_clean_repository_reports_head_and_is_not_modified(self):
        proj = committed_fixture()
        head = git(proj, "rev-parse", "HEAD")
        before = tree_digest(proj)  # includes .git: the identity read writes nothing (no index refresh)
        doc, _ = scan(proj)
        ident = context(doc)["source_identity"]
        self.assertEqual((ident["vcs"], ident["head"], ident["dirty"]), ("git", head, False))
        self.assertEqual(before, tree_digest(proj))

    def test_dirty_tree_is_dirty_and_its_paths_are_not_recorded(self):
        proj = committed_fixture()
        (proj / "private-plan-notes.txt").write_text("not for the report")
        (proj / "src" / "index.ts").write_text((proj / "src" / "index.ts").read_text() + "\n// edited\n")
        out = Path(tempfile.mkdtemp(prefix="nobill-sc-"))
        doc, _ = scan(proj, out=out)
        ident = context(doc)["source_identity"]
        self.assertEqual((ident["vcs"], ident["dirty"]), ("git", True))
        for name in ("findings.json", "report.html", "report.md"):
            text = (out / name).read_text()
            self.assertNotIn("private-plan-notes", text, name)
            self.assertNotIn("// edited", text, name)

    def test_read_failures_are_unknown_never_clean(self):
        cases = {}
        no_git = Path(tempfile.mkdtemp(prefix="nobill-nogit-"))  # PATH without git
        cases["git not installed"] = (committed_fixture(), {"PATH": str(no_git)})
        broken = copy_fixture("clean")
        (broken / ".git").write_text("gitdir: /nonexistent/nobill-test\n")
        cases["broken .git link"] = (broken, None)
        filtered = committed_fixture()
        git(filtered, "config", "filter.secret.clean", "cat")
        cases["repository-defined content filter"] = (filtered, None)
        for name, (proj, env) in cases.items():
            with self.subTest(name):
                before = tree_digest(proj)
                doc, _ = scan(proj, env=env)
                ident = context(doc)["source_identity"]
                self.assertIsNone(ident["dirty"], name)
                self.assertNotEqual(ident["vcs"], "none", name)
                self.assertTrue(ident["detail"], name)
                self.assertEqual(before, tree_digest(proj), name)

    def filtered_repo(self, marker: Path) -> Path:
        """A committed repo whose files are all routed through a 'evil' filter (defined later by the
        caller) and whose tracked file has a new mtime, so git status would re-hash it through the filter."""
        proj = copy_fixture("clean")
        (proj / ".gitattributes").write_text("* filter=evil\n")
        git(proj, "init", "-q")
        git(proj, "add", ".")
        git(proj, "commit", "-q", "-m", "fixture")
        src = proj / "src" / "index.ts"
        st = src.stat()
        os.utime(src, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))
        return proj

    def test_filters_from_any_config_scope_never_run(self):
        # sol review 2026-10-21 finding 1: status honours included, worktree, global and system config
        # too; a filter command defined there must neither run nor leave the state claimed as read
        def included(proj, cmd):
            inc = Path(tempfile.mkdtemp(prefix="nobill-inc-")) / "extra.gitconfig"
            inc.write_text(f'[filter "evil"]\n\tclean = {cmd}\n')
            git(proj, "config", "include.path", str(inc))
            return None

        def worktree(proj, cmd):
            git(proj, "config", "extensions.worktreeConfig", "true")
            git(proj, "config", "--worktree", "filter.evil.clean", cmd)
            return None

        def process(proj, cmd):
            git(proj, "config", "filter.evil.process", cmd)
            return None

        def home_global(proj, cmd):
            home = _util.temp_home()
            (home / ".gitconfig").write_text(f'[filter "evil"]\n\tclean = {cmd}\n')
            return {"HOME": str(home)}

        def xdg_global(proj, cmd):
            xdg = Path(tempfile.mkdtemp(prefix="nobill-xdg-"))
            (xdg / "git").mkdir()
            (xdg / "git" / "config").write_text(f'[filter "evil"]\n\tclean = {cmd}\n')
            return {"XDG_CONFIG_HOME": str(xdg)}

        for name, setup, repo_scope in (("included file", included, True), ("worktree config", worktree, True),
                                        ("process filter", process, True), ("global ~/.gitconfig", home_global, False),
                                        ("XDG global config", xdg_global, False)):
            with self.subTest(name):
                marker = Path(tempfile.mkdtemp(prefix="nobill-marker-")) / "filter-ran"
                proj = self.filtered_repo(marker)
                env = setup(proj, f"touch {marker}; cat")
                before = tree_digest(proj)
                doc, _ = scan(proj, env=env)
                self.assertFalse(marker.exists(), f"{name}: the filter command ran")
                self.assertEqual(before, tree_digest(proj), name)
                ident = context(doc)["source_identity"]
                if repo_scope:  # the repository defines a filter: its state is not read, not clean
                    self.assertIsNone(ident["dirty"], name)
                    self.assertIn("filter", ident["detail"], name)

    def test_unreadable_directory_makes_the_state_unknown(self):
        if os.geteuid() == 0:
            self.skipTest("root reads every directory")
        proj = committed_fixture()
        locked = proj / "locked"
        locked.mkdir()
        (locked / "f.txt").write_text("x")
        locked.chmod(0)
        try:
            doc, _ = scan(proj)
        finally:
            locked.chmod(0o755)
        ident = context(doc)["source_identity"]
        self.assertEqual(ident["vcs"], "git")
        self.assertIsNone(ident["dirty"])
        self.assertIn("not read completely", ident["detail"])

    def test_git_environment_cannot_redirect_to_another_repository(self):
        other = committed_fixture("do_alarm_loop")
        proj = copy_fixture("clean")  # not a repository
        doc, _ = scan(proj, env={"GIT_DIR": str(other / ".git"), "GIT_WORK_TREE": str(other)})
        self.assertEqual(context(doc)["source_identity"]["vcs"], "none")


class DeclaredPaths(unittest.TestCase):
    def test_entries_name_declared_paths_and_whether_they_exist(self):
        proj = copy_fixture("queue_loop")  # top level plus a staging environment
        doc, _ = scan(proj)
        ctx = context(doc)
        self.assertEqual(ctx["configs"], ["wrangler.toml"])
        mains = [(e["worker"], e["env"], e["path"], e["exists"]) for e in ctx["entries"] if e["kind"] == "main"]
        self.assertEqual(len(mains), 2, ctx["entries"])
        self.assertEqual({m[1] for m in mains}, {None, "staging"})
        self.assertTrue(all(m[3] is True for m in mains))
        for e in ctx["entries"]:
            self.assertEqual(set(e), {"worker", "env", "kind", "path", "exists"})

    def test_missing_main_and_assets_directory(self):
        root = Path(tempfile.mkdtemp(prefix="nobill-sc-")) / "proj"
        (root / "app").mkdir(parents=True)
        (root / "app" / "wrangler.json").write_text(json.dumps({
            "name": "w", "main": "dist/worker.js", "compatibility_date": "2026-10-01",
            "assets": {"directory": "./public"}}))
        (root / "app" / "public").mkdir()
        doc, _ = scan(root)
        got = {(e["kind"], e["path"], e["exists"]) for e in context(doc)["entries"]}
        # a build output that does not exist yet is a declared path, not a verified deployment
        self.assertEqual(got, {("main", "app/dist/worker.js", False), ("assets", "app/public", True)})

    def test_no_config_has_no_entries(self):
        root = Path(tempfile.mkdtemp(prefix="nobill-sc-")) / "proj"
        root.mkdir(parents=True)
        (root / "package.json").write_text('{"devDependencies": {"wrangler": "4"}}')
        doc, _ = scan(root)
        self.assertEqual((context(doc)["configs"], context(doc)["entries"]), ([], []))


if __name__ == "__main__":
    unittest.main()
