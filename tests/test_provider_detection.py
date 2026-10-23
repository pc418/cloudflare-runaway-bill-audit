"""Cloudflare-only scans reject other projects before creating any output."""
import json
import os
import tempfile
import unittest
from pathlib import Path

import _util
from _util import run_cli, tree_digest

ERROR = ("error: not a Cloudflare project (no wrangler config or Cloudflare dependency found); "
         "pass --provider cloudflare to scan anyway")


class ProviderDetection(unittest.TestCase):
    def project(self, files):
        tmp = tempfile.TemporaryDirectory(prefix="nobill-detect-")
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        project = base / "project"
        project.mkdir()
        for rel, text in files.items():
            path = project / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        return project, base / "reports"

    def vercel(self):
        return self.project({
            "vercel.json": "{}",
            "package.json": '{"dependencies":{"next":"15"}}',
            "api/gen.js": 'export default async function handler(req,res){return fetch("https://api.openai.com/v1/responses",{method:"POST",body:req.body});}',
        })

    def test_non_cloudflare_rejected_before_default_or_explicit_output(self):
        for explicit in (False, True):
            with self.subTest(explicit=explicit):
                project, reports = self.vercel()
                temp_base = reports.parent / "temp-base"
                temp_base.mkdir()
                before = tree_digest(project)
                cp = run_cli(["scan", str(project), *(["--out", str(reports)] if explicit else [])],
                             env={"TMPDIR": str(temp_base)})
                self.assertEqual(cp.returncode, 2, cp.stdout)
                self.assertEqual(cp.stderr.strip(), ERROR)
                self.assertEqual(cp.stdout, "")
                self.assertFalse(reports.exists())
                self.assertEqual(list(temp_base.iterdir()), [])
                self.assertEqual(tree_digest(project), before)

    def test_explicit_cloudflare_still_forces_scan(self):
        project, reports = self.vercel()
        cp = run_cli(["scan", str(project), "--provider", "cloudflare", "--out", str(reports)])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        doc = json.loads((reports / "findings.json").read_text())
        self.assertEqual(doc["providers"], ["cloudflare"])
        self.assertEqual(doc["schema"], "cloudflare-runaway-bill-audit/findings@1")
        self.assertEqual(doc["tool"]["name"], "cloudflare-runaway-bill-audit")
        self.assertTrue(any(f["rule"] == "CF-NO-CONFIG" for f in doc["findings"]))

    def test_nested_wrangler_is_still_detected(self):
        project, reports = self.project({
            "packages/api/wrangler.toml": 'name = "worker"\nmain = "index.js"\n',
            "packages/api/index.js": 'export default {fetch(){return new Response("ok");}};',
        })
        cp = run_cli(["scan", str(project), "--out", str(reports)])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertTrue((reports / "findings.json").is_file())

    def test_cloudflare_dependency_without_config_is_still_detected(self):
        for name, section in (("wrangler", "devDependencies"), ("@cloudflare/workers-types", "dependencies")):
            with self.subTest(dependency=name):
                project, reports = self.project({"package.json": json.dumps({section: {name: "1"}})})
                cp = run_cli(["scan", str(project), "--out", str(reports)])
                self.assertEqual(cp.returncode, 0, cp.stderr)
                self.assertTrue((reports / "findings.json").is_file())


class UnreadableDuringDetection(unittest.TestCase):
    """Detection stays conservative, but a refusal caused by an unreadable path says so: the
    project may be a Cloudflare project whose config could not be read (coordinator 2026-10-21)."""

    def setUp(self):
        if os.geteuid() == 0:
            self.skipTest("root reads every path")
        tmp = tempfile.TemporaryDirectory(prefix="nobill-detect-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.project = self.base / "project"
        self.reports = self.base / "reports"

    def write(self, rel, text):
        path = self.project / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def lock(self, path):
        mode = path.stat().st_mode & 0o777
        path.chmod(0)
        self.addCleanup(path.chmod, mode)

    def refuse(self):
        cp = run_cli(["scan", str(self.project), "--out", str(self.reports)])
        self.assertEqual(cp.returncode, 2, cp.stdout)
        self.assertEqual(cp.stdout, "")
        self.assertFalse(self.reports.exists())
        return cp.stderr

    def test_unlistable_directory_is_named_in_the_refusal(self):
        self.write("services/api/wrangler.json", '{"name": "api", "main": "index.js"}')
        self.write("services/web/index.js", "")
        self.lock(self.project / "services" / "api")
        err = self.refuse()
        self.assertIn("services/api", err)
        self.assertNotIn("services/web", err)
        self.assertIn("may be a Cloudflare project whose config could not be read", err)
        self.assertIn("--provider cloudflare", err)
        self.assertNotEqual(err.strip(), ERROR)

    def test_several_unlistable_directories_are_all_named(self):
        for rel in ("a/wrangler.toml", "b/c/wrangler.toml"):
            self.write(rel, 'name = "w"\n')
        self.lock(self.project / "a")
        self.lock(self.project / "b" / "c")
        err = self.refuse()
        self.assertIn("a (", err)
        self.assertIn("b/c", err)

    def test_unreadable_package_json_is_named_in_the_refusal(self):
        pkg = self.write("package.json", '{"devDependencies": {"wrangler": "4"}}')
        self.lock(pkg)
        err = self.refuse()
        self.assertIn("package.json", err)
        self.assertIn("may be a Cloudflare project whose config could not be read", err)
        self.assertIn("--provider cloudflare", err)

    def test_readable_non_cloudflare_project_keeps_the_plain_refusal(self):
        self.write("vercel.json", "{}")
        self.write("api/gen.js", "")
        self.assertEqual(self.refuse().strip(), ERROR)
