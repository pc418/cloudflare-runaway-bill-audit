"""End-to-end scans of the fixture projects (no network, account layer off): configuration facts,
target immutability and output containment.

The fixtures' application source is kept as agent-evaluation input. The scan no longer analyses
it (owner 2026-10-20, docs/261020-refactor-AGENT_LED_BILLING_AUDIT.md), so these tests assert
configuration facts only; what the source does is the reviewing agent's finding.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import _util
from _util import by_rule, copy_fixture, scan, tree_digest


def alarm_rules(doc):
    return sorted({f["rule"] for f in doc["findings"] if f["severity"] == "alarm"})


class FixtureScans(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docs = {}
        cls.digests = {}
        for name in ("moltbot_sandbox", "do_alarm_loop", "queue_loop", "itty_open_ai", "clean", "broken_config"):
            proj = copy_fixture(name)
            if name == "clean":  # a dependency's config must be ignored
                nm = proj / "node_modules" / "some-pkg"
                nm.mkdir(parents=True)
                (nm / "wrangler.toml").write_text('name = "dep"\nmain = "i.js"\n[ai]\nbinding = "AI"\n')
            before = tree_digest(proj)
            cls.docs[name], _ = scan(proj)
            cls.digests[name] = (before, tree_digest(proj))

    def test_scanned_projects_are_not_modified(self):
        for name, (before, after) in self.digests.items():
            self.assertEqual(before, after, name)
            # the scan really read the project: a scanner that did nothing would also leave it unchanged
            d = self.docs[name]
            self.assertTrue(d["findings"], name)
            self.assertTrue(any(e.get("kind") == "file" for f in d["findings"] for e in f["evidence"]), name)

    def test_no_source_findings_and_an_empty_inventory(self):
        # PIN (owner 2026-10-20, docs/261020-refactor-AGENT_LED_BILLING_AUDIT.md sections 3 and 6): the scan
        # runs no source analysis; every finding comes from configuration or the account layer, and the
        # paid-work inventory is left for the agent, even for fixtures whose source has known exposures
        for name, d in self.docs.items():
            self.assertEqual({f["source"] for f in d["findings"]} - {"config", "api"}, set(), name)
            self.assertEqual(d["paid_work_inventory"], [], name)
            self.assertFalse([f for f in d["findings"] if "coverage_ref" in f], name)

    def test_moltbot_config_facts(self):
        d = self.docs["moltbot_sandbox"]
        # binding presence is not evidence that a catch-all starts the container: no automatic alarm
        self.assertEqual(alarm_rules(d), [])
        cmax = by_rule(d, "CF-CONTAINER-MAX-INSTANCES", "suggestion")[0]
        self.assertEqual(cmax["source"], "config")
        self.assertEqual(cmax["evidence"][0]["line"], 18)  # the containers entry in the jsonc, past the comment header
        self.assertTrue(by_rule(d, "CF-CONTAINER-SIZE", "suggestion"))
        self.assertTrue(by_rule(d, "CF-WORKERS-DEV-ON", "suggestion"))

    def test_do_alarm_loop_config_facts(self):
        d = self.docs["do_alarm_loop"]
        self.assertEqual(alarm_rules(d), [])
        self.assertTrue(by_rule(d, "CF-CPU-LIMIT", "pass"))

    def test_queue_loop_config_facts(self):
        d = self.docs["queue_loop"]
        bounds = by_rule(d, "CF-QUEUE-CONSUMER-BOUNDS")
        self.assertEqual(sorted(f["severity"] for f in bounds), ["pass", "suggestion"])
        sugg = [f for f in bounds if f["severity"] == "suggestion"][0]
        self.assertEqual(sugg["evidence"][0]["snippet"], 'queue = "memory-ingest"')
        self.assertEqual(sugg["evidence"][0]["line"], 19)
        # the staging env inherits observability (100% sampling) but not bindings
        self.assertEqual(len(by_rule(d, "CF-LOG-SAMPLING", "suggestion")), 2)

    def test_itty_config_facts(self):
        d = self.docs["itty_open_ai"]
        self.assertTrue(by_rule(d, "CF-RUN-WORKER-FIRST"))
        self.assertTrue(by_rule(d, "CF-SUBREQUESTS-RAISED", "suggestion"))
        cpu = by_rule(d, "CF-CPU-LIMIT", "suggestion")[0]
        self.assertIn("300,000", cpu["title"])

    def test_clean_project_config_facts(self):
        d = self.docs["clean"]
        self.assertEqual(alarm_rules(d), [])
        for rule in ("CF-WORKERS-DEV-ON", "CF-NO-RATELIMIT-BINDING", "CF-CPU-LIMIT", "CF-LOG-SAMPLING",
                     "CF-QUEUE-CONSUMER-BOUNDS"):
            self.assertTrue(by_rule(d, rule, "pass"), rule)
        workers = d["provider_info"]["cloudflare"]["workers"]
        self.assertFalse(any("dep" in w for w in workers), workers)

    def test_config_parse_failure_is_unknown_not_pass(self):
        d = self.docs["broken_config"]
        unk = by_rule(d, "CF-CONFIG-UNREADABLE", "unknown")
        self.assertEqual(sorted(f["evidence"][0]["file"] for f in unk), ["wrangler.jsonc", "wrangler.toml"])
        for f in unk:
            self.assertIn("config unreadable", f["missing"])
        self.assertFalse([f for f in d["findings"] if f["severity"] == "pass"])
        self.assertFalse(d["provider_info"]["cloudflare"]["workers"])

    def test_every_finding_is_well_formed(self):
        rules = {f["rule"] for d in self.docs.values() for f in d["findings"]}
        self.assertGreaterEqual(len(rules), 12, sorted(rules))  # an empty or truncated scan cannot pass vacuously
        for name, d in self.docs.items():
            self.assertTrue(d["findings"], name)
            for f in d["findings"]:
                self.assertTrue(f["fix"]["text"], f["id"])
                self.assertTrue(all(doc["url"].startswith("https://developers.cloudflare.com/") for doc in f["fix"]["docs"]))
                if f["confidence"] == "heuristic":
                    self.assertEqual(f["review"]["status"], "needs-review")
                if f["severity"] == "unknown":
                    self.assertTrue(f["missing"].strip())
                for ref in f["why"]["incidents"]:
                    self.assertIn(ref, d["incidents"])

    def test_every_incident_is_available_to_the_agent(self):
        # the agent cites any catalogue anchor, whether or not a retained rule maps to it
        from nobill.incidents import INCIDENTS
        for name, d in self.docs.items():
            self.assertEqual(set(d["incidents"]), set(INCIDENTS), name)

    def test_account_layer_off_reports_unknown_with_reason(self):
        d = self.docs["itty_open_ai"]
        alert = [f for f in by_rule(d, "CF-NO-BILLING-ALERT") if f["severity"] == "unknown"]
        self.assertEqual(len(alert), 1)
        self.assertIn("--account", alert[0]["missing"])
        self.assertTrue(all(r["status"] == "not run" for r in d["scope_requirements"]))


class OutputLocation(unittest.TestCase):
    def test_out_inside_project_is_refused(self):
        proj = copy_fixture("clean")
        before = tree_digest(proj)
        cp = _util.run_cli(["scan", str(proj), "--out", str(proj / "report")])
        self.assertEqual(cp.returncode, 2)
        self.assertIn("outside the scanned project", cp.stderr)
        self.assertEqual(before, tree_digest(proj))

    def test_default_out_is_a_new_temp_dir(self):
        proj = copy_fixture("clean")
        cp = _util.run_cli(["scan", str(proj)])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        path = Path([l for l in cp.stdout.splitlines() if l.startswith("findings (edit, then render):")][0]
                    .split(":", 1)[1].strip())
        self.assertTrue(path.is_file())
        self.assertTrue(str(path).startswith(str(Path(tempfile.gettempdir()).resolve())) or
                        str(path).startswith(tempfile.gettempdir()))
        self.assertFalse(str(path).startswith(str(proj)))
        json.loads(path.read_text())


class OutputContainment(unittest.TestCase):
    """The scanner never writes into the scanned project, whatever the output or bytecode settings."""

    def test_default_temp_dir_inside_the_project_is_refused(self):
        proj = copy_fixture("clean")
        tmp_inside = proj / "tmp"
        tmp_inside.mkdir()
        before = tree_digest(proj)
        cp = _util.run_cli(["scan", str(proj)], env={"TMPDIR": str(tmp_inside), "TEMP": str(tmp_inside),
                                                      "TMP": str(tmp_inside)})
        self.assertEqual(cp.returncode, 2, cp.stdout + cp.stderr)
        self.assertIn("--out", cp.stderr)
        self.assertEqual(before, tree_digest(proj))

    def test_project_containing_the_temp_dir_is_refused(self):
        proj = copy_fixture("clean")
        before = tree_digest(proj)
        cp = _util.run_cli(["scan", str(proj)], env={"TMPDIR": str(proj / "src")})
        self.assertEqual(cp.returncode, 2, cp.stdout + cp.stderr)
        self.assertEqual(before, tree_digest(proj))

    def _record_writes(self, argv: list[str], env: dict) -> tuple[int, list[str]]:
        """Run the CLI in-process and record every filesystem create/write it attempts."""
        import builtins
        import contextlib
        import io
        from unittest import mock
        from nobill import cli
        writes: list[str] = []
        real_open, real_os_open, real_mkdir = builtins.open, os.open, os.mkdir
        wflags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC

        def rec_open(file, mode="r", *a, **k):
            if isinstance(file, (str, bytes, os.PathLike)) and any(c in mode for c in "wax+"):
                writes.append(os.fspath(file))
            return real_open(file, mode, *a, **k)

        def rec_os_open(path, flags, *a, **k):
            if flags & wflags:
                writes.append(os.fspath(path))
            return real_os_open(path, flags, *a, **k)

        def rec_mkdir(path, *a, **k):
            writes.append(os.fspath(path))
            return real_mkdir(path, *a, **k)

        old_env = {k: os.environ.get(k) for k in ("TMPDIR", "TEMP", "TMP")}
        try:
            for k in old_env:
                os.environ.pop(k, None)
            os.environ.update(env)
            with mock.patch.object(tempfile, "tempdir", None), mock.patch("builtins.open", rec_open), \
                    mock.patch("io.open", rec_open), mock.patch("os.open", rec_os_open), \
                    mock.patch("os.mkdir", rec_mkdir), contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                rc = cli.main(argv)
        finally:
            for k, v in old_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        return rc, writes

    def test_no_create_or_write_under_the_project_even_transiently(self):
        # reviewer probe: TMPDIR is the project and tempfile's cached tempdir is cleared
        proj = copy_fixture("clean").resolve()
        rc, writes = self._record_writes(["scan", str(proj)], {"TMPDIR": str(proj)})
        self.assertEqual(rc, 2)
        self.assertEqual([w for w in writes if Path(w).resolve().is_relative_to(proj) or
                          Path(os.path.abspath(w)).is_relative_to(proj)], [])
        # positive control: a temp dir outside the project gets the report, the project gets nothing
        elsewhere = Path(tempfile.mkdtemp(prefix="nobill-tmpbase-")).resolve()
        rc, writes = self._record_writes(["scan", str(proj)], {"TMPDIR": str(elsewhere)})
        self.assertEqual(rc, 0)
        self.assertTrue([w for w in writes if Path(w).resolve().is_relative_to(elsewhere)])
        self.assertEqual([w for w in writes if Path(w).resolve().is_relative_to(proj)], [])

    def test_existing_output_symlink_into_the_project_is_never_followed(self):
        # reviewer probe: a pre-existing <out>/report.md symlink to project/src/index.ts used to be
        # followed by write_text and truncate the source. Covers every output of scan and of render.
        def setup():
            proj = copy_fixture("clean")
            out = Path(tempfile.mkdtemp(prefix="nobill-out-"))
            return proj, out, proj / "src" / "index.ts"

        for name in ("findings.json", "report.html", "report.md"):
            with self.subTest(command="scan", output=name):
                proj, out, target = setup()
                (out / name).symlink_to(target)
                before = tree_digest(proj)
                cp = _util.run_cli(["scan", str(proj), "--out", str(out)])
                self.assertEqual(cp.returncode, 2, cp.stdout + cp.stderr)
                self.assertIn("links into the scanned project", cp.stderr)
                self.assertEqual(before, tree_digest(proj))
                self.assertEqual(sorted(os.listdir(out)), [name])  # validated before anything was written
        for name in ("report.html", "report.md"):
            with self.subTest(command="render", output=name):
                proj, out, target = setup()
                scan(proj, out=out)
                (out / name).unlink()
                (out / name).symlink_to(target)
                before = tree_digest(proj)
                cp = _util.run_cli(["render", str(out / "findings.json")])
                self.assertEqual(cp.returncode, 2, cp.stdout + cp.stderr)
                self.assertIn("links into the scanned project", cp.stderr)
                self.assertEqual(before, tree_digest(proj))

    def test_existing_hard_link_into_the_project_is_replaced_not_written_through(self):
        # a hard link cannot be told apart by resolving it; the atomic replace swaps the entry instead
        proj = copy_fixture("clean")
        target = proj / "src" / "index.ts"
        out = Path(tempfile.mkdtemp(prefix="nobill-out-"))
        try:
            os.link(target, out / "report.md")
        except OSError as exc:
            self.skipTest(f"no hard links here: {exc}")
        before = tree_digest(proj)
        scan(proj, out=out)
        self.assertEqual(before, tree_digest(proj))
        self.assertFalse(os.path.samefile(target, out / "report.md"))
        self.assertIn("# Cloudflare bill-risk handoff", (out / "report.md").read_text())

    def test_render_outputs_never_alias_each_other_or_the_findings(self):
        # reviewer probe: `render --out custom.MD` passed the Path inequality guard, and on a
        # case-insensitive file system report.md then overwrote the HTML while exiting 0
        proj = copy_fixture("clean")
        out = Path(tempfile.mkdtemp(prefix="nobill-out-"))
        scan(proj, out=out)
        findings = (out / "findings.json").read_text()
        for name in ("custom.MD", "custom.Md", "FINDINGS.json", "Findings.JSON", "findings.json"):
            with self.subTest(out=name):
                before = sorted(os.listdir(out))
                cp = _util.run_cli(["render", str(out / "findings.json"), "--out", str(out / name)])
                self.assertEqual(cp.returncode, 2, cp.stdout + cp.stderr)
                self.assertIn("same file", cp.stderr)
                self.assertEqual(sorted(os.listdir(out)), before)  # nothing written
                self.assertEqual((out / "findings.json").read_text(), findings)
        # an existing hard-linked alias of the HTML at the markdown path is refused too
        (out / "r.html").write_text("old")
        os.link(out / "r.html", out / "r.md")
        cp = _util.run_cli(["render", str(out / "findings.json"), "--out", str(out / "r.html")])
        self.assertEqual(cp.returncode, 2, cp.stdout + cp.stderr)
        self.assertIn("same file", cp.stderr)
        # a plain custom name still works
        cp = _util.run_cli(["render", str(out / "findings.json"), "--out", str(out / "custom.html")])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertTrue((out / "custom.html").read_text().startswith("<!doctype html>"))
        self.assertTrue((out / "custom.md").read_text().startswith("# Cloudflare bill-risk handoff"))

    def test_project_local_install_without_dash_b_writes_no_bytecode(self):
        """The documented invocation `python3 <skill>/scripts/audit.py scan .` with the skill
        installed inside the project (e.g. .claude/skills/) must not leave __pycache__ there."""
        proj = copy_fixture("clean")
        skill = proj / ".claude" / "skills" / "cloudflare-runaway-bill-audit"
        shutil.copytree(_util.SCRIPTS, skill / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
        before = tree_digest(proj)
        out = Path(tempfile.mkdtemp(prefix="nobill-out-"))
        env = {k: v for k, v in os.environ.items() if k != "PYTHONDONTWRITEBYTECODE"}
        cp = subprocess.run([sys.executable, str(skill / "scripts" / "audit.py"), "scan", str(proj), "--out", str(out)],
                            capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(list(proj.rglob("__pycache__")), [])
        self.assertEqual(before, tree_digest(proj))


if __name__ == "__main__":
    unittest.main()
