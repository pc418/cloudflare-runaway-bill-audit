"""report.md: the compact agent handoff written next to report.html by scan and render."""

import copy
import html
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import _util
from _util import copy_fixture, scan, tree_digest

HOSTILE = ('``` `` ` ~~~\n# Injected heading\n[x](javascript:alert(1)) <script>alert(1)</script> '
           '<img src=x onerror=alert(2)> ![i](https://evil.example/p.png) [ref]: https://evil.example\n'
           '===\n<https://evil.example/autolink> \\[esc\\](javascript:void(0))')

# GFM extended autolinks: bare URLs, www. hosts, emails and mailto:/xmpp: forms
AUTOLINKS = ("see https://evil.example/collect?x=1 and HTTP://EVIL.example/a, ftp://evil.example/f, "
             "www.evil.example/p (www.evil.example/q) *www.evil.example/r* a.b@evil.example "
             "mailto:x@evil.example xmpp:x@evil.example/res")
TOOL_URL = "https://developers.cloudflare.com/x/"

_ESC = re.compile(r"\\([\\`\[\]<>#])")


def plain(md: str) -> str:
    """The text a reader sees for backslash-escaped spans (the escaping is reversible)."""
    return _ESC.sub(r"\1", md)


def fences(md: str) -> list[tuple[str, str]]:
    """(fence, body) for every fenced block, parsed the CommonMark way (closing fence >= opening)."""
    out, lines, i = [], md.split("\n"), 0
    while i < len(lines):
        m = re.match(r"^(`{3,})[^`]*$", lines[i])
        if m:
            fence, body, i = m.group(1), [], i + 1
            while i < len(lines) and not re.match(rf"^{fence}`*\s*$", lines[i]):
                body.append(lines[i])
                i += 1
            out.append((fence, "\n".join(body)))
        i += 1
    return out


def one_line(value) -> str:
    return " ".join(str(value).split())


def sections_by_id(md: str) -> dict[str, str]:
    """Each finding's block in report.md, keyed by the stable id on its first line."""
    out = {}
    for block in re.split(r"(?m)^(?=### |## )", md):
        m = re.search(r"`(f\d{3,})`", block)
        if block.startswith("### ") and m:
            out[m.group(1)] = block
    return out


def ids_in_order(md: str) -> list[str]:
    return re.findall(r"(?m)^(?:### .*\n\n|- )`(f\d{3,})`", md)


def check_item(tc: unittest.TestCase, f: dict, block: str) -> None:
    """Every piece of a finding the agent needs is in its own block of report.md."""
    seen = plain(block)
    tc.assertIn(f["rule"], seen)
    tc.assertIn(one_line(f["title"]), seen)
    if f.get("target"):
        tc.assertIn(one_line(f["target"]), seen)
    for e in f["evidence"]:
        if e["kind"] == "file":
            tc.assertIn(f"{e['file']}:{e['line']}", seen)
            if e.get("snippet"):
                tc.assertIn(e["snippet"], block)
        elif e["kind"] == "api":
            for k in ("endpoint", "field", "value"):
                if e.get(k) is not None:
                    tc.assertIn(one_line(e[k]), seen, k)
        else:
            tc.assertIn(one_line(e["text"]), seen)
    if f["severity"] == "unknown":
        tc.assertIn(one_line(f["missing"]), seen)
    tc.assertIn(one_line(f["fix"]["text"]), seen)
    for d in f["fix"]["docs"]:
        tc.assertIn(d["url"], seen)
    review = f["review"]
    tc.assertIn(f"review {review['status']}", seen)
    if review.get("reason"):
        tc.assertIn(one_line(review["reason"]), seen)
    if review.get("original_severity") and review["original_severity"] != f["severity"]:
        tc.assertIn(f"was {review['original_severity']}", seen)


def outside_fences(md: str) -> str:
    """The markdown with fenced blocks and inline code spans removed: what a renderer interprets."""
    for fence, body in fences(md):
        md = md.replace(f"{fence}\n{body}\n{fence}", "", 1)
    return re.sub(r"(?<![\\`])(`+)(?!`).*?(?<!`)\1(?!`)", "", md, flags=re.S)


class MarkdownContent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proj = copy_fixture("itty_open_ai")
        cls.before = tree_digest(cls.proj)
        cls.out = Path(tempfile.mkdtemp(prefix="nobill-md-"))
        cls.doc, cls.cp = scan(cls.proj, out=cls.out)
        cls.md = (cls.out / "report.md").read_text()

    def test_written_next_to_the_html_and_not_in_the_project(self):
        self.assertTrue((self.out / "report.html").is_file())
        self.assertTrue((self.out / "report.md").is_file())
        self.assertEqual(self.before, tree_digest(self.proj))
        self.assertFalse(list(self.proj.rglob("report.md")))

    def test_every_actionable_finding_with_evidence_and_fix(self):
        blocks = sections_by_id(self.md)
        active = [f for f in self.doc["findings"] if f["severity"] in ("alarm", "suggestion", "unknown")]
        self.assertTrue(any(f["severity"] == "unknown" for f in active))
        self.assertTrue(any(e["kind"] == "note" for f in active for e in f["evidence"]))
        for f in active:
            with self.subTest(f["id"]):
                self.assertIn(f["id"], blocks)
                check_item(self, f, blocks[f["id"]])

    def test_action_first_order_and_compact_tail(self):
        out = Path(tempfile.mkdtemp(prefix="nobill-md-pass-"))
        doc, _ = scan(copy_fixture("clean"), out=out)  # the itty scan has no pass to check
        md = (out / "report.md").read_text()
        heads = [md.index(h) for h in ("## Must fix", "## Suggestions", "## Unknowns", "## Passed")]
        self.assertEqual(heads, sorted(heads))
        for word in ("Project:", "Scanned:", "Providers:", "Layers:", "Counts:"):
            self.assertIn(word, md.split("## Must fix")[0])
        passed = md.split("## Passed", 1)[1].split("\n## ", 1)[0]  # the inventory/source appendix follows
        passes = [f for f in doc["findings"] if f["severity"] == "pass"]
        self.assertTrue(passes)
        self.assertEqual(sum(1 for line in passed.split("\n") if line.startswith("### P")), len(passes))
        blocks = sections_by_id(passed)
        for finding in passes:
            with self.subTest(finding["id"]):
                check_item(self, finding, blocks[finding["id"]])

    def test_pass_and_not_applicable_preserve_controls_evidence_and_details(self):
        # PIN owner 2026-10-21: dual-agent skill use found pass caveats lost in handoff.
        from test_render import minimal_doc
        d = minimal_doc()
        original = d["findings"][0]
        d["findings"] = []
        for ident, severity in (("f002", "pass"), ("f003", "not-applicable")):
            finding = copy.deepcopy(original)
            finding.update(id=ident, severity=severity, source="agent", title=f"Scoped result {ident}")
            finding["review"] = {"status": "confirmed", "reason": f"Inspected path {ident}"}
            finding["why"] = {"text": f"Only concurrent holds are bounded {ident}; <script>not executable</script>", "incidents": []}
            finding["fix"] = {"text": f"Retain separate attempt accounting {ident}",
                              "docs": [{"title": "Control documentation", "url": TOOL_URL}]}
            finding["evidence"] = [
                {"kind": "file", "file": "src/job.ts", "line": 10, "snippet": "await reserve();"},
                {"kind": "note", "text": f"Refund after provider acceptance remains possible {ident}"}]
            finding["details"] = {"columns": ["unit"], "rows": [{"unit": f"attempts {ident}"}], "note": f"Scope note {ident}"}
            d["findings"].append(finding)
        out = Path(tempfile.mkdtemp(prefix="nobill-pass-handoff-"))
        (out / "findings.json").write_text(json.dumps(d))
        cp = _util.run_cli(["render", str(out / "findings.json")])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        md = (out / "report.md").read_text()
        rendered = (out / "report.html").read_text()
        for finding in d["findings"]:
            check_item(self, finding, sections_by_id(md)[finding["id"]])
            for value in (finding["why"]["text"], finding["fix"]["text"], finding["evidence"][1]["text"],
                          finding["details"]["rows"][0]["unit"], finding["details"]["note"]):
                self.assertIn(value, plain(md))
                self.assertIn(html.escape(value, quote=True), rendered)
        self.assertNotIn("<script>", rendered)
        self.assertEqual(json.loads((out / "findings.json").read_text()), d)

    def test_same_order_as_findings_json(self):
        fs = self.doc["findings"]
        dismissed = [f["id"] for f in fs if f["review"]["status"] == "false-positive"]
        want = [f["id"] for sev in ("alarm", "suggestion", "unknown") for f in fs
                if f["severity"] == sev and f["id"] not in dismissed]
        want += dismissed + [f["id"] for f in fs if f["severity"] == "pass" and f["id"] not in dismissed]
        self.assertEqual(ids_in_order(self.md), want)

    def test_unknowns_keep_evidence_fix_target_and_review(self):
        # reviewer probe: a schema-valid unknown with file/snippet/note evidence, an API field and value,
        # a target, fix/docs and a user-confirmed review lost all of it except rule, title and missing
        from nobill.markdown import render_md
        from nobill.findings import validate_document
        from test_render import minimal_doc
        d = minimal_doc()
        unk = copy.deepcopy(d["findings"][0])
        unk.update(id="f002", severity="unknown", rule="CF-NO-BILLING-ALERT", title="No budget alert seen",
                   target="account acc-1", confidence="certain", source="api",
                   missing="Notifications Read on the token")
        unk["evidence"] = [{"kind": "file", "file": "wrangler.toml", "line": 7, "snippet": "[observability]"},
                           {"kind": "api", "endpoint": "/accounts/acc-1/alerting/v3/policies", "field": "alert_type",
                            "value": "billing_usage_alert"},
                           {"kind": "note", "text": "budget alerts have no verified API"}]
        unk["fix"] = {"text": "Create a budget alert in Billing.",
                      "docs": [{"title": "alerts", "url": "https://developers.cloudflare.com/notifications/"}]}
        unk["review"] = {"status": "confirmed", "reason": "user confirmed a $50 budget alert in the dashboard",
                         "original_severity": "alarm"}
        d["findings"].append(unk)
        self.assertEqual(validate_document(d), [])
        md = render_md(d)
        blocks = sections_by_id(md)
        self.assertIn("f002", blocks)
        self.assertIn("## Unknowns", md.split(blocks["f002"])[0])
        check_item(self, unk, blocks["f002"])


def with_agent_text(d: dict, value: str) -> dict:
    """The agent-written and collected text outside findings: review summary, inventory, source context."""
    d.update(audit_status="reviewed", review_summary=value + "\n" + value)
    d["paid_work_inventory"] = [{"worker": value, "file": value, "line": 2, "method": value, "path": value,
                                 "paid_work": [value], "guard_signals": {value: ["x"]}, "review": value}]
    d["provider_info"] = {"cloudflare": {"source_context": {
        "configs": [value], "entries": [{"worker": value, "env": value, "kind": value, "path": value, "exists": True}],
        "source_identity": {"vcs": "git", "head": value, "dirty": None, "detail": value}}}}
    return d


class MarkdownSafety(unittest.TestCase):
    def hostile_doc(self):
        from test_render import minimal_doc
        d = minimal_doc()
        f = d["findings"][0]
        f.update(title=HOSTILE, target=HOSTILE)
        f["evidence"] = [{"kind": "file", "file": HOSTILE, "line": 3, "snippet": HOSTILE},
                         {"kind": "api", "endpoint": HOSTILE, "field": HOSTILE, "value": HOSTILE},
                         {"kind": "note", "text": HOSTILE}]
        f["why"]["text"] = HOSTILE
        f["fix"] = {"text": HOSTILE, "docs": [{"title": HOSTILE, "url": "javascript:alert(1)"},
                                              {"title": "ok", "url": "https://developers.cloudflare.com/x/"}]}
        f["review"] = {"status": "confirmed", "reason": HOSTILE}
        unk = copy.deepcopy(f)
        unk.update(id="f002", severity="unknown", missing=HOSTILE)
        dis = copy.deepcopy(f)
        dis.update(id="f003")
        dis["review"] = {"status": "false-positive", "reason": HOSTILE}
        ps = copy.deepcopy(f)
        ps.update(id="f004", severity="pass")
        d["findings"] += [unk, dis, ps]
        d["project"] = HOSTILE
        return with_agent_text(d, HOSTILE)

    def test_hostile_project_text_cannot_break_fences_or_inject(self):
        from nobill.markdown import render_md
        md = render_md(self.hostile_doc())
        # 1. every fence closes where it should: the hostile snippet is intact inside its fence
        blocks = fences(md)
        self.assertTrue(blocks)
        self.assertTrue(any(body == HOSTILE for _, body in blocks), blocks)
        self.assertTrue(all(len(f) > 3 for f, b in blocks if "```" in b))
        # 2. outside code, nothing is live markdown/HTML
        live = outside_fences(md)
        self.assertIsNone(re.search(r"(?m)^\s*#+\s*Injected", live))
        self.assertIsNone(re.search(r"(?<!\\)\[[^\]\n]*(?<!\\)\]\(", live), "unescaped link")
        opened = re.findall(r"(?<!\\)<([^>\s]*)>?", live)  # raw HTML or autolinks a renderer would act on
        self.assertEqual(set(opened), {"https://developers.cloudflare.com/x/"})  # only the tool's safe doc link
        self.assertIsNone(re.search(r"(?m)^\s*\[ref\]:", live))
        self.assertIsNone(re.search(r"(?m)^={3,}\s*$", live), "setext heading underline")
        self.assertNotIn("javascript:alert(1)>", md)
        self.assertNotIn("](javascript:", live.replace("\\]", ""))
        # 3. the reader still sees the text
        self.assertIn("[x](javascript:alert(1))", plain(live).replace("\n", " ") + plain(md))

    def autolink_doc(self):
        from test_render import minimal_doc
        d = minimal_doc()
        f = d["findings"][0]
        f.update(title=AUTOLINKS, target=AUTOLINKS)
        f["evidence"].append({"kind": "note", "text": AUTOLINKS})
        f["why"]["text"] = AUTOLINKS
        f["fix"] = {"text": AUTOLINKS, "docs": [{"title": "ok", "url": TOOL_URL}]}
        f["review"] = {"status": "confirmed", "reason": AUTOLINKS}
        unk = copy.deepcopy(f)
        unk.update(id="f002", severity="unknown", missing=AUTOLINKS)
        dis = copy.deepcopy(f)
        dis.update(id="f003")
        dis["review"] = {"status": "false-positive", "reason": AUTOLINKS}
        ps = copy.deepcopy(f)
        ps.update(id="f004", severity="pass")
        d["findings"] += [unk, dis, ps]
        return with_agent_text(d, AUTOLINKS)

    def test_bare_urls_www_and_emails_in_project_text_are_not_links(self):
        # reviewer probe: GFM autolinks bare URLs, www. hosts and emails in plain text
        from nobill.markdown import render_md
        md = render_md(self.autolink_doc())
        live = outside_fences(md).replace(f"<{TOOL_URL}>", "")
        self.assertIsNone(re.search(r"(?i)[a-z][a-z0-9+.-]*:(?:\\)?//|www(?:\\)?\.|@", live),
                          "an autolink form outside code")
        self.assertIn("https://evil.example/collect?x=1", md)  # still shown, as inert code
        self.assertIn("a.b@evil.example", md)

    @unittest.skipUnless(shutil.which("pandoc"), "pandoc (a GFM reader with autolinks) is not installed")
    def test_gfm_reader_finds_only_the_tools_own_links(self):
        from nobill.markdown import render_md
        for name, doc in (("autolinks", self.autolink_doc()), ("hostile", self.hostile_doc())):
            with self.subTest(name):
                html = subprocess.run(["pandoc", "-f", "gfm", "-t", "html"], input=render_md(doc),
                                      capture_output=True, text=True, timeout=60, check=True).stdout
                self.assertEqual(set(re.findall(r'href="([^"]*)"', html)), {TOOL_URL})
                self.assertIsNone(re.search(r"<(script|img|iframe)\b", html))
                self.assertNotIn(">Injected heading</h", html)

    def test_render_writes_md_from_the_reviewed_json(self):
        from test_render import minimal_doc
        out = Path(tempfile.mkdtemp(prefix="nobill-mdr-"))
        d = minimal_doc()
        d["findings"][0]["review"] = {"status": "confirmed", "reason": "read src/index.ts:3"}
        (out / "findings.json").write_text(json.dumps(d))
        cp = _util.run_cli(["render", str(out / "findings.json")])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        md = (out / "report.md").read_text()
        self.assertTrue(md.startswith("# Cloudflare bill-risk handoff\n"))
        must = md.split("## Must fix (alarms) (1)", 1)[1].split("\n## ", 1)[0]
        check_item(self, d["findings"][0], sections_by_id(must)["f001"])
        # the review decision moves the finding: dismissed, it leaves the must-fix list and keeps its reason
        d["findings"][0]["review"] = {"status": "false-positive", "reason": "only serves /favicon.ico"}
        (out / "findings.json").write_text(json.dumps(d))
        cp = _util.run_cli(["render", str(out / "findings.json")])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        md = (out / "report.md").read_text()
        self.assertIn("## Must fix (alarms) (0)", md)
        dismissed = md.split("## Dismissed by review (1)", 1)[1].split("\n## ", 1)[0]
        self.assertRegex(plain(dismissed), r"- `f001` `CF-CATCHALL-COMPUTE` .*only serves /favicon.ico")


LABELS = ["report (html):", "report (md, give to agents):", "findings (edit, then render):"]


class CliTail(unittest.TestCase):
    def check_tail(self, stdout: str, counts_word: str) -> list[Path]:
        lines = stdout.rstrip("\n").split("\n")
        tail, before = lines[-3:], lines[:-3]
        self.assertTrue(before and counts_word in before[-1], lines)
        paths = []
        col = {len(l) - len(l.split(":", 1)[1].lstrip()) for l in tail}
        self.assertEqual(len(col), 1, f"paths not aligned: {tail}")
        for label, line in zip(LABELS, tail):
            self.assertTrue(line.startswith(label), (label, line))
            p = Path(line[len(label):].strip())
            self.assertTrue(p.is_absolute() and p.is_file(), p)
            paths.append(p)
        self.assertEqual([p.name for p in paths], ["report.html", "report.md", "findings.json"])
        return paths

    def test_scan_ends_with_the_paths(self):
        proj = copy_fixture("itty_open_ai")
        out = Path(tempfile.mkdtemp(prefix="nobill-tail-"))
        _, cp = scan(proj, out=out)
        paths = self.check_tail(cp.stdout, "scan finding(s) marked needs-review")
        self.assertTrue(all(str(p).startswith(str(out.resolve())) for p in paths))

    def test_render_ends_with_the_paths(self):
        proj = copy_fixture("clean")
        out = Path(tempfile.mkdtemp(prefix="nobill-tail-"))
        scan(proj, out=out)
        cp = _util.run_cli(["render", str(out / "findings.json")])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.check_tail(cp.stdout, "dismissed")


if __name__ == "__main__":
    unittest.main()
