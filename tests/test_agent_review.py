"""The scan -> agent audit -> render handoff: audit status, review summary and the agent's inventory.

PIN (owner 2026-10-20, "I don't want a static analyser but a skill for agents to know where to look at";
docs/261020-refactor-AGENT_LED_BILLING_AUDIT.md section 6): a scan is preparation, not an audit. It writes
audit_status "unreviewed" and stays visibly unreviewed in the CLI and both reports, whatever its findings;
only the agent sets "reviewed" (with a non-empty review_summary); render never promotes the status; a
document without the field renders as "audit status not recorded".
"""

import copy
import html
import json
import re
import tempfile
import unittest
from pathlib import Path

import _util
from _util import copy_fixture, scan
from nobill.findings import validate_document
from nobill.markdown import render_md
from nobill.render import render

UNREVIEWED = "UNREVIEWED: raw scan"
REVIEWED = "Reviewed by an agent"
NOT_RECORDED = "Audit status not recorded"

WHY = ("Any visitor can POST /api/describe and each call runs a vision model on the uploaded image. "
       "The only limiter runs after the model call, so a burst is billed before it is rejected. "
       "Decisive condition: the quota debit happens after env.AI.run returns.")
SUMMARY = ("Inspected: Worker snapshot-api (src/index.js), the queue consumer and the browser screenshot path.\n"
           "C1 repetition: no self-enqueue; C3 open paid endpoints: POST /api/describe exposed (a001).\n"
           "Remaining gaps: the iOS client was not available to read (a003).")


def section(md: str, heading: str) -> str:
    return md.split(heading, 1)[1].split("\n## ", 1)[0]


class RawScan(unittest.TestCase):
    """A scan with no source findings is unreviewed, and an empty inventory is not a pass."""

    @classmethod
    def setUpClass(cls):
        cls.out = Path(tempfile.mkdtemp(prefix="nobill-raw-"))
        cls.doc, cls.cp = scan(copy_fixture("clean"), out=cls.out)
        cls.html = (cls.out / "report.html").read_text()
        cls.md = (cls.out / "report.md").read_text()

    def test_scan_writes_unreviewed_and_an_empty_summary(self):
        self.assertEqual((self.doc["audit_status"], self.doc["review_summary"]), ("unreviewed", ""))
        self.assertEqual(self.doc["paid_work_inventory"], [])
        self.assertEqual(validate_document(self.doc), [])

    def test_unreviewed_is_visible_in_cli_html_and_markdown(self):
        # the clean fixture has no alarm: the status, not the counts, says the audit has not happened
        self.assertFalse([f for f in self.doc["findings"] if f["severity"] == "alarm"])
        self.assertIn("audit status: " + UNREVIEWED, self.cp.stdout)
        head = self.html.split('<h2 id="alarm"', 1)[0]
        self.assertIn(UNREVIEWED, head)
        self.assertIn('class="status unreviewed"', head)
        self.assertIn(UNREVIEWED, self.md.split("## Must fix", 1)[0])
        self.assertNotIn("all heuristic findings reviewed", self.html + self.md)

    def test_empty_inventory_is_not_a_pass(self):
        inv_html = self.html.split('<h2 id="inventory"', 1)[1].split("<h2", 1)[0]
        self.assertIn("An empty inventory is not a pass", inv_html)
        self.assertIn("An empty inventory is not a pass", section(self.md, "## Paid-work inventory (0)"))

    def test_reports_make_no_code_analysis_claim(self):
        for name, blob in (("html", self.html), ("md", self.md), ("stdout", self.cp.stdout)):
            self.assertNotRegex(blob.lower(), r"traced every route|code analysis|routes the scanner traced|"
                                              r"every route the scanner", name)
        self.assertNotIn("code,", re.search(r"- Layers: (.*)", self.md).group(1))
        lim = " ".join(self.doc["provider_info"]["cloudflare"]["limits"])
        self.assertIn("does not read or trace application source", lim)

    def test_source_context_is_in_both_reports(self):
        self.assertIn('id="source"', self.html)
        self.assertIn("not verified deployments", self.html)
        src = section(self.md, "## Source context (cloudflare)")
        self.assertIn("src/index.ts", src)
        self.assertIn("Source identity:", src)


def agent_edited(doc: dict) -> dict:
    """An agent's audit of the itty fixture: traced inventory (HTTP and queue rows), a concrete risk,
    a dismissed scanner candidate, a scoped pass, an unresolved question, status and summary."""
    d = copy.deepcopy(doc)
    d["audit_status"] = "reviewed"
    d["review_summary"] = SUMMARY
    d["paid_work_inventory"] = [
        {"worker": "snapshot-api", "file": "src/index.js", "line": 19, "method": "POST", "path": "/api/describe",
         "paid_work": ["Workers AI"], "review": "audience: anonymous; rate: none before the model call; "
         "cumulative budget: none; per-request work: one vision call per upload (src/index.js:24)"},
        {"worker": "snapshot-api", "file": "src/queue.js", "line": 7, "method": "queue", "path": "JOBS consumer",
         "paid_work": ["Browser Run"], "review": "audience: internal producer only; rate: max_concurrency 2; "
         "cumulative budget: n/a; per-request work: one screenshot per message, retries bounded at 3"},
    ]
    candidate = next(f for f in d["findings"] if f["review"]["status"] == "needs-review")
    candidate["review"] = {"status": "false-positive",
                           "reason": "asset requests return from env.ASSETS.fetch before any browser launch "
                                     "(src/index.js:8-11)"}
    d["findings"] += [
        {"id": "a001", "rule": "AGENT-OPEN-VISION", "provider": "cloudflare", "class": "C3", "severity": "alarm",
         "title": "POST /api/describe runs a vision model for anonymous callers before any limit",
         "target": "snapshot-api", "confidence": "certain", "source": "agent",
         "evidence": [{"kind": "file", "file": "src/index.js", "line": 24, "snippet": "await env.AI.run(model, { image })"}],
         "why": {"text": WHY, "incidents": ["vercel-23k", "posthog-devin-1273"]},
         "fix": {"text": "Reserve the per-user quota before env.AI.run and reject when exhausted.",
                 "docs": [{"title": "Rate Limiting", "url": "https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/"}]},
         "review": {"status": "confirmed", "reason": "traced from the route to the sink"}},
        {"id": "a002", "rule": "AGENT-QUEUE-RETRIES", "provider": "cloudflare", "class": "C1", "severity": "pass",
         "title": "JOBS consumer: one screenshot per message, failures retried at most 3 times", "target": "snapshot-api",
         "confidence": "certain", "source": "agent",
         "evidence": [{"kind": "file", "file": "src/queue.js", "line": 7, "snippet": "for (const m of batch.messages)"}],
         "why": {"text": "Scope: this consumer only; no send() back to JOBS on any branch.", "incidents": []},
         "fix": {"text": "None needed.", "docs": []},
         "review": {"status": "confirmed", "reason": "read every branch of src/queue.js"}},
        {"id": "a003", "rule": "AGENT-CLIENT-UNREAD", "provider": "cloudflare", "class": "C7", "severity": "unknown",
         "title": "iOS client upload retry behaviour not examined", "target": "ios app",
         "confidence": "certain", "source": "agent", "missing": "the iOS client source is not in this checkout",
         "evidence": [{"kind": "note", "text": "README links an App Store build that calls /api/describe"}],
         "why": {"text": "Client retries after partial success can repeat the paid call.", "incidents": []},
         "fix": {"text": "Read the client's upload retry loop.", "docs": []},
         "review": {"status": "confirmed", "reason": "remaining gap"}},
    ]
    return d


class AgentEditedFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = Path(tempfile.mkdtemp(prefix="nobill-rev-"))
        raw, _ = scan(copy_fixture("itty_open_ai"), out=cls.out)
        cls.doc = agent_edited(raw)
        (cls.out / "findings.json").write_text(json.dumps(cls.doc, indent=2))
        cls.cp = _util.run_cli(["render", str(cls.out / "findings.json")])
        cls.html = (cls.out / "report.html").read_text()
        cls.md = (cls.out / "report.md").read_text()

    def test_renders_and_keeps_the_agents_status(self):
        self.assertEqual(self.cp.returncode, 0, self.cp.stderr)
        self.assertIn("audit status: " + REVIEWED, self.cp.stdout)
        self.assertIn("dismissed 1", self.cp.stdout)
        self.assertIn(REVIEWED, self.html.split('<h2 id="alarm"', 1)[0])
        self.assertIn(REVIEWED, self.md.split("## Must fix", 1)[0])
        self.assertEqual(json.loads((self.out / "findings.json").read_text()), self.doc)  # render edits nothing

    def test_summary_in_both_formats(self):
        summary_html = self.html.split('<h2 id="summary"', 1)[1].split("<h2", 1)[0]
        summary_md = section(self.md, "## Review summary")
        for line in SUMMARY.splitlines():
            self.assertIn(html.escape(line, quote=True), summary_html)
            self.assertIn(f"- {line}", summary_md)

    def test_inventory_rows_with_control_labels_and_a_non_http_trigger(self):
        inv_html = self.html.split('<h2 id="inventory"', 1)[1].split("<h2", 1)[0]
        inv_md = section(self.md, "## Paid-work inventory (2)")
        for blob in (inv_html, inv_md):
            self.assertIn("POST /api/describe", blob)
            self.assertIn("queue JOBS consumer", blob)
            self.assertIn("Browser Run", blob)
            for label in ("audience:", "rate:", "cumulative budget:", "per-request work:"):
                self.assertIn(label, blob)
        self.assertIn("src/queue.js:7", inv_md)

    def test_concrete_risk_keeps_its_full_why(self):
        alarms = section(self.md, "## Must fix (alarms) (1)")
        self.assertIn("a001", alarms)
        self.assertIn("Decisive condition: the quota debit happens after env.AI.run returns.", alarms)
        self.assertIn("Decisive condition: the quota debit happens after env.AI.run returns.", self.html)
        self.assertIn("posthog-devin-1273", alarms)  # any catalogue anchor, not only retained rules' ids

    def test_dismissed_candidate_scoped_pass_and_unresolved_question(self):
        dismissed = section(self.md, "## Dismissed by review (1)")
        self.assertIn("before any browser launch", dismissed)
        self.assertIn("before any browser launch", self.html)
        passed = section(self.md, "## Passed")
        self.assertIn("a002", passed)
        self.assertIn("read every branch of src/queue.js", passed)
        unknowns = section(self.md, "## Unknowns")
        self.assertIn("a003", unknowns)
        self.assertIn("the iOS client source is not in this checkout", unknowns)
        self.assertIn("the iOS client source is not in this checkout", self.html)


class StatusContract(unittest.TestCase):
    def doc(self) -> dict:
        from test_render import minimal_doc
        return minimal_doc()

    def test_validator(self):
        d = self.doc()
        self.assertEqual(validate_document(d), [])  # legacy: no audit keys
        for status, summary, ok in (("unreviewed", "", True), ("reviewed", "Inspected the Worker.", True),
                                    ("reviewed", "", False), ("reviewed", "   ", False), ("reviewed", None, False),
                                    ("done", "x", False), ("Reviewed", "x", False), (None, "", False),
                                    ("unreviewed", 5, False)):
            with self.subTest(status=status, summary=summary):
                d = self.doc()
                d["audit_status"] = status
                if summary is not None:
                    d["review_summary"] = summary
                self.assertEqual(validate_document(d) == [], ok, validate_document(d))

    def test_inventory_rows_are_objects_with_a_string_review(self):
        row = {"worker": "api", "file": "src/index.js", "line": 3, "paid_work": ["Workers AI"],
               "review": "audience: anonymous; rate: none"}
        legacy = {k: v for k, v in row.items() if k != "review"}
        for rows, error in (([row, legacy], None),
                            ([row, "POST /api/describe -> Workers AI"], "paid_work_inventory[1]: expected an object"),
                            ([row, dict(row, review={"audience": "anonymous"})],
                             "paid_work_inventory[1].review: expected a string"),
                            ([dict(row, review=None)], "paid_work_inventory[0].review: expected a string")):
            with self.subTest(rows=rows):
                d = self.doc()
                d["paid_work_inventory"] = rows
                self.assertEqual(validate_document(d), [error] if error else [])

    def test_render_refuses_an_invalid_inventory_row(self):
        out = Path(tempfile.mkdtemp(prefix="nobill-inv-"))
        raw, _ = scan(copy_fixture("clean"), out=out)
        raw["paid_work_inventory"] = [{"worker": "api", "review": {"audience": "anonymous"}}]
        (out / "findings.json").write_text(json.dumps(raw))
        for cmd in ("validate", "render"):
            with self.subTest(cmd=cmd):
                cp = _util.run_cli([cmd, str(out / "findings.json")])
                self.assertEqual(cp.returncode, 2, cp.stdout)
                self.assertIn("paid_work_inventory[0].review: expected a string", cp.stderr)

    def test_legacy_document_renders_as_not_recorded(self):
        d = self.doc()  # source "code" finding, no audit keys
        html, md = render(d), render_md(d)
        self.assertIn(NOT_RECORDED, html.split('<h2 id="alarm"', 1)[0])
        self.assertIn(NOT_RECORDED, md.split("## Must fix", 1)[0])
        for blob in (html, md):
            self.assertNotIn(UNREVIEWED, blob)
            self.assertNotIn(REVIEWED, blob)

    def test_legacy_coverage_card_still_groups_its_checks(self):
        d = self.doc()
        card = copy.deepcopy(d["findings"][0])
        card.update(id="f002", rule="CF-SOURCE-COVERAGE", **{"class": "META"}, severity="unknown", source="code",
                    title="Source coverage incomplete", missing="import './x' does not resolve",
                    evidence=[{"kind": "note", "text": "unresolved import ./x"}])
        waiting = copy.deepcopy(card)
        waiting.update(id="f003", rule="CF-SELF-FETCH", title="Not established: self fetch", coverage_ref="f002",
                       evidence=[{"kind": "note", "text": "needs the unread helper"}])
        d["findings"] += [card, waiting]
        self.assertEqual(validate_document(d), [])
        html, md = render(d), render_md(d)
        self.assertIn("Checks waiting on this coverage (1)", html)
        self.assertIn("Not established: self fetch", section(md, "## Unknowns"))

    def test_render_never_promotes_the_status(self):
        out = Path(tempfile.mkdtemp(prefix="nobill-prom-"))
        raw, _ = scan(copy_fixture("clean"), out=out)
        for f in raw["findings"]:  # even with every finding settled by review
            f["review"] = {"status": "confirmed", "reason": "checked"}
        (out / "findings.json").write_text(json.dumps(raw))
        cp = _util.run_cli(["render", str(out / "findings.json")])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("audit status: " + UNREVIEWED, cp.stdout)
        self.assertEqual(json.loads((out / "findings.json").read_text())["audit_status"], "unreviewed")
        self.assertIn(UNREVIEWED, (out / "report.html").read_text())
        self.assertIn(UNREVIEWED, (out / "report.md").read_text())
        # a reviewed status without a summary is refused, not rendered
        raw["audit_status"] = "reviewed"
        (out / "findings.json").write_text(json.dumps(raw))
        cp = _util.run_cli(["render", str(out / "findings.json")])
        self.assertEqual(cp.returncode, 2)
        self.assertIn("review_summary", cp.stderr)

    def test_reviewed_status_does_not_remove_unknowns(self):
        d = self.doc()
        unk = copy.deepcopy(d["findings"][0])
        unk.update(id="f002", severity="unknown", missing="Notifications Read on the token", source="api",
                   title="Not checked: billing alert")
        d["findings"].append(unk)
        d.update(audit_status="reviewed", review_summary="Inspected the Worker; the alert policy stays unread.")
        md = render_md(d)
        self.assertIn("Not checked: billing alert", section(md, "## Unknowns (1)"))
        self.assertIn("Not checked: billing alert", render(d))


if __name__ == "__main__":
    unittest.main()
