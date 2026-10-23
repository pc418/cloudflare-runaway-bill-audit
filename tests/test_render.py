"""Findings schema validation, HTML escaping, and the scan -> agent edit -> render flow."""

import copy
import html
import json
import re
import tempfile
import unittest
from pathlib import Path

import _util
from _util import copy_fixture, scan
from nobill.findings import SCHEMA_ID, validate_document
from nobill.render import render

HOSTILE = '<script>alert("x")</script><img src=x onerror=alert(1)> " onmouseover="alert(2)'


def minimal_doc():
    return {
        "schema": SCHEMA_ID, "tool": {"name": "t", "version": "0"}, "generated_at": "2026-10-13T00:00:00+00:00",
        "project": "/p", "providers": ["cloudflare"], "options": {}, "scope_requirements": [],
        "provider_info": {}, "paid_work_inventory": [],
        "incidents": {"moltbot": {"title": "Catch-all started containers", "provider": "Cloudflare", "url": ""}},
        "findings": [{
            "id": "f001", "rule": "CF-CATCHALL-COMPUTE", "provider": "cloudflare", "class": "C5", "severity": "alarm",
            "title": "Catch-all", "target": "w", "confidence": "heuristic", "source": "code",
            "evidence": [{"kind": "file", "file": "src/index.ts", "line": 3, "snippet": "app.all('*')"}],
            "why": {"text": "why", "incidents": ["moltbot"]},
            "fix": {"text": "fix", "docs": [{"title": "d", "url": "https://developers.cloudflare.com/x/"}]},
            "review": {"status": "needs-review", "reason": ""},
        }],
    }


class Validation(unittest.TestCase):
    def test_minimal_is_valid(self):
        self.assertEqual(validate_document(minimal_doc()), [])

    def test_rejections(self):
        cases = {
            "severity": lambda f: f.update(severity="critical"),
            "missing": lambda f: f.update(severity="unknown"),
            "false-positive": lambda f: f.update(review={"status": "false-positive", "reason": " "}),
            "url": lambda f: f["fix"]["docs"].append({"title": "x", "url": "javascript:alert(1)"}),
            "evidence": lambda f: f.update(evidence=[]),
            "incident": lambda f: f["why"]["incidents"].append("not-an-id"),
            "line": lambda f: f["evidence"].append({"kind": "file", "file": "a.ts", "line": "3"}),
        }
        for name, mutate in cases.items():
            d = minimal_doc()
            mutate(d["findings"][0])
            self.assertTrue(validate_document(d), name)
        d = minimal_doc()
        d["findings"].append(copy.deepcopy(d["findings"][0]))
        self.assertTrue(any("duplicate" in p for p in validate_document(d)))


class Escaping(unittest.TestCase):
    def test_hostile_text_is_escaped_everywhere(self):
        d = minimal_doc()
        f = d["findings"][0]
        f["title"] = HOSTILE
        f["target"] = HOSTILE
        f["evidence"].append({"kind": "file", "file": HOSTILE, "line": 1, "snippet": HOSTILE})
        f["evidence"].append({"kind": "api", "endpoint": HOSTILE, "field": HOSTILE, "value": HOSTILE})
        f["evidence"].append({"kind": "note", "text": HOSTILE})
        f["review"] = {"status": "confirmed", "reason": HOSTILE}
        f["details"] = {"columns": ["a"], "rows": [{"a": HOSTILE}], "note": HOSTILE}
        d["project"] = HOSTILE
        d["paid_work_inventory"] = [{"method": HOSTILE, "path": HOSTILE, "file": HOSTILE, "line": 1,
                                     "paid_work": [HOSTILE], "guard_signals": {}, "review": HOSTILE}]
        d["scope_requirements"] = [{"provider": "cloudflare", "check": HOSTILE, "endpoint": HOSTILE,
                                    "permission": HOSTILE, "status": HOSTILE, "detail": HOSTILE}]
        out = render(d)
        self.assertNotIn("<script", out.lower())
        self.assertNotIn("<img", out.lower())
        self.assertNotIn('" onmouseover="', out)
        self.assertIn("&lt;script&gt;", out)

    def test_every_supplied_field_is_rendered_escaped(self):
        """A renderer that drops a field must fail: each field carries its own hostile marker."""
        def m(name):
            return f'<i data-f="{name}">{name}</i>'
        d = minimal_doc()
        f = d["findings"][0]
        f.update(title=m("title"), target=m("target"), **{"class": "C5"})
        f["why"] = {"text": m("why"), "incidents": ["moltbot", "https://example.com/" + "inc"]}
        f["fix"] = {"text": m("fix"), "docs": [{"title": m("doctitle"), "url": "https://developers.cloudflare.com/x/"}]}
        f["evidence"] = [{"kind": "file", "file": m("file"), "line": 7, "snippet": m("snippet")},
                         {"kind": "api", "endpoint": m("endpoint"), "field": m("field"), "value": m("value")},
                         {"kind": "note", "text": m("note")}]
        f["review"] = {"status": "confirmed", "reason": m("reason"), "original_severity": "suggestion"}
        f["details"] = {"columns": [m("col")], "rows": [{m("col"): m("cell")}], "note": m("detailnote")}
        unk = copy.deepcopy(f)
        unk.update(id="f002", severity="unknown", source="api", missing=m("missing") + " needs token", title=m("unktitle"))
        passed = copy.deepcopy(f)
        passed.update(id="f003", severity="pass", title=m("passtitle"), target=m("passtarget"))
        passed["review"] = {"status": "confirmed", "reason": m("passreason")}
        dismissed = copy.deepcopy(f)
        dismissed.update(id="f004", title=m("fptitle"))
        dismissed["review"] = {"status": "false-positive", "reason": m("fpreason")}
        d["findings"] += [unk, passed, dismissed]
        d["incidents"]["moltbot"]["title"] = m("incident")
        d["project"] = m("project")
        d["generated_at"] = m("generated")
        d["paid_work_inventory"] = [{"method": m("method"), "path": m("path"), "file": m("invfile"), "line": 3,
                                     "paid_work": [m("paidwork")], "guard_signals": {m("signal"): ["x"]},
                                     "review": m("invreview")}]
        d["scope_requirements"] = [{"provider": m("provider"), "check": m("check"), "endpoint": m("scopeendpoint"),
                                    "permission": m("permission"), "status": m("status"), "detail": m("detail")}]
        d["provider_info"] = {"cloudflare": {"token_instructions": m("tokeninstr"), "oauth_note": m("oauth"),
                                             "limits": [m("limit")],
                                             "account": {"auth": m("auth"), "auth_problems": [m("authproblem")]},
                                             "source_context": {"configs": [m("srcconfig")], "entries": [
                                                 {"worker": m("srcworker"), "env": m("srcenv"), "kind": m("srckind"),
                                                  "path": m("srcpath"), "exists": False}],
                                                 "source_identity": {"vcs": "none", "head": None, "dirty": None,
                                                                     "detail": m("srcdetail")}}}}
        d["paid_work_inventory"][0]["worker"] = m("invworker")
        d.update(audit_status="reviewed", review_summary=m("summary"))
        out = render(d)
        self.assertNotIn("<i data-f", out)
        markers = ["srcconfig", "srcworker", "srcenv", "srckind", "srcpath", "srcdetail", "invworker", "summary","title", "target", "why", "fix", "doctitle", "file", "snippet", "endpoint", "field", "value", "note",
                   "reason", "col", "cell", "detailnote", "missing", "unktitle", "passtitle", "passtarget", "passreason",
                   "fptitle", "fpreason", "incident", "project", "generated", "method", "path", "invfile", "paidwork",
                   "signal", "invreview", "provider", "check", "scopeendpoint", "permission", "status", "detail",
                   "tokeninstr", "oauth", "limit", "auth", "authproblem"]
        missing = [k for k in markers if html.escape(m(k), quote=True) not in out]
        self.assertEqual(missing, [])

    def test_header_links_the_agent_handoff(self):
        out = render(minimal_doc())
        head = out.split('<h2 id="alarm"', 1)[0]
        self.assertIn('href="report.md"', head)
        self.assertIn("agent", head.lower())
        tmp = Path(tempfile.mkdtemp())
        (tmp / "findings.json").write_text(json.dumps(minimal_doc()))
        cp = _util.run_cli(["render", str(tmp / "findings.json"), "--out", str(tmp / "my report.html")])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn('href="my%20report.md"', (tmp / "my report.html").read_text())
        self.assertTrue((tmp / "my report.md").is_file())

    def test_unsafe_incident_url_is_not_a_link(self):
        d = minimal_doc()
        d["incidents"]["moltbot"]["url"] = "javascript:alert(1)"
        self.assertNotIn("javascript:", render(d))

    def test_self_contained(self):
        out = render(minimal_doc())
        self.assertIsNone(re.search(r"<script|<link|@import|\bsrc=|url\(", out, re.I))
        self.assertIn("prefers-color-scheme: dark", out)
        self.assertIn('name="viewport"', out)


class AgentReviewFlow(unittest.TestCase):
    def test_edit_then_render(self):
        proj = copy_fixture("itty_open_ai")
        out = Path(tempfile.mkdtemp(prefix="nobill-review-"))
        doc, _ = scan(proj, out=out)
        html = (out / "report.html").read_text()
        order = [html.index(f'id="{s}"') for s in ("alarm", "suggestion", "unknown", "pass", "scope", "inventory", "incidents")]
        self.assertEqual(order, sorted(order))

        # the reviewer dismisses one config suggestion, confirms the rest, adds a judgment finding
        sugg = [f for f in doc["findings"] if f["severity"] == "suggestion"]
        sugg[0]["review"] = {"status": "false-positive", "reason": "guarded by a WAF rule (docs/waf.md:12)"}
        for f in sugg[1:]:
            f["review"] = {"status": "confirmed", "reason": "read the handler"}
        doc["findings"].append({
            "id": "a001", "rule": "AGENT-QUOTA", "provider": "cloudflare", "class": "C3", "severity": "alarm",
            "title": "POST /api/describe has no per-user quota", "target": "snapshot-api",
            "confidence": "certain", "source": "agent",
            "evidence": [{"kind": "file", "file": "src/index.js", "line": 19, "snippet": "router.post('/api/describe'"}],
            "why": {"text": "anyone can loop it", "incidents": ["cloudflare-36k"]},
            "fix": {"text": "add a quota", "docs": [{"title": "Rate Limiting", "url": "https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/"}]},
            "review": {"status": "confirmed", "reason": "agent judgment"},
        })
        (out / "findings.json").write_text(json.dumps(doc))
        cp = _util.run_cli(["render", str(out / "findings.json")])
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("dismissed 1", cp.stdout)
        html = (out / "report.html").read_text()
        self.assertIn("POST /api/describe has no per-user quota", html)
        self.assertIn("guarded by a WAF rule", html)

    def test_render_refuses_invalid_json(self):
        out = Path(tempfile.mkdtemp())
        d = minimal_doc()
        d["findings"][0]["severity"] = "unknown"  # no 'missing'
        (out / "findings.json").write_text(json.dumps(d))
        cp = _util.run_cli(["render", str(out / "findings.json")])
        self.assertEqual(cp.returncode, 2)
        self.assertIn("missing permission or reason", cp.stderr)
        self.assertFalse((out / "report.html").exists())


if __name__ == "__main__":
    unittest.main()
