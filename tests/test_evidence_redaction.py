"""Evidence is redacted before it is clipped, and decoder diagnostics never copy the config file."""

import json
import tempfile
import unittest
from pathlib import Path

import _util
from _util import by_rule, scan

TOKEN = "tokSECRETvalue-0123456789abcdefABCDEF"


def project(config: str) -> Path:
    root = Path(tempfile.mkdtemp(prefix="nobill-evidence-"))
    (root / "index.js").write_text('export default {fetch() {return new Response("ok")}}')
    (root / "wrangler.json").write_text(config)
    return root


class EvidenceRedaction(unittest.TestCase):
    def test_a_credential_straddling_the_clip_point_never_reaches_a_snippet(self):
        # The evidence snippet is the config line. Clipping it to 240 characters before redaction
        # keeps the first characters of a credential that straddles the clip point.
        for pad in (140, 150, 160, 170):
            with self.subTest(pad=pad):
                root = project('{"name":"w","main":"index.js","ai":{"binding":"AI"},"workers_dev":"yes",'
                               '"note":"' + "x" * pad + TOKEN + '"}')
                doc, _ = scan(root, env={"CLOUDFLARE_API_TOKEN": TOKEN})
                text = json.dumps(doc)
                self.assertNotIn("tokSEC", text)
                found = [f for f in by_rule(doc, "CF-WORKERS-DEV-ON") if f["source"] == "config"]
                self.assertEqual([f["severity"] for f in found], ["unknown"])
                snippets = [e["snippet"] for e in found[0]["evidence"] if e.get("kind") == "file"]
                self.assertTrue(snippets and all("workers_dev" in sn for sn in snippets), snippets)
                self.assertTrue(any("[REDACTED]" in sn or sn.endswith("…") for sn in snippets), snippets)
                for f in doc["findings"]:
                    for ev in f["evidence"]:
                        for key in ("snippet", "value"):
                            if key in ev:
                                self.assertLessEqual(len(ev[key]), 241, ev)

    def test_a_pages_routes_line_is_redacted_before_it_is_clipped(self):
        for pad in (120, 150, 215, 230):
            with self.subTest(pad=pad):
                root = project('{"name":"w","pages_build_output_dir":"dist","ai":{"binding":"AI"}}')
                (root / "dist").mkdir()
                (root / "dist" / "_routes.json").write_text('{"include": ["/*", "' + "x" * pad + TOKEN + '"]}')
                doc, _ = scan(root, env={"CLOUDFLARE_API_TOKEN": TOKEN})
                self.assertNotIn("tokSEC", json.dumps(doc))
                found = [f for f in by_rule(doc, "CF-RUN-WORKER-FIRST") if f["source"] == "config"]
                self.assertEqual([f["severity"] for f in found], ["suggestion"], found)
                snippet = [e["snippet"] for e in found[0]["evidence"] if e.get("kind") == "file"][0]
                self.assertIn("include", snippet)
                self.assertLessEqual(len(snippet), 241)

    def test_an_undecodable_config_is_not_copied_into_the_diagnostic(self):
        root = project('{"name":"w","main":"index.js","limits":{"cpu_ms":' + "9" * 5000 + '},'
                       '"vars":{"SECRET_SAUCE":"sk_live_abcdef0123456789"}}')
        doc, _ = scan(root)
        found = by_rule(doc, "CF-CONFIG-UNREADABLE")
        self.assertEqual([f["severity"] for f in found], ["unknown"], found)
        self.assertNotIn("sk_live_", json.dumps(doc))
        self.assertLess(len(found[0]["missing"]), 600, found[0]["missing"])
        self.assertIn("ValueError", found[0]["missing"])


if __name__ == "__main__":
    unittest.main()
