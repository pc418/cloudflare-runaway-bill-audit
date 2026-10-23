"""Composition cases: malformed rows and fields beside valid ones keep stable identities and every
diagnostic. PIN: owner 2026-10-20 (docs/261020-refactor-AGENT_LED_BILLING_AUDIT.md) and the sol review
of the lead's pass (plan.md 2026-10-21): invalid is never absent, never a default, never a crash."""

import json
import unittest

import _util
from test_config_scope import cfg, document


class RowIdentity(unittest.TestCase):
    def test_a_null_row_before_a_row_with_a_bad_name_keeps_indices_and_does_not_crash(self):
        doc = document('"containers":[null,{"class_name":["bad"],"max_instances":5}]')
        maxi = cfg(doc, "CF-CONTAINER-MAX-INSTANCES")
        self.assertEqual(sorted((f["severity"], f["target"]) for f in maxi),
                         [("pass", "w (wrangler.json) / containers[1]"), ("unknown", "w (wrangler.json) / containers[0]")], maxi)
        unreadable = cfg(doc, "CF-CONFIG-UNREADABLE")
        self.assertEqual([f["target"] for f in unreadable], ["w (wrangler.json) / containers[1]"], unreadable)
        self.assertIn('containers[1].class_name is not', unreadable[0]["missing"])
        self.assertIn('["bad"]', unreadable[0]["missing"])
        self.assertNotIn("/ container\"", json.dumps(doc))

    def test_a_blank_class_name_never_labels_a_row_container(self):
        doc = document('"containers":[{"class_name":"","max_instances":5}]')
        self.assertEqual([(f["severity"], f["target"]) for f in cfg(doc, "CF-CONTAINER-MAX-INSTANCES")],
                         [("pass", "w (wrangler.json) / containers[0]")])
        self.assertIn('("")', cfg(doc, "CF-CONFIG-UNREADABLE")[0]["missing"])
        self.assertNotIn("/ container\"", json.dumps(doc))

    def test_a_consumer_with_an_unreadable_queue_name_keeps_its_retry_facts(self):
        doc = document('"queues":{"consumers":[{"queue":[],"max_retries":3,"dead_letter_queue":"dlq"}]}')
        bounds = cfg(doc, "CF-QUEUE-CONSUMER-BOUNDS")
        self.assertEqual([(f["severity"], f["target"]) for f in bounds],
                         [("pass", "w (wrangler.json) / queues.consumers[0]")], bounds)
        self.assertIn("queues.consumers[0].queue", cfg(doc, "CF-CONFIG-UNREADABLE")[0]["missing"])


    def test_dead_letter_membership_uses_the_validated_name_not_the_label(self):
        doc = document('"ai":{"binding":"AI"},"queues":{"consumers":[{"queue":"jobs","max_retries":3,"dead_letter_queue":"dlq"},'
                       '{"queue":"dlq","max_retries":3}]}')
        self.assertEqual([f["target"] for f in cfg(doc, "CF-QUEUE-CONCURRENCY")], ["w (wrangler.json) / queue jobs"])
        bounds = {f["target"]: f["title"] for f in cfg(doc, "CF-QUEUE-CONSUMER-BOUNDS")}
        self.assertIn("Dead-letter queue consumer", bounds["w (wrangler.json) / queue dlq"])
        self.assertEqual(sorted(bounds), ["w (wrangler.json) / queue dlq", "w (wrangler.json) / queue jobs"])

    def test_a_malformed_queue_name_does_not_abort_the_live_scan(self):
        import tempfile
        from pathlib import Path
        import test_account as account_tests
        from _util import FakeCloudflare, scan, temp_home
        root = Path(tempfile.mkdtemp(prefix="nobill-live-queue-"))
        (root / "index.js").write_text('export default {fetch() {return new Response("ok")}}')
        (root / "wrangler.json").write_text('{"name":"w","main":"index.js","queues":{"consumers":[{"queue":[],"max_retries":3,"dead_letter_queue":"dlq"}]},'
                                            '"containers":[{"class_name":"Box","name":{},"max_instances":2}],'
                                            '"kv_namespaces":[{"name":[]}],"assets":{"directory":"public\\u0000bad"}}')
        with FakeCloudflare(account_tests.granted_routes()) as fake:
            env = {"HOME": str(temp_home()), "NOBILL_CLOUDFLARE_API_BASE": fake.base,
                   "CLOUDFLARE_ACCOUNT_ID": account_tests.ACCT, "CLOUDFLARE_API_TOKEN": account_tests.TOKEN}
            doc, cp = scan(root, extra=["--account"], env=env)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual([(f["severity"], f["target"]) for f in cfg(doc, "CF-QUEUE-CONSUMER-BOUNDS")],
                         [("pass", "w (wrangler.json) / queues.consumers[0]")])
        self.assertTrue(any(f["source"] == "api" for f in doc["findings"]))
        drift = [f for f in doc["findings"] if f["rule"] == "CF-CONFIG-DRIFT" and f["source"] == "api"]
        self.assertEqual(len(drift), 1, drift)  # a kv row whose name is a list is not a binding and not a crash
        kinds = [e["kind"] for e in doc["provider_info"]["cloudflare"]["source_context"]["entries"]]
        self.assertNotIn("assets", kinds)  # the malformed directory is reported by CF-RUN-WORKER-FIRST, not listed
        self.assertEqual([f["severity"] for f in cfg(doc, "CF-RUN-WORKER-FIRST")], ["unknown"])


    def test_a_binding_row_without_its_name_field_is_diagnosed_not_filtered(self):
        import tempfile
        from pathlib import Path
        import test_account as account_tests
        from _util import FakeCloudflare, scan, temp_home
        root = Path(tempfile.mkdtemp(prefix="nobill-drift-"))
        (root / "index.js").write_text('export default {fetch() {return new Response("ok")}}')
        (root / "wrangler.json").write_text('{"name":"snapshot-api","main":"index.js","ai":{"binding":"AI"},"kv_namespaces":[{"name":[]}]}')
        with FakeCloudflare(account_tests.granted_routes()) as fake:
            env = {"HOME": str(temp_home()), "NOBILL_CLOUDFLARE_API_BASE": fake.base,
                   "CLOUDFLARE_ACCOUNT_ID": account_tests.ACCT, "CLOUDFLARE_API_TOKEN": account_tests.TOKEN}
            doc, cp = scan(root, extra=["--account"], env=env)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        drift = [f for f in doc["findings"] if f["rule"] == "CF-CONFIG-DRIFT" and f["source"] == "api"]
        self.assertEqual([f["severity"] for f in drift], ["unknown"], drift)
        unreadable = cfg(doc, "CF-CONFIG-UNREADABLE")
        self.assertEqual([f["severity"] for f in unreadable], ["unknown"], unreadable)
        self.assertIn("kv_namespaces[0].binding is not declared", unreadable[0]["missing"])


class InvalidIsNotAbsent(unittest.TestCase):
    def test_a_malformed_binding_name_never_becomes_the_default_binding(self):
        doc = document('"ai":{"binding":null},"workers_dev":false')
        found = cfg(doc, "CF-WORKERS-DEV-ON")
        self.assertEqual([f["severity"] for f in found], ["unknown"], found)
        self.assertIn("ai.binding", found[0]["missing"])
        rows = [r for f in cfg(doc, "CF-COST-INVENTORY") for r in f["details"]["rows"]]
        self.assertNotIn("Workers AI", [r["binding"] for r in rows])
        self.assertNotIn('"AI"', json.dumps(rows))

    def test_two_malformed_settings_under_one_rule_keep_both_diagnostics(self):
        doc = document('"ai":{"binding":"AI"},"workers_dev":"yes","preview_urls":"no"')
        found = cfg(doc, "CF-WORKERS-DEV-ON")
        self.assertEqual([f["severity"] for f in found], ["unknown"], found)
        self.assertIn('workers_dev is not a boolean ("yes")', found[0]["missing"])
        self.assertIn('preview_urls is not a boolean ("no")', found[0]["missing"])


if __name__ == "__main__":
    unittest.main()
