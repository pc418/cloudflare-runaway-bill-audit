"""A malformed config field invalidates only its own conclusion; valid siblings keep theirs.
PIN: owner 2026-10-20 (docs/261020-refactor-AGENT_LED_BILLING_AUDIT.md): malformed means unknown,
never pass, never silence; the advisor decision of 2026-10-21 (plan.md): field- or row-scoped, never section-wide."""

import tempfile
import unittest
from pathlib import Path

import _util
from _util import by_rule, scan


def document(fragment: str) -> dict:
    root = Path(tempfile.mkdtemp(prefix="nobill-scope-"))
    (root / "index.js").write_text('export default {fetch() {return new Response("ok")}}')
    (root / "wrangler.json").write_text('{"name":"w","main":"index.js",' + fragment + '}')
    return scan(root)[0]


def cfg(doc, rule):
    return [f for f in by_rule(doc, rule) if f["source"] == "config"]


class ContainerRows(unittest.TestCase):
    def test_a_custom_instance_size_table_is_valid(self):
        doc = document('"durable_objects":{"bindings":[{"name":"BOX","class_name":"Box"}]},'
                       '"containers":[{"class_name":"Box","max_instances":5,"instance_type":{"vcpu":1,"memory_mib":4096,"disk_mb":8000}}]')
        self.assertEqual(cfg(doc, "CF-CONTAINER-SIZE"), [])
        self.assertEqual([(f["severity"], f["target"]) for f in cfg(doc, "CF-CONTAINER-MAX-INSTANCES")],
                         [("pass", "w (wrangler.json) / Box")])
        self.assertEqual([f["severity"] for f in cfg(doc, "CF-WORKERS-DEV-ON")], ["suggestion"])
        rows = cfg(doc, "CF-COST-INVENTORY")[0]["details"]["rows"]
        self.assertIn("Containers", [r["binding"] for r in rows])

    def test_a_large_named_size_is_still_a_suggestion(self):
        doc = document('"containers":[{"class_name":"Box","max_instances":5,"instance_type":"standard-4"}]')
        self.assertEqual([f["severity"] for f in cfg(doc, "CF-CONTAINER-SIZE")], ["suggestion"])

    def test_a_bad_size_on_one_row_leaves_both_rows_max_instances(self):
        doc = document('"containers":[{"class_name":"A","max_instances":5,"instance_type":[]},'
                       '{"class_name":"B","max_instances":2}]')
        self.assertEqual(sorted((f["severity"], f["target"]) for f in cfg(doc, "CF-CONTAINER-MAX-INSTANCES")),
                         [("pass", "w (wrangler.json) / A"), ("pass", "w (wrangler.json) / B")])
        size = cfg(doc, "CF-CONTAINER-SIZE")
        self.assertEqual([(f["severity"], f["target"]) for f in size], [("unknown", "w (wrangler.json) / A")])
        self.assertIn("[]", size[0]["missing"])
        self.assertEqual(len(cfg(doc, "CF-COST-INVENTORY")), 1)

    def test_a_bad_max_instances_never_becomes_the_default(self):
        doc = document('"containers":[{"class_name":"A","max_instances":"5"}]')
        found = cfg(doc, "CF-CONTAINER-MAX-INSTANCES")
        self.assertEqual([f["severity"] for f in found], ["unknown"], found)
        self.assertIn('"5"', found[0]["missing"])


class QueueRows(unittest.TestCase):
    def test_a_bad_producer_does_not_silence_a_valid_consumer(self):
        doc = document('"ai":{"binding":"AI"},"queues":{"producers":[{"binding":5,"queue":"jobs"}],'
                       '"consumers":[{"queue":"jobs","max_retries":3,"dead_letter_queue":"dlq"}]}')
        self.assertEqual([(f["severity"], f["target"]) for f in cfg(doc, "CF-QUEUE-CONSUMER-BOUNDS")],
                         [("pass", "w (wrangler.json) / queue jobs")])
        self.assertEqual([f["severity"] for f in cfg(doc, "CF-QUEUE-CONCURRENCY")], ["suggestion"])
        unreadable = cfg(doc, "CF-CONFIG-UNREADABLE")
        self.assertEqual([f["severity"] for f in unreadable], ["unknown"], unreadable)
        self.assertIn("producers[0].binding", unreadable[0]["missing"])

    def test_a_bad_consumer_row_leaves_the_other_consumer(self):
        doc = document('"queues":{"consumers":[null,{"queue":"jobs","max_retries":3,"dead_letter_queue":"dlq"}]}')
        found = cfg(doc, "CF-QUEUE-CONSUMER-BOUNDS")
        self.assertEqual(sorted(f["severity"] for f in found), ["pass", "unknown"], found)


class PaidBindingCompleteness(unittest.TestCase):
    def test_no_known_paid_binding_plus_an_unreadable_one_is_unknown_not_silence(self):
        doc = document('"ai":null')
        for rule in ("CF-WORKERS-DEV-ON", "CF-NO-RATELIMIT-BINDING"):
            found = cfg(doc, rule)
            self.assertEqual([f["severity"] for f in found], ["unknown"], (rule, found))
            self.assertIn("ai", found[0]["missing"])

    def test_a_known_paid_binding_keeps_its_checks_with_a_completeness_note(self):
        doc = document('"ai":null,"browser":{"binding":"B"}')
        found = cfg(doc, "CF-WORKERS-DEV-ON")
        self.assertEqual([f["severity"] for f in found], ["suggestion"], found)
        self.assertTrue(any("incomplete" in e.get("text", "") for e in found[0]["evidence"]), found[0]["evidence"])
        self.assertEqual([f["severity"] for f in cfg(doc, "CF-NO-RATELIMIT-BINDING")], ["suggestion"])


if __name__ == "__main__":
    unittest.main()
