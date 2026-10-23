"""Malformed literal config values must survive the complete offline scan as unknowns."""

import tempfile
import unittest
from pathlib import Path

import _util
from _util import by_rule, scan

# More than a finite double can represent, but below Python's integer-string safety limit.
HUGE = ('9999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999'
        '9999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999'
        '9999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999'
        '9999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999')


class ConfigValues(unittest.TestCase):
    def document(self, fragment, fmt="json"):
        with tempfile.TemporaryDirectory(prefix="nobill-values-") as tmp:
            root = Path(tmp)
            (root / "index.js").write_text('export default {fetch() {return new Response("ok")}}')
            text = ('{"name":"w","main":"index.js","ai":{"binding":"AI"},' + fragment + '}') if fmt == "json" else (
                'name = "w"\nmain = "index.js"\n' + fragment)
            (root / ("wrangler." + fmt)).write_text(text)
            return scan(root)[0]

    def unknown(self, fragment, rule, quoted, fmt="json"):
        doc = self.document(fragment, fmt)
        found = [f for f in by_rule(doc, rule) if f["source"] == "config"]
        self.assertEqual([f["severity"] for f in found], ["unknown"], found)
        self.assertIn(quoted, found[0]["missing"])
        self.assertIn("w (wrangler.", found[0]["target"])

    def test_oversized_integers_never_crash_or_certify_settings(self):
        for fragment, rule in [
            ('"limits":{"cpu_ms":' + HUGE + '}', "CF-CPU-LIMIT"),
            ('"limits":{"subrequests":' + HUGE + '}', "CF-SUBREQUESTS-RAISED"),
            ('"containers":[{"class_name":"Sbx","max_instances":' + HUGE + '}]', "CF-CONTAINER-MAX-INSTANCES"),
            ('"queues":{"consumers":[{"queue":"jobs","max_retries":' + HUGE + ',"dead_letter_queue":"dlq"}]}',
             "CF-QUEUE-CONSUMER-BOUNDS"),
        ]:
            with self.subTest(rule=rule):
                self.unknown(fragment, rule, HUGE[:40])

    def test_toml_dates_and_times_are_diagnostic_values_not_crashes(self):
        for literal in ('2026-10-21', '07:32:00', '2026-10-21T07:32:00Z'):
            for fragment, rule in [('limits = ' + literal, "CF-CPU-LIMIT"),
                                   ('[limits]\ncpu_ms = ' + literal, "CF-CPU-LIMIT"),
                                   ('[observability]\nenabled = true\nhead_sampling_rate = ' + literal,
                                    "CF-LOG-SAMPLING")]:
                with self.subTest(fragment=fragment):
                    self.unknown(fragment, rule, literal[:8], "toml")

    def test_null_is_not_an_omitted_setting(self):
        cases = [
            ('"limits":null', "CF-CPU-LIMIT"),
            ('"limits":{"cpu_ms":null}', "CF-CPU-LIMIT"),
            ('"limits":{"cpu_ms":50,"subrequests":null}', "CF-SUBREQUESTS-RAISED"),
            ('"observability":null', "CF-LOG-SAMPLING"),
            ('"observability":{"enabled":true,"logs":null,"head_sampling_rate":0.1}', "CF-LOG-SAMPLING"),
            ('"observability":{"enabled":null}', "CF-LOG-SAMPLING"),
            ('"observability":{"logs":{"enabled":null}}', "CF-LOG-SAMPLING"),
            ('"observability":{"enabled":true,"head_sampling_rate":null}', "CF-LOG-SAMPLING"),
            ('"workers_dev":false,"preview_urls":null', "CF-WORKERS-DEV-ON"),
            ('"workers_dev":null', "CF-WORKERS-DEV-ON"),
            ('"assets":null', "CF-RUN-WORKER-FIRST"),
            ('"assets":{"run_worker_first":null}', "CF-RUN-WORKER-FIRST"),
        ]
        for fragment, rule in cases:
            with self.subTest(fragment=fragment):
                self.unknown(fragment, rule, "null")

    def test_inactive_or_overridden_sampling_values_are_still_validated(self):
        for fragment in ('"observability":{"enabled":false,"head_sampling_rate":"bad"}',
                         '"observability":{"enabled":true,"head_sampling_rate":null,"logs":{"head_sampling_rate":0.1}}',
                         '"observability":{"enabled":false,"logs":{"head_sampling_rate":1e999}}'):
            with self.subTest(fragment=fragment):
                self.unknown(fragment, "CF-LOG-SAMPLING", "head_sampling_rate")

    def test_structural_siblings_are_unknown_not_crashes_or_empty_inventories(self):
        cases = [
            ('"queues":{"consumers":null}', "CF-QUEUE-CONSUMER-BOUNDS", "null"),
            ('"queues":{"consumers":[null]}', "CF-QUEUE-CONSUMER-BOUNDS", "null"),
            ('"queues":{"consumers":[{"queue":"jobs","dead_letter_queue":[],"max_retries":3}]}',
             "CF-QUEUE-CONSUMER-BOUNDS", "[]"),
            ('"queues":{"consumers":[{"queue":"jobs","max_concurrency":null}]}', "CF-QUEUE-CONCURRENCY", "null"),
            ('"containers":[{"class_name":"Sbx","instance_type":{},"max_instances":3}]', "CF-CONTAINER-SIZE", "{}"),
            ('"assets":{"run_worker_first":["/*",null]}', "CF-RUN-WORKER-FIRST", "null"),
            ('"ratelimits":[{"name":[]}]', "CF-NO-RATELIMIT-BINDING", "[]"),
            ('"durable_objects":{"bindings":null}', "CF-CONFIG-UNREADABLE", "null"),
            ('"kv_namespaces":[{"binding":{}}]', "CF-CONFIG-UNREADABLE", "{}"),
            ('"env":{"prod":null}', "CF-CONFIG-UNREADABLE", "null"),
            ('"account_id":null', "CF-CONFIG-UNREADABLE", "null"),
        ]
        for fragment, rule, value in cases:
            with self.subTest(fragment=fragment):
                self.unknown(fragment, rule, value)

    def test_omission_and_valid_controls_are_preserved(self):
        doc = self.document('"limits":{"cpu_ms":50},"observability":{"enabled":true,"head_sampling_rate":0},'
                            '"workers_dev":false,"preview_urls":false')
        for rule in ("CF-CPU-LIMIT", "CF-LOG-SAMPLING", "CF-WORKERS-DEV-ON"):
            self.assertEqual([f["severity"] for f in by_rule(doc, rule) if f["source"] == "config"], ["pass"])
        absent = self.document('"workers_dev":false')
        self.assertEqual([f["severity"] for f in by_rule(absent, "CF-CPU-LIMIT") if f["source"] == "config"], ["suggestion"])
        self.assertEqual(by_rule(absent, "CF-LOG-SAMPLING"), [])


if __name__ == "__main__":
    unittest.main()
