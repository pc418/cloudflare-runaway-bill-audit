"""Configuration-only checks on small generated projects (no network, account layer off).

Kept from the detector-breadth suite when the source analyzer was retired (owner 2026-10-20,
docs/261020-refactor-AGENT_LED_BILLING_AUDIT.md): these read wrangler configuration and Pages
_routes.json only, never application source.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

import _util  # noqa: F401  (temp HOME, no credentials)
from _util import by_rule, scan

AI_JSON = {"name": "w", "main": "src/index.ts", "compatibility_date": "2026-10-01", "workers_dev": False,
           "ai": {"binding": "AI"}}
LIMITER_JSON = {**AI_JSON, "ratelimits": [{"name": "LIMITER", "namespace_id": "1001",
                                           "simple": {"limit": 10, "period": 60}}]}
HELLO = 'export default {\n  async fetch(req, env) {\n    return new Response("hello");\n  }\n};\n'


def project(files: dict[str, str], config: dict | None = AI_JSON, name: str = "wrangler.json") -> Path:
    root = Path(tempfile.mkdtemp(prefix="nobill-cfg-")) / "proj"
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    if config is not None:
        (root / name).write_text(json.dumps(config))
    return root


def sev(doc, rule) -> list[str]:
    return sorted(f["severity"] for f in doc["findings"] if f["rule"] == rule)


class AssetRouting(unittest.TestCase):
    """PIN (lead brief 2026-10-13, G5b): run_worker_first patterns that cover everything are
    `true`; a Pages _routes.json that includes every path runs the Functions for every asset.
    PIN (owner 2026-10-20, docs/261020-refactor-AGENT_LED_BILLING_AUDIT.md section 7): a heavy binding
    behind it does not make it an alarm; it is a suggestion the agent reviews against the code path."""

    DO = {"durable_objects": {"bindings": [{"name": "ROOM", "class_name": "Room"}]},
          "migrations": [{"tag": "v1", "new_sqlite_classes": ["Room"]}]}
    CODE = ('import { DurableObject } from "cloudflare:workers";\nexport class Room extends DurableObject {}\n'
            'export default { async fetch(req, env) { return env.ROOM.get(env.ROOM.idFromName("a")).fetch(req); } };\n')

    def cfg(self, rwf):
        return {**AI_JSON, **self.DO, "assets": {"directory": "public", "binding": "ASSETS", "run_worker_first": rwf}}

    def test_catch_all_pattern_list_is_like_true_T07(self):
        for rwf in (True, ["/*"], ["/*", "!/static/*"]):
            with self.subTest(rwf=rwf):
                doc, _ = scan(project({"src/index.ts": self.CODE, "public/index.html": "x"}, self.cfg(rwf)))
                self.assertEqual(sev(doc, "CF-RUN-WORKER-FIRST"), ["suggestion"])
                f = by_rule(doc, "CF-RUN-WORKER-FIRST")[0]
                self.assertEqual((f["confidence"], f["review"]["status"]), ("heuristic", "needs-review"))
                self.assertIn("binding presence does not show", " ".join(e.get("text", "") for e in f["evidence"]))
        # without a heavy binding the routing fact itself is certain
        cfg = {**AI_JSON, "assets": {"directory": "public", "run_worker_first": True}}
        cfg.pop("ai")
        doc, _ = scan(project({"src/index.ts": HELLO, "public/index.html": "x"}, cfg))
        f = by_rule(doc, "CF-RUN-WORKER-FIRST")[0]
        self.assertEqual((f["severity"], f["confidence"]), ("suggestion", "certain"))

    def test_specific_patterns_are_not_everything(self):
        doc, _ = scan(project({"src/index.ts": self.CODE, "public/index.html": "x"}, self.cfg(["/api/*"])))
        self.assertEqual(sev(doc, "CF-RUN-WORKER-FIRST"), [])

    PAGES = {"name": "site", "compatibility_date": "2026-10-01", "pages_build_output_dir": "public",
             "browser": {"binding": "BROWSER"}}
    FN = ('import puppeteer from "@cloudflare/puppeteer";\nexport const onRequest = async ({ env }) => {\n'
          '  const b = await puppeteer.launch(env.BROWSER);\n  try { return new Response(await (await b.newPage()).title()); }\n'
          '  finally { await b.close(); }\n};\n')

    def test_pages_routes_json_including_everything_T08(self):
        doc, _ = scan(project({"functions/[[path]].ts": self.FN, "public/index.html": "x",
                               "public/_routes.json": '{"version": 1, "include": ["/*"], "exclude": []}'}, self.PAGES))
        self.assertEqual(sev(doc, "CF-RUN-WORKER-FIRST"), ["suggestion"])
        f = by_rule(doc, "CF-RUN-WORKER-FIRST")[0]
        self.assertEqual(f["evidence"][0]["file"], "public/_routes.json")
        self.assertEqual(f["review"]["status"], "needs-review")

    def test_unreadable_pages_routes_json_is_unknown(self):
        for name, text in {"not json": '{"include": ["/*"',
                           "include not a list": '{"version": 1, "include": "/*"}'}.items():
            with self.subTest(name):
                doc, _ = scan(project({"functions/api/x.ts": self.FN, "public/index.html": "x",
                                       "public/_routes.json": text}, self.PAGES))
                unk = by_rule(doc, "CF-RUN-WORKER-FIRST", "unknown")
                self.assertEqual(len(unk), 1, name)
                self.assertIn("public/_routes.json", unk[0]["missing"])
                self.assertFalse(by_rule(doc, "CF-RUN-WORKER-FIRST", "pass"))
        # not built yet: no evidence either way, no finding
        doc, _ = scan(project({"functions/api/x.ts": self.FN}, self.PAGES))
        self.assertEqual(sev(doc, "CF-RUN-WORKER-FIRST"), [])

    def test_inaccessible_output_directory_is_unknown_not_a_crash(self):
        # sol review 2026-10-21 finding 4: the existence probe ran outside the guarded read
        if os.geteuid() == 0:
            self.skipTest("root reads every directory")
        root = project({"functions/api/x.ts": self.FN, "public/index.html": "x",
                        "public/_routes.json": '{"version": 1, "include": ["/*"], "exclude": []}'}, self.PAGES)
        (root / "public").chmod(0)
        try:
            doc, _ = scan(root)
        finally:
            (root / "public").chmod(0o755)
        unk = by_rule(doc, "CF-RUN-WORKER-FIRST", "unknown")
        self.assertEqual(len(unk), 1, doc["findings"])
        self.assertIn("public/_routes.json", unk[0]["missing"])

    def test_output_directory_outside_the_config_directory_still_renders(self):
        outside = Path(tempfile.mkdtemp(prefix="nobill-pages-out-")).resolve()
        (outside / "_routes.json").write_text('{"version": 1,\n "include": ["/*"], "exclude": []}')
        root = project({"functions/api/x.ts": self.FN}, {**self.PAGES, "pages_build_output_dir": str(outside)})
        doc, _ = scan(root)
        f = by_rule(doc, "CF-RUN-WORKER-FIRST")
        self.assertEqual([x["severity"] for x in f], ["suggestion"])
        where = f[0]["evidence"][0]
        self.assertTrue(where["file"].startswith("../"), where["file"])  # outside the project, still a path
        self.assertEqual((root.resolve() / where["file"]).resolve(), outside / "_routes.json")
        self.assertEqual(where["line"], 2)
        # a declared output "directory" that is a file holds no _routes.json: absent, no finding, no crash
        bad = project({"functions/api/x.ts": self.FN, "public": "not a directory"}, self.PAGES)
        doc, _ = scan(bad)
        self.assertEqual(sev(doc, "CF-RUN-WORKER-FIRST"), [])

    def test_pages_routes_json_with_specific_paths(self):
        doc, _ = scan(project({"functions/api/[[path]].ts": self.FN, "public/index.html": "x",
                               "public/_routes.json": '{"version": 1, "include": ["/api/*"], "exclude": []}'}, self.PAGES))
        self.assertEqual(sev(doc, "CF-RUN-WORKER-FIRST"), [])


class MalformedSettings(unittest.TestCase):
    """A setting of the wrong type is unknown, never a pass (design 261020 section 7: do not turn
    malformed settings into passes). Values as a hand-written wrangler.json can carry them."""

    CONTAINER = {"durable_objects": {"bindings": [{"name": "SBX", "class_name": "Sbx"}]},
                 "migrations": [{"tag": "v1", "new_sqlite_classes": ["Sbx"]}]}

    def one(self, rule: str, config: dict) -> list[dict]:
        """The config-layer results of one rule (the offline account layer adds its own unknowns);
        a dead-letter consumer's case looks at that consumer only."""
        doc, _ = scan(project({"src/index.ts": HELLO}, config))
        found = [f for f in by_rule(doc, rule) if f["source"] == "config"]
        dlq = [f for f in found if (f["target"] or "").endswith("queue jobs-dlq")]
        return dlq or found

    def test_wrong_types_are_unknown(self):
        cases = {
            "max_instances string": ("CF-CONTAINER-MAX-INSTANCES", {**LIMITER_JSON, **self.CONTAINER, "containers": [
                {"class_name": "Sbx", "image": "./Dockerfile", "max_instances": "5"}]}),
            "max_instances bool": ("CF-CONTAINER-MAX-INSTANCES", {**LIMITER_JSON, **self.CONTAINER, "containers": [
                {"class_name": "Sbx", "image": "./Dockerfile", "max_instances": True}]}),
            "max_instances zero": ("CF-CONTAINER-MAX-INSTANCES", {**LIMITER_JSON, **self.CONTAINER, "containers": [
                {"class_name": "Sbx", "image": "./Dockerfile", "max_instances": 0}]}),
            "cpu_ms string": ("CF-CPU-LIMIT", {**LIMITER_JSON, "limits": {"cpu_ms": "50"}}),
            "cpu_ms bool": ("CF-CPU-LIMIT", {**LIMITER_JSON, "limits": {"cpu_ms": True}}),
            "sampling string": ("CF-LOG-SAMPLING", {**LIMITER_JSON, "observability": {
                "enabled": True, "head_sampling_rate": "0.1"}}),
            "max_retries string": ("CF-QUEUE-CONSUMER-BOUNDS", {**LIMITER_JSON, "queues": {"consumers": [
                {"queue": "jobs", "max_retries": "3", "dead_letter_queue": "jobs-dlq"}]}}),
            "empty dead_letter_queue": ("CF-QUEUE-CONSUMER-BOUNDS", {**LIMITER_JSON, "queues": {"consumers": [
                {"queue": "jobs", "max_retries": 3, "dead_letter_queue": ""}]}}),
            "dlq consumer max_retries string": ("CF-QUEUE-CONSUMER-BOUNDS", {**LIMITER_JSON, "queues": {"consumers": [
                {"queue": "jobs", "max_retries": 3, "dead_letter_queue": "jobs-dlq"},
                {"queue": "jobs-dlq", "max_retries": "1"}]}}),
            "workers_dev string": ("CF-WORKERS-DEV-ON", {**LIMITER_JSON, "workers_dev": "false",
                                                        "preview_urls": False}),
        }
        for name, (rule, config) in cases.items():
            with self.subTest(name):
                found = self.one(rule, config)
                self.assertIn("unknown", [f["severity"] for f in found], name)
                self.assertNotIn("pass", [f["severity"] for f in found], name)
                for f in found:
                    if f["severity"] == "unknown":
                        self.assertTrue(f["missing"].strip())

    def test_well_typed_values_still_pass(self):
        cases = {
            "max_instances": ("CF-CONTAINER-MAX-INSTANCES", {**LIMITER_JSON, **self.CONTAINER, "containers": [
                {"class_name": "Sbx", "image": "./Dockerfile", "max_instances": 5}]}),
            "cpu_ms": ("CF-CPU-LIMIT", {**LIMITER_JSON, "limits": {"cpu_ms": 50}}),
            "sampling": ("CF-LOG-SAMPLING", {**LIMITER_JSON, "observability": {"enabled": True,
                                                                           "head_sampling_rate": 0.1}}),
            "queue": ("CF-QUEUE-CONSUMER-BOUNDS", {**LIMITER_JSON, "queues": {"consumers": [
                {"queue": "jobs", "max_retries": 3, "dead_letter_queue": "jobs-dlq"}]}}),
            "workers_dev": ("CF-WORKERS-DEV-ON", {**LIMITER_JSON, "workers_dev": False, "preview_urls": False}),
        }
        for name, (rule, config) in cases.items():
            with self.subTest(name):
                self.assertEqual([f["severity"] for f in self.one(rule, config)], ["pass"], name)


class NumericDomains(unittest.TestCase):
    """Sol review 2026-10-21 finding 3: TOML accepts nan and inf, and NaN compares false with every
    bound, so it slipped past the range checks into a pass. Each numeric setting is checked against its
    whole domain first; anything outside is unknown with the value quoted, never a pass or suggestion."""

    BASE = ('name = "w"\nmain = "src/index.ts"\ncompatibility_date = "2026-10-01"\nworkers_dev = false\n'
            '[ai]\nbinding = "AI"\n[[ratelimits]]\nname = "LIMITER"\nnamespace_id = "1001"\n'
            'simple = { limit = 10, period = 60 }\n')
    CONTAINER = ('[[durable_objects.bindings]]\nname = "SBX"\nclass_name = "Sbx"\n'
                 '[[migrations]]\ntag = "v1"\nnew_sqlite_classes = ["Sbx"]\n'
                 '[[containers]]\nclass_name = "Sbx"\nimage = "./Dockerfile"\nmax_instances = {}\n')
    SETTINGS = {
        "CF-CPU-LIMIT": "[limits]\ncpu_ms = {}\n",
        "CF-LOG-SAMPLING": "[observability]\nenabled = true\nhead_sampling_rate = {}\n",
        "CF-CONTAINER-MAX-INSTANCES": CONTAINER,
        "CF-QUEUE-CONSUMER-BOUNDS": '[[queues.consumers]]\nqueue = "jobs"\ndead_letter_queue = "jobs-dlq"\nmax_retries = {}\n',
        "CF-SUBREQUESTS-RAISED": "[limits]\nsubrequests = {}\n",
    }

    def severities(self, rule: str, value: str) -> list[str]:
        root = Path(tempfile.mkdtemp(prefix="nobill-num-")) / "proj"
        (root / "src").mkdir(parents=True)
        (root / "src" / "index.ts").write_text(HELLO)
        (root / "wrangler.toml").write_text(self.BASE + self.SETTINGS[rule].replace("{}", value))
        doc, _ = scan(root)
        return [f["severity"] for f in by_rule(doc, rule) if f["source"] == "config"]

    def test_out_of_domain_values_are_unknown(self):
        cases = {
            "CF-CPU-LIMIT": ["nan", "inf", "-inf", "0", "-5", "300001"],
            "CF-LOG-SAMPLING": ["nan", "inf", "-inf", "1.5", "-0.1"],
            "CF-CONTAINER-MAX-INSTANCES": ["nan", "inf", "0", "-1", "2.5"],
            "CF-QUEUE-CONSUMER-BOUNDS": ["nan", "inf", "-1", "2.5"],
            "CF-SUBREQUESTS-RAISED": ["nan", "inf", "-1", "2.5", "50000.0", '"many"', "true"],
        }
        for rule, values in cases.items():
            for value in values:
                with self.subTest(rule=rule, value=value):
                    self.assertEqual(self.severities(rule, value), ["unknown"])

    def test_in_domain_values_keep_their_verdicts(self):
        cases = {
            "CF-CPU-LIMIT": {"50": "pass", "50.5": "pass", "300000": "suggestion"},
            "CF-LOG-SAMPLING": {"0": "pass", "0.5": "pass", "1": "suggestion", "1.0": "suggestion"},
            "CF-CONTAINER-MAX-INSTANCES": {"1": "pass", "19": "pass", "20": "suggestion"},
            "CF-QUEUE-CONSUMER-BOUNDS": {"0": "pass", "3": "pass"},
            "CF-SUBREQUESTS-RAISED": {"50": None, "10000": None, "50000": "suggestion"},
        }
        for rule, values in cases.items():
            for value, expected in values.items():
                with self.subTest(rule=rule, value=value):
                    self.assertEqual(self.severities(rule, value), [expected] if expected else [])

    def test_limits_that_are_not_a_table_are_unknown(self):
        # a malformed [limits] used to read as "cpu_ms not set"; it cannot be read at all
        root = Path(tempfile.mkdtemp(prefix="nobill-num-")) / "proj"
        (root / "src").mkdir(parents=True)
        (root / "src" / "index.ts").write_text(HELLO)
        (root / "wrangler.toml").write_text(self.BASE.replace('workers_dev = false\n', 'workers_dev = false\nlimits = 5\n'))
        doc, _ = scan(root)
        cpu = [f for f in by_rule(doc, "CF-CPU-LIMIT") if f["source"] == "config"]
        self.assertEqual([f["severity"] for f in cpu], ["unknown"])
        self.assertIn("limits is not a table", cpu[0]["missing"])


class ScopedPasses(unittest.TestCase):
    """PIN (owner 2026-10-20, docs/261020-refactor-AGENT_LED_BILLING_AUDIT.md section 6): a config pass
    describes only the checked setting. A declared Rate Limiting binding does not prove it runs, queue
    retry settings do not bound re-enqueue, and CPU / instance caps do not bound total spend."""

    def test_config_passes_never_certify_route_controls(self):
        config = {**LIMITER_JSON, "limits": {"cpu_ms": 50},
                  "durable_objects": {"bindings": [{"name": "SBX", "class_name": "Sbx"}]},
                  "migrations": [{"tag": "v1", "new_sqlite_classes": ["Sbx"]}],
                  "containers": [{"class_name": "Sbx", "image": "./Dockerfile", "max_instances": 3}],
                  "queues": {"consumers": [{"queue": "jobs", "max_retries": 3, "dead_letter_queue": "jobs-dlq",
                                            "max_concurrency": 2}]}}
        doc, _ = scan(project({"src/index.ts": HELLO}, config))
        expect = {"CF-NO-RATELIMIT-BINDING": "is for review",
                  "CF-QUEUE-CONSUMER-BOUNDS": "do not bound messages the code sends or re-enqueues",
                  "CF-CPU-LIMIT": "does not bound how many invocations run or total spend",
                  "CF-CONTAINER-MAX-INSTANCES": "or total spend"}
        for rule, words in expect.items():
            with self.subTest(rule):
                passed = by_rule(doc, rule, "pass")
                self.assertEqual(len(passed), 1, rule)
                self.assertIn(words, " ".join(e.get("text", "") for e in passed[0]["evidence"]))
                self.assertNotRegex(passed[0]["title"].lower(), r"\bbounded\b|\bprotected\b|\bsafe\b")

    def test_pass_prose_states_the_checked_fact_not_the_failure(self):
        # PIN owner 2026-10-21: improve friction from real skill use (dual-agent audit of a real project).
        config = {**LIMITER_JSON, "limits": {"cpu_ms": 50},
                  "observability": {"enabled": True, "head_sampling_rate": 0.1},
                  "queues": {"consumers": [
                      {"queue": "jobs", "max_retries": 5, "dead_letter_queue": "jobs-dlq"},
                      {"queue": "jobs-dlq", "max_retries": 3}]}}
        out = Path(tempfile.mkdtemp(prefix="nobill-pass-prose-"))
        doc, _ = scan(project({"src/index.ts": HELLO}, config), out=out)
        expected = {"CF-NO-RATELIMIT-BINDING": "declared",
                    "CF-WORKERS-DEV-ON": "disabled",
                    "CF-CPU-LIMIT": "50",
                    "CF-LOG-SAMPLING": "0.1",
                    "CF-QUEUE-CONSUMER-BOUNDS": "max_retries"}
        for rule, fact in expected.items():
            passed = by_rule(doc, rule, "pass")
            self.assertTrue(passed, rule)
            for finding in passed:
                with self.subTest(rule=rule, target=finding["target"]):
                    self.assertIn(fact, finding["why"]["text"])
                    self.assertIn(finding["title"], finding["why"]["text"])
                    self.assertNotIn("declares no ratelimits", finding["why"]["text"])
                    self.assertNotIn("Add a ratelimits", finding["fix"]["text"])
        self.assertNotIn("declares no ratelimits", (out / "report.html").read_text())
        self.assertIn("Rate Limiting binding declared", (out / "report.md").read_text())

    def test_queue_concurrency_reports_configuration_not_consumer_behavior(self):
        config = {**AI_JSON, "queues": {"consumers": [{"queue": "jobs"}]}}
        doc, _ = scan(project({"src/index.ts": HELLO}, config))
        finding = by_rule(doc, "CF-QUEUE-CONCURRENCY")[0]
        self.assertEqual(finding["severity"], "suggestion")
        self.assertIn("does not establish", finding["why"]["text"])
        self.assertNotIn("hits paid APIs at full width", finding["why"]["text"])
        self.assertIn("consumer", finding["fix"]["text"])
        # Missing and malformed configuration keep their separate existing dispositions.
        doc, _ = scan(project({"src/index.ts": HELLO}, AI_JSON))
        self.assertEqual(by_rule(doc, "CF-NO-RATELIMIT-BINDING")[0]["severity"], "suggestion")
        self.assertIn("declares no ratelimits", by_rule(doc, "CF-NO-RATELIMIT-BINDING")[0]["why"]["text"])
        config["queues"]["consumers"][0]["max_concurrency"] = "many"
        doc, _ = scan(project({"src/index.ts": HELLO}, config))
        self.assertEqual(by_rule(doc, "CF-QUEUE-CONCURRENCY")[0]["severity"], "unknown")


class ObservabilityBlock(unittest.TestCase):
    """A malformed observability block is unknown quoting the value (as on the live side), not silence."""

    def severities(self, observability) -> tuple[list[str], list[dict]]:
        config = {**LIMITER_JSON}
        if observability is not None:
            config["observability"] = observability
        doc, _ = scan(project({"src/index.ts": HELLO}, config))
        found = [f for f in by_rule(doc, "CF-LOG-SAMPLING") if f["source"] == "config"]
        return [f["severity"] for f in found], found

    def test_malformed_blocks_are_unknown(self):
        for name, obs in {"block not a table": "on",
                          "block a list": [{"enabled": True}],
                          "logs not a table": {"enabled": True, "logs": "on"},
                          "enabled not a boolean": {"enabled": "true", "head_sampling_rate": 1},
                          "logs.enabled not a boolean": {"logs": {"enabled": 1, "head_sampling_rate": 0.1}}}.items():
            with self.subTest(name):
                sevs, found = self.severities(obs)
                self.assertEqual(sevs, ["unknown"], name)
                self.assertTrue(found[0]["missing"].strip())

    def test_valid_blocks_are_unchanged(self):
        for name, (obs, expected) in {"absent": (None, []), "disabled": ({"enabled": False}, []),
                                      "sampled": ({"enabled": True, "head_sampling_rate": 0.1}, ["pass"]),
                                      "logs table, unset rate": ({"logs": {"enabled": True}}, ["suggestion"]),
                                      "rate 1": ({"enabled": True, "logs": {"head_sampling_rate": 1}}, ["suggestion"])
                                      }.items():
            with self.subTest(name):
                self.assertEqual(self.severities(obs)[0], expected, name)


class Discovery(unittest.TestCase):
    def test_unlistable_directory_is_an_unknown_not_a_silent_skip(self):
        # same class as sol review 2026-10-21 finding 4: a directory the walk cannot list may hold a
        # wrangler config; the scan says the inventory may be incomplete instead of dropping it
        if os.geteuid() == 0:
            self.skipTest("root lists every directory")
        root = project({"src/index.ts": HELLO,
                        "services/api/wrangler.json": json.dumps({**AI_JSON, "name": "api"})}, AI_JSON)
        locked = root / "services" / "api"
        locked.chmod(0)
        try:
            doc, _ = scan(root)
        finally:
            locked.chmod(0o755)
        unk = [f for f in by_rule(doc, "CF-CONFIG-UNREADABLE", "unknown") if f["target"] == "services/api"]
        self.assertEqual(len(unk), 1, doc["findings"])
        self.assertIn("may be incomplete", unk[0]["missing"])
        self.assertEqual(doc["provider_info"]["cloudflare"]["source_context"]["configs"], ["wrangler.json"])
        # a readable tree reports nothing of the kind
        doc, _ = scan(project({"src/index.ts": HELLO}, AI_JSON))
        self.assertEqual(by_rule(doc, "CF-CONFIG-UNREADABLE"), [])


class CostInventory(unittest.TestCase):
    def test_stream_binding_is_in_the_cost_inventory_B03(self):
        doc, _ = scan(project({"src/index.ts": HELLO}, {**LIMITER_JSON, "stream": {"binding": "STREAM"}}))
        rows = by_rule(doc, "CF-COST-INVENTORY")[0]["details"]["rows"]
        self.assertIn("Stream", [r["binding"] for r in rows])


if __name__ == "__main__":
    unittest.main()
