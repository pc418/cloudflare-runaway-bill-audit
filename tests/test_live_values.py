"""Literal live responses, through the read-only client and complete scan; no external network."""

import json
import unittest

import _util
import test_account as account_tests
from _util import FakeCloudflare, by_rule
from test_config_values import HUGE
from nobill.providers.cloudflare.auth import Secret
from nobill.providers.cloudflare.client import Client

A = account_tests.A
SETTINGS = f"GET {A}/workers/scripts/snapshot-api/settings"
GATEWAYS = f"GET {A}/ai-gateway/gateways"


def response(result, extra=""):
    return 200, ('{"success":true,"errors":[],"result":' + result + extra + '}').encode()


class LiveValues(unittest.TestCase):
    run_scan = account_tests.AccountScans.run_scan

    def unknown(self, key, result, rule, quoted, args=("--account",)):
        routes = account_tests.granted_routes()
        routes[key] = response(result)
        doc, _ = self.run_scan(routes, args=args)
        found = [f for f in by_rule(doc, rule) if f["source"] == "api"]
        self.assertEqual([f["severity"] for f in found], ["unknown"], found)
        self.assertIn(quoted, found[0]["missing"])
        self.assertTrue(found[0]["target"])

    def test_configured_workers_validate_every_live_sampling_value(self):
        for obs in ('null', '{"enabled":true,"head_sampling_rate":"bad"}',
                    '{"enabled":true,"logs":null}', '{"enabled":null}',
                    '{"logs":{"enabled":null}}', '{"enabled":true,"head_sampling_rate":null}',
                    '{"enabled":false,"head_sampling_rate":"bad"}',
                    '{"enabled":true,"head_sampling_rate":null,"logs":{"head_sampling_rate":0.1}}',
                    '{"enabled":true,"head_sampling_rate":' + HUGE + '}'):
            with self.subTest(obs=obs[:80]):
                self.unknown(SETTINGS, '{"bindings":[],"observability":' + obs + '}', "CF-LOG-SAMPLING",
                             "null" if "null" in obs else '"bad"' if '"bad"' in obs else HUGE[:40])

    def test_malformed_bindings_are_not_empty_or_equal(self):
        for bindings in ('null', '[null]', '[{"type":"ai","name":[]}]', '[{"type":null,"name":"AI"}]'):
            with self.subTest(bindings=bindings):
                self.unknown(SETTINGS, '{"bindings":' + bindings + '}', "CF-CONFIG-DRIFT", "bindings")

    def test_queue_null_negative_and_oversized_values_are_unknown(self):
        for consumer, quoted in [
            ('{"settings":null}', 'null'),
            ('{"settings":{"max_retries":null},"dead_letter_queue":"dlq"}', 'null'),
            ('{"settings":{"max_retries":-1},"dead_letter_queue":"dlq"}', '-1'),
            ('{"settings":{"max_retries":' + HUGE + '},"dead_letter_queue":"dlq"}', HUGE[:40]),
            ('{"settings":{"max_retries":3},"dead_letter_queue":null}', 'null'),
            ('{"settings":{"max_retries":3},"dead_letter_queue":[]}', '[]'),
        ]:
            with self.subTest(consumer=consumer[:100]):
                self.unknown(f"GET {A}/queues", '[{"queue_name":"jobs","consumers":[' + consumer + ']}]',
                             "CF-QUEUE-CONSUMER-BOUNDS", quoted, ("--account-wide",))
        self.unknown(f"GET {A}/queues", '[{"queue_name":"jobs","consumers":null}]',
                     "CF-QUEUE-CONSUMER-BOUNDS", "null", ("--account-wide",))

    def test_container_null_negative_and_oversized_values_are_unknown(self):
        for value in ('null', '-1', '0', HUGE, 'true', '"3"'):
            with self.subTest(value=value[:80]):
                self.unknown(f"GET {A}/containers/applications", '[{"name":"w","max_instances":' + value + '}]',
                             "CF-CONTAINER-MAX-INSTANCES", value[:40], ("--account-wide",))
        self.unknown(f"GET {A}/containers/applications", 'null', "CF-CONTAINER-MAX-INSTANCES", "null", ("--account-wide",))

    def test_enabled_gateway_limits_are_validated(self):
        for limits, quoted in [('null', 'null'), ('{"enabled":null}', 'null'),
                               ('{"enabled":true,"rules":null}', 'null'),
                               ('{"enabled":true,"rules":[{"limit":' + HUGE + ',"limitType":"cost","window":60}]}', HUGE[:40]),
                               ('{"enabled":true,"rules":[{"limit":5,"limitType":"cost","window":null}]}', 'null'),
                               ('{"enabled":true,"rules":[{"limit":5,"limitType":"cost","window":60,"enabled":null}]}', 'null')]:
            with self.subTest(limits=limits[:80]):
                self.unknown(GATEWAYS, '[{"id":"g","spend_limits":' + limits + '}]', "CF-AI-GATEWAY-SPEND", quoted)

    def test_usage_values_and_aggregate_overflow_are_unknown(self):
        row = ('{"dimensions":{"scriptName":"snapshot-api"},"sum":{"requests":VALUE,"errors":0,"subrequests":1},'
               '"quantiles":QUANTILES}')
        variants = [(row.replace('VALUE', HUGE).replace('QUANTILES', '{}'), HUGE[:40]),
                    (row.replace('VALUE', '1').replace('QUANTILES', '{"cpuTimeP99":null}'), 'null'),
                    (row.replace('VALUE', '1').replace('QUANTILES', 'null'), 'null'),
                    (row.replace('VALUE', '1e308').replace('QUANTILES', '{}') + ',' +
                     row.replace('VALUE', '1e308').replace('QUANTILES', '{}'), 'requests')]
        for rows, quoted in variants:
            with self.subTest(rows=rows[:80]):
                routes = account_tests.granted_routes()
                routes['POST /graphql'] = (200, ('{"data":{"viewer":{"accounts":[{"workersInvocationsAdaptive":[' +
                                                rows + ']}]}}}').encode())
                doc, _ = self.run_scan(routes)
                found = [f for f in by_rule(doc, "CF-USAGE-SNAPSHOT") if f['source'] == 'api']
                self.assertEqual([f['severity'] for f in found], ['unknown'], found)
                self.assertIn(quoted, found[0]['missing'])

    def test_alert_and_r2_siblings_quote_invalid_values(self):
        self.unknown(f"GET {A}/alerting/v3/policies",
                     '[{"alert_type":"billing_usage_alert","enabled":true},'
                     '{"alert_type":"billing_usage_alert","enabled":null}]', "CF-NO-BILLING-ALERT", "null")
        self.unknown(f"GET {A}/r2/buckets/snapshot-shots/domains/managed", '{"enabled":null,"domain":"pub-1.r2.dev"}',
                     "CF-R2-DEV-PUBLIC", "null")
        # available_alerts {"Billing": null} and custom {"domains": null} are auxiliary reads: see test_live_precision.

    def test_valid_and_omitted_live_values_keep_useful_results(self):
        routes = account_tests.granted_routes()
        routes[SETTINGS] = response('{"bindings":[],"observability":{"enabled":true,"head_sampling_rate":1}}')
        routes[f"GET {A}/queues"] = response('[{"queue_name":"jobs","consumers":[{"dead_letter_queue":"dlq"}]}]')
        routes[f"GET {A}/containers/applications"] = response('[{"name":"w","max_instances":1}]')
        doc, _ = self.run_scan(routes, args=("--account-wide",))
        for rule, severity in (("CF-LOG-SAMPLING", "suggestion"), ("CF-AI-GATEWAY-SPEND", "pass"),
                               ("CF-QUEUE-CONSUMER-BOUNDS", "pass"), ("CF-CONTAINER-MAX-INSTANCES", "pass")):
            self.assertEqual([f['severity'] for f in by_rule(doc, rule) if f['source'] == 'api'], [severity])

    def test_unknown_diagnostics_do_not_expose_a_clipped_credential(self):
        routes = account_tests.granted_routes()
        routes[SETTINGS] = response('{"bindings":[],"observability":{"logs":' +
                                    json.dumps("x" * 150 + account_tests.TOKEN) + '}}')
        doc, _ = self.run_scan(routes)
        found = [f for f in by_rule(doc, "CF-LOG-SAMPLING") if f['source'] == 'api']
        self.assertEqual([f['severity'] for f in found], ['unknown'])
        self.assertNotIn('tokSECRET', json.dumps(doc))


class ResponseValues(unittest.TestCase):
    def test_invalid_json_diagnostics_scrub_before_clipping(self):
        literal = 'x' * 230 + account_tests.TOKEN
        with FakeCloudflare({'GET /x': (200, literal.encode())}) as fake:
            result = Client(Secret(account_tests.TOKEN), base=fake.base).get('/x')
        self.assertFalse(result.ok)
        self.assertNotIn('tokSECRET', result.reason)

    def test_bad_json_numbers_and_metadata_return_quoted_failures(self):
        for literal, quoted in [
            ('{"success":true,"result":[NaN]}', 'NaN'),
            ('{"success":true,"result":[Infinity]}', 'Infinity'),
            ('{"success":true,"result":[-Infinity]}', '-Infinity'),
            ('{"success":true,"result":[],"result_info":null}', 'null'),
            ('{"success":true,"result":[],"result_info":{"page":null,"total_pages":2}}', 'null'),
            ('{"success":true,"result":[],"result_info":{"page":true,"total_pages":2}}', 'true'),
            ('{"success":true,"result":[],"result_info":{"page":1,"total_pages":' + HUGE + '}}', HUGE[:40]),
            ('{"success":true,"result":[],"result_info":{"cursor":[]}}', '[]'),
        ]:
            with self.subTest(literal=literal[:80]):
                with FakeCloudflare({'GET /x': (200, literal.encode())}) as fake:
                    result = Client(Secret(account_tests.TOKEN), base=fake.base).get_all('/x')
                self.assertFalse(result.ok)
                self.assertIn(quoted, result.reason)
                self.assertNotIn(account_tests.TOKEN, result.reason)

    def test_pagination_does_not_report_truncated_results_as_complete(self):
        with FakeCloudflare({'GET /x': response('[]', ',"result_info":{"cursor":"again"}')}) as fake:
            result = Client(Secret(account_tests.TOKEN), base=fake.base).get_all('/x', max_pages=2)
        self.assertFalse(result.ok)
        self.assertIn('again', result.reason)
        self.assertLessEqual(len(fake.requests), 2)


if __name__ == "__main__":
    unittest.main()
