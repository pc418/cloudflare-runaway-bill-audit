"""A valid primary live fact keeps its conclusion when an auxiliary read fails or an unrelated record is odd."""

import unittest

import _util
import test_account as account_tests
from _util import by_rule, denied, ok

A = account_tests.A
SETTINGS = f"GET {A}/workers/scripts/snapshot-api/settings"


def api(doc, rule):
    return [f for f in by_rule(doc, rule) if f["source"] == "api"]


class LivePrecision(unittest.TestCase):
    run_scan = account_tests.AccountScans.run_scan

    def test_an_enabled_billing_policy_passes_when_available_alerts_is_denied(self):
        routes = account_tests.granted_routes()
        routes[f"GET {A}/alerting/v3/available_alerts"] = denied()
        doc, _ = self.run_scan(routes)
        self.assertEqual([f["severity"] for f in api(doc, "CF-NO-BILLING-ALERT")], ["pass"])

    def test_no_match_is_unknown_not_alarm_when_available_alerts_is_denied(self):
        routes = account_tests.granted_routes()
        routes[f"GET {A}/alerting/v3/available_alerts"] = denied()
        routes[f"GET {A}/alerting/v3/policies"] = ok([{"id": "p9", "name": "Origin", "alert_type": "http_alert_origin_error", "enabled": True}])
        doc, _ = self.run_scan(routes)
        self.assertEqual([f["severity"] for f in api(doc, "CF-NO-BILLING-ALERT")], ["unknown"])

    def test_an_enabled_billing_policy_passes_when_available_alerts_is_malformed(self):
        routes = account_tests.granted_routes()
        routes[f"GET {A}/alerting/v3/available_alerts"] = ok({"Billing": None})
        doc, _ = self.run_scan(routes)
        self.assertEqual([f["severity"] for f in api(doc, "CF-NO-BILLING-ALERT")], ["pass"])

    def test_an_unrelated_odd_policy_does_not_hide_an_enabled_billing_policy(self):
        routes = account_tests.granted_routes()
        routes[f"GET {A}/alerting/v3/policies"] = ok([
            {"id": "p9", "name": None, "alert_type": "http_alert_origin_error", "enabled": True},
            {"id": "p1", "name": "Monthly budget", "alert_type": "billing_usage_alert", "enabled": True}])
        doc, _ = self.run_scan(routes)
        self.assertEqual([f["severity"] for f in api(doc, "CF-NO-BILLING-ALERT")], ["pass"])

    def test_a_billing_candidate_with_a_bad_enabled_flag_is_still_unknown(self):
        routes = account_tests.granted_routes()
        routes[f"GET {A}/alerting/v3/policies"] = ok([
            {"id": "p1", "name": "Monthly budget", "alert_type": "billing_usage_alert", "enabled": "yes"}])
        doc, _ = self.run_scan(routes)
        self.assertEqual([f["severity"] for f in api(doc, "CF-NO-BILLING-ALERT")], ["unknown"])

    def test_public_r2_dev_stays_a_suggestion_when_custom_domains_cannot_be_read(self):
        for custom in (denied(), ok({"domains": None}), ok(None)):
            with self.subTest(custom=custom):
                routes = account_tests.granted_routes()
                routes[f"GET {A}/r2/buckets/snapshot-shots/domains/custom"] = custom
                doc, _ = self.run_scan(routes)
                found = api(doc, "CF-R2-DEV-PUBLIC")
                self.assertEqual([f["severity"] for f in found], ["suggestion"], found)
                self.assertTrue(any("custom domains" in e.get("text", "") for e in found[0]["evidence"]), found[0]["evidence"])

    def test_disabled_r2_dev_passes_whatever_the_domain_field_holds(self):
        routes = account_tests.granted_routes()
        routes[f"GET {A}/r2/buckets/snapshot-shots/domains/managed"] = ok({"enabled": False, "domain": None})
        doc, _ = self.run_scan(routes)
        self.assertEqual([f["severity"] for f in api(doc, "CF-R2-DEV-PUBLIC")], ["pass"])

    def test_single_object_settings_with_null_metadata_still_count(self):
        routes = account_tests.granted_routes()
        status, body = routes[SETTINGS]
        routes[SETTINGS] = (status, dict(body, result_info=None, errors=None))
        doc, _ = self.run_scan(routes)
        drift = api(doc, "CF-CONFIG-DRIFT")
        self.assertIn([f["severity"] for f in drift], (["pass"], ["suggestion"]), drift)
        self.assertTrue(any(e.get("field") == "bindings[].name" for e in drift[0]["evidence"]), drift[0]["evidence"])

    def test_disabled_spend_limits_are_a_suggestion_whatever_their_rules_hold(self):
        routes = account_tests.granted_routes()
        routes[f"GET {A}/ai-gateway/gateways"] = ok([{"id": "default", "spend_limits": {
            "enabled": False, "rules": [{"limit": None, "limitType": "cost", "window": 60}]}}])
        doc, _ = self.run_scan(routes)
        self.assertEqual([f["severity"] for f in api(doc, "CF-AI-GATEWAY-SPEND")], ["suggestion"])

    def test_one_sampling_finding_per_worker_when_bindings_are_malformed(self):
        routes = account_tests.granted_routes()
        routes[SETTINGS] = ok({"bindings": [None], "observability": {"enabled": True}})
        doc, _ = self.run_scan(routes)
        self.assertEqual([f["severity"] for f in api(doc, "CF-LOG-SAMPLING")], ["suggestion"])
        self.assertEqual([f["severity"] for f in api(doc, "CF-CONFIG-DRIFT")], ["unknown"])


if __name__ == "__main__":
    unittest.main()
