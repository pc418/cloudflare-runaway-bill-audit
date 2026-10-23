"""Envelope metadata is validated where it is consumed: pagination in get_all, not every get."""

import unittest
from urllib.parse import parse_qs, urlsplit

import _util
import test_account as account_tests
from _util import FakeCloudflare, by_rule, ok
from nobill.providers.cloudflare.auth import Secret
from nobill.providers.cloudflare.client import Client

A = account_tests.A


def paged(pages):
    """pages: list of (result, result_info) served by cursor= / page= query parameter."""
    def serve(path):
        q = parse_qs(urlsplit(path).query)
        idx = 0
        if "cursor" in q:
            idx = int(q["cursor"][0][1:])
        elif "page" in q:
            idx = int(q["page"][0]) - 1
        result, info = pages[idx]
        return ok(result, result_info=info)
    return serve


class Envelope(unittest.TestCase):
    def client(self, fake):
        return Client(Secret(account_tests.TOKEN), base=fake.base)

    def test_single_object_reads_ignore_null_pagination_metadata(self):
        body = b'{"success":true,"result":{"enabled":true},"result_info":null,"errors":null}'
        with FakeCloudflare({"GET /x": (200, body)}) as fake:
            res = self.client(fake).get("/x")
        self.assertTrue(res.ok, res.reason)
        self.assertEqual(res.result, {"enabled": True})

    def test_a_null_cursor_ends_a_list(self):
        body = b'{"success":true,"result":[1],"result_info":{"cursor":null,"per_page":20}}'
        with FakeCloudflare({"GET /x": (200, body)}) as fake:
            res = self.client(fake).get_all("/x")
        self.assertTrue(res.ok, res.reason)
        self.assertEqual(res.result, [1])

    def test_total_count_without_total_pages_still_pages(self):
        pages = [([1], {"page": 1, "per_page": 1, "total_count": 2}), ([2], {"page": 2, "per_page": 1, "total_count": 2})]
        with FakeCloudflare({"GET /x": paged(pages)}) as fake:
            res = self.client(fake).get_all("/x")
        self.assertTrue(res.ok, res.reason)
        self.assertEqual(res.result, [1, 2])
        self.assertEqual(len(fake.requests), 2)

    def test_wrapped_lists_follow_the_cursor(self):
        pages = [({"buckets": [{"name": "a"}]}, {"cursor": "c1", "per_page": 1}),
                 ({"buckets": [{"name": "b"}]}, {"per_page": 1})]
        with FakeCloudflare({"GET /x": paged(pages)}) as fake:
            res = self.client(fake).get_all("/x", key="buckets")
        self.assertTrue(res.ok, res.reason)
        self.assertEqual(res.result, {"buckets": [{"name": "a"}, {"name": "b"}]})
        self.assertEqual(len(fake.requests), 2)

    def test_malformed_pagination_metadata_is_incomplete_not_complete(self):
        for info in ('null', '{"page":"1","total_pages":2}', '{"cursor":[]}', '{"total_count":2,"per_page":null,"page":1}'):
            with self.subTest(info=info):
                body = ('{"success":true,"result":[1],"result_info":' + info + '}').encode()
                with FakeCloudflare({"GET /x": (200, body)}) as fake:
                    res = self.client(fake).get_all("/x")
                self.assertFalse(res.ok)
                self.assertIn("result_info", res.reason)


class AccountWideBuckets(unittest.TestCase):
    run_scan = account_tests.AccountScans.run_scan

    def test_every_page_of_buckets_is_checked(self):
        routes = account_tests.granted_routes()
        routes[f"GET {A}/r2/buckets"] = paged([
            ({"buckets": [{"name": "snapshot-shots"}]}, {"cursor": "c1", "per_page": 1}),
            ({"buckets": [{"name": "second"}]}, {"per_page": 1})])
        routes[f"GET {A}/r2/buckets/second/domains/managed"] = ok({"bucketId": "b2", "domain": "pub-2.r2.dev", "enabled": True})
        routes[f"GET {A}/r2/buckets/second/domains/custom"] = ok({"domains": []})
        doc, _ = self.run_scan(routes, args=("--account-wide",))
        targets = sorted(f["target"] for f in by_rule(doc, "CF-R2-DEV-PUBLIC") if f["source"] == "api")
        self.assertEqual(targets, ["bucket second", "bucket snapshot-shots"])
        self.assertEqual([f["severity"] for f in by_rule(doc, "CF-R2-DEV-PUBLIC") if f["target"] == "bucket second"], ["suggestion"])


if __name__ == "__main__":
    unittest.main()
