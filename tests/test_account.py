"""Account layer: credential resolution, the read-only client guard, 200/403/401 mapping, token secrecy.

All HTTP goes to a local fake server (FakeCloudflare); nothing reaches the network.
"""

import contextlib
import copy
import datetime as dt
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _util
from _util import FakeCloudflare, by_rule, copy_fixture, denied, ok, scan, unauthorized
from nobill.providers.cloudflare import auth
from nobill.providers.cloudflare.client import USER_AGENT, Client, ReadOnlyViolation, assert_read_only

TOKEN = "tokSECRETvalue-0123456789abcdefABCDEF"
ACCT = "acc0123456789"
A = f"/accounts/{ACCT}"


@contextlib.contextmanager
def env(**values):
    old = {k: os.environ.get(k) for k in values}
    try:
        for k, v in values.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def write_wrangler_auth(path: Path, token: str, expires: dt.datetime | None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f'oauth_token = "{token}"', 'refresh_token = "refresh-should-never-be-read"']
    if expires is not None:
        lines.append(f'expiration_time = "{expires.isoformat().replace("+00:00", "Z")}"')
    lines.append('scopes = ["account:read", "workers_scripts:write"]')
    path.write_text("\n".join(lines) + "\n")


NOW = dt.datetime(2026, 10, 13, 12, 0, tzinfo=dt.timezone.utc)


class CredentialResolution(unittest.TestCase):
    def setUp(self):
        self.home = _util.temp_home()
        self.xdg = self.home / "xdg"
        self.ctx = env(HOME=str(self.home), XDG_CONFIG_HOME=str(self.xdg), CLOUDFLARE_API_TOKEN=None,
                       CLOUDFLARE_API_ENVIRONMENT=None)
        self.ctx.__enter__()

    def tearDown(self):
        self.ctx.__exit__(None, None, None)

    def test_env_token_wins(self):
        write_wrangler_auth(self.home / ".wrangler/config/default.toml", "oauth-1", NOW + dt.timedelta(hours=1))
        with env(CLOUDFLARE_API_TOKEN=TOKEN):
            c = auth.resolve(NOW)
        self.assertEqual(c.kind, "api-token")
        self.assertEqual(c.token.reveal(), TOKEN)

    def test_legacy_home_dir_is_wranglers_first_choice(self):
        write_wrangler_auth(self.home / ".wrangler/config/default.toml", "legacy-tok", NOW + dt.timedelta(hours=1))
        write_wrangler_auth(self.xdg / ".wrangler/config/default.toml", "xdg-tok", NOW + dt.timedelta(hours=1))
        c = auth.resolve(NOW)
        self.assertEqual(c.token.reveal(), "legacy-tok")
        self.assertIn("~/.wrangler/config/default.toml", c.source)

    def test_expired_file_falls_back_to_the_other_location(self):
        write_wrangler_auth(self.home / ".wrangler/config/default.toml", "old", NOW - dt.timedelta(days=50))
        write_wrangler_auth(self.xdg / ".wrangler/config/default.toml", "fresh", NOW + dt.timedelta(hours=2))
        c = auth.resolve(NOW)
        self.assertEqual(c.token.reveal(), "fresh")
        self.assertTrue(any("expired" in p for p in c.problems))

    def test_macos_preferences_path(self):
        with env(XDG_CONFIG_HOME=None), mock.patch.object(auth.platform, "system", return_value="Darwin"):
            write_wrangler_auth(self.home / "Library/Preferences/.wrangler/config/default.toml", "mac", NOW + dt.timedelta(hours=1))
            c = auth.resolve(NOW)
        self.assertEqual(c.token.reveal(), "mac")
        self.assertIn("Library/Preferences/.wrangler", c.source)

    def test_all_expired_means_no_token(self):
        write_wrangler_auth(self.home / ".wrangler/config/default.toml", "old", NOW - dt.timedelta(minutes=1))
        c = auth.resolve(NOW)
        self.assertIsNone(c.token)
        self.assertEqual(c.kind, "none")
        self.assertTrue(any("expired" in p for p in c.problems))
        self.assertFalse(any("wrangler whoami" in p for p in c.problems))

    def test_encrypted_login_is_reported(self):
        enc = self.home / ".wrangler/config/default.enc"
        enc.parent.mkdir(parents=True)
        enc.write_text("{}")
        c = auth.resolve(NOW)
        self.assertIsNone(c.token)
        self.assertTrue(any("encrypted" in p for p in c.problems))

    def test_secret_repr_is_redacted(self):
        s = auth.Secret(TOKEN)
        self.assertNotIn(TOKEN, repr(s))
        self.assertNotIn(TOKEN, str(s))
        self.assertNotIn(TOKEN, f"{s} {[s]} {dict(t=s)}")


class ReadOnlyGuard(unittest.TestCase):
    def test_allowed_and_rejected_requests(self):
        assert_read_only("GET", "/accounts", None)
        assert_read_only("POST", "/graphql", {"query": "query { viewer { zones { zoneTag } } }"})
        assert_read_only("POST", "/graphql", {"query": '{ viewer { a(filter: {name: "mutation x"}) { b } } }'})
        for method, path, body in [
            ("DELETE", "/accounts/a/workers/scripts/x", None),
            ("PUT", "/accounts/a/workers/scripts/x/subdomain", {"enabled": False}),
            ("PATCH", "/accounts/a/workers/scripts/x/settings", {}),
            ("POST", "/accounts/a/workers/scripts", {"query": "query { a }"}),
            ("POST", "/graphql", {"query": "mutation { deleteThing(id: 1) { ok } }"}),
            ("POST", "/graphql", {"query": "query A { a }\nmutation B { b }"}),
            ("POST", "/graphql", {"query": "subscription { a }"}),
            ("POST", "/graphql", {"mutation": "x"}),
            ("POST", "/graphql", {"query": "query { a }", "extensions": {}}),
            ("GET", "/accounts", {"body": 1}),
        ]:
            with self.assertRaises(ReadOnlyViolation, msg=f"{method} {path} {body}"):
                assert_read_only(method, path, body)

    def test_guard_runs_before_any_network_io(self):
        with FakeCloudflare({}) as fake:
            c = Client(auth.Secret(TOKEN), base=fake.base)
            with self.assertRaises(ReadOnlyViolation):
                c.request("DELETE", "/accounts/x")
            with self.assertRaises(ReadOnlyViolation):
                c.graphql("mutation { x }")
            self.assertEqual(fake.requests, [])

    def test_graphql_comments_and_strings_cannot_hide_a_mutation(self):
        hidden = [
            'query Safe { a }\n# """\nmutation Write { deleteAll { ok } }\n# """',
            'query Safe { a }\n"""doc"""\nmutation Write { b }',
            '"description" mutation Write { b }',
            'query Safe { a } # comment\nmutation Write { b }',
            'query Safe { a(s: "x\\" } mutation W { b }") { c } }\nmutation Write { d }',
            '{ a }\nsubscription S { b }',
            'query Q { a }\n{ b } mutation M { c }',
            'query Q { a ',          # unbalanced: undecidable, so refused
            'query Q { a(s: "open) }',
            'fragment F on T { a } mutation M { ...F }',
        ]
        with FakeCloudflare({}) as fake:
            c = Client(auth.Secret(TOKEN), base=fake.base)
            for q in hidden:
                with self.assertRaises(ReadOnlyViolation, msg=q):
                    assert_read_only("POST", "/graphql", {"query": q, "operationName": "Write"})
                with self.assertRaises(ReadOnlyViolation, msg=q):
                    c.graphql(q)
            self.assertEqual(fake.requests, [])
        for q in ['query Q($m: String = "mutation") { a(s: $m) }', '# mutation\nquery Q { a }',
                  'query Q { a } fragment F on T { b }', '{ a(s: """mutation { x }""") }',
                  'query Q @dir(arg: mutation) { a }', 'query Q { mutation: a }']:
            assert_read_only("POST", "/graphql", {"query": q})

    def test_only_cloudflare_or_local_bases(self):
        with self.assertRaises(ValueError):
            Client(auth.Secret(TOKEN), base="https://evil.example.com/client/v4")

    def test_redirects_are_not_followed(self):
        with FakeCloudflare({}) as other, FakeCloudflare({"GET /accounts": (302, {}, {"Location": "PLACEHOLDER"})}) as fake:
            fake.routes["GET /accounts"] = (302, {}, {"Location": other.base + "/steal"})
            res = Client(auth.Secret(TOKEN), base=fake.base).get("/accounts")
            self.assertFalse(res.ok)
            self.assertEqual(other.requests, [])

    def test_user_agent_is_not_python_urllib(self):
        with FakeCloudflare({"GET /accounts": ok([])}) as fake:
            Client(auth.Secret(TOKEN), base=fake.base).get("/accounts")
        self.assertEqual(fake.requests[0]["ua"], USER_AGENT)
        self.assertNotIn("Python-urllib", USER_AGENT)

    def test_network_error_has_no_token(self):
        c = Client(auth.Secret(TOKEN), base="http://127.0.0.1:9", timeout=2)
        res = c.get("/accounts")
        self.assertEqual(res.status, 0)
        self.assertIn("network error", res.reason)
        self.assertNotIn(TOKEN, res.reason)

    def test_malformed_credential_is_refused_with_a_constant_error(self):
        bad = TOKEN + "\nX-Injected: " + TOKEN
        with self.assertRaises(ValueError) as cm:
            Client(auth.Secret(bad), base="http://127.0.0.1:9")
        chain, exc = [], cm.exception
        while exc is not None:
            chain.append(f"{exc!s} {exc!r} {exc.args!r}")
            exc = exc.__cause__ or exc.__context__
        self.assertNotIn(TOKEN, " ".join(chain))
        self.assertTrue(cm.exception.__suppress_context__ or cm.exception.__context__ is None)

    def test_unexpected_transport_exception_is_sanitized(self):
        c = Client(auth.Secret(TOKEN), base="http://127.0.0.1:9")
        for err in (ValueError(f"Invalid header value b'Bearer {TOKEN}'"), RuntimeError(TOKEN),
                    OSError(f"connect failed for {TOKEN}")):
            with mock.patch.object(c._opener, "open", side_effect=err):
                res = c.get("/accounts")
            self.assertEqual(res.status, 0)
            self.assertFalse(res.ok)
            self.assertNotIn(TOKEN, res.reason + res.error_text())

    def test_client_scrubs_the_token_from_api_error_text(self):
        with FakeCloudflare({"GET /accounts": (400, {"success": False, "result": None,
                                                     "errors": [{"code": 1, "message": "bad auth " + TOKEN}, "raw " + TOKEN]})}) as fake:
            res = Client(auth.Secret(TOKEN), base=fake.base).get("/accounts")
        self.assertFalse(res.ok)
        self.assertNotIn(TOKEN, res.error_text() + res.reason + repr(res))
        self.assertIn("[REDACTED]", res.error_text())

    def test_env_token_with_header_breaking_characters_is_not_used(self):
        for bad in (TOKEN + "\nX: y", TOKEN + " trailing", "tok\u00e9n"):
            with env(CLOUDFLARE_API_TOKEN=bad):
                cred = auth.resolve(NOW)
            self.assertIsNone(cred.token, repr(bad))
            self.assertTrue(cred.problems)
            self.assertNotIn(TOKEN, " ".join(cred.problems) + cred.source)


def granted_routes():
    return {
        f"GET {A}/alerting/v3/policies": ok([{"id": "p1", "name": "Monthly budget", "alert_type": "billing_usage_alert",
                                               "enabled": True, "mechanisms": {"email": [{"id": "x@example.com"}]}}]),
        f"GET {A}/alerting/v3/available_alerts": ok({"Billing": [{"type": "billing_usage_alert", "display_name": "Usage Based Billing"}]}),
        f"GET {A}/workers/scripts/snapshot-api/settings": ok({
            "bindings": [{"type": "ai", "name": "AI"}, {"type": "browser", "name": "MYBROWSER"},
                         {"type": "images", "name": "IMAGES"}, {"type": "kv_namespace", "name": "SESSIONS"},
                         {"type": "r2_bucket", "name": "SHOTS"}, {"type": "assets", "name": "ASSETS"},
                         {"type": "secret_text", "name": "OPENAI_KEY"}],
            "observability": {"enabled": True}}),
        f"GET {A}/workers/scripts/snapshot-api/subdomain": ok({"enabled": True, "previews_enabled": False}),
        f"GET {A}/r2/buckets/snapshot-shots/domains/managed": ok({"bucketId": "b1", "domain": "pub-1.r2.dev", "enabled": True}),
        f"GET {A}/r2/buckets/snapshot-shots/domains/custom": ok({"domains": [{"domain": "img.example.com", "enabled": True}]}),
        f"GET {A}/ai-gateway/gateways": ok([{"id": "default", "spend_limits": {"enabled": True, "rules": [
            {"limit": 5, "limitType": "cost", "window": 86400}]}}]),
        "POST /graphql": (200, {"data": {"viewer": {"accounts": [{"workersInvocationsAdaptive": [
            {"sum": {"requests": 1200, "errors": 3, "subrequests": 80000}, "quantiles": {"cpuTimeP50": 900, "cpuTimeP99": 4000},
             "dimensions": {"scriptName": "snapshot-api"}}]}]}}, "errors": None}),
    }


class SharedRedaction(unittest.TestCase):
    """scan and render redact every credential resolvable here, whether or not the account layer ran."""

    def paste(self, findings: Path, *values: str) -> None:
        """An agent review that pastes credential values into the findings it edits."""
        doc = json.loads(findings.read_text())
        f = doc["findings"][0]
        f["title"] += " " + values[0]
        f["review"] = {"status": "confirmed", "reason": "checked with " + " and ".join(values)}
        f["evidence"].append({"kind": "note", "text": "header was Bearer " + values[-1]})
        unk = next(x for x in doc["findings"] if x["severity"] == "unknown")
        unk["missing"] += " (tried " + values[0] + ")"
        findings.write_text(json.dumps(doc, indent=2))

    def render_and_check(self, out: Path, env: dict, *values: str) -> None:
        cp = _util.run_cli(["render", str(out / "findings.json")], env=env)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        html, md = (out / "report.html").read_text(), (out / "report.md").read_text()
        for v in values:
            for name, blob in (("stdout", cp.stdout), ("stderr", cp.stderr), ("html", html), ("md", md)):
                self.assertFalse(v in blob, f"{v[:6]}... in {name}")
        self.assertIn("checked with [REDACTED]", html)
        self.assertIn("checked with \\[REDACTED\\]", md)
        self.assertIn("Bearer \\[REDACTED\\]", md)

    def test_render_redacts_an_env_token_pasted_during_review(self):
        # reviewer probe: a token added to findings.json after the scan reached report.md and report.html
        proj = copy_fixture("itty_open_ai")
        out = Path(tempfile.mkdtemp(prefix="nobill-red-"))
        scan(proj, out=out)
        self.paste(out / "findings.json", TOKEN)
        self.render_and_check(out, {"CLOUDFLARE_API_TOKEN": TOKEN, "HOME": str(_util.temp_home())}, TOKEN)

    def test_render_redacts_wrangler_login_values_even_expired(self):
        home = _util.temp_home()
        write_wrangler_auth(home / ".wrangler/config/default.toml", TOKEN, NOW - dt.timedelta(days=30))
        proj = copy_fixture("itty_open_ai")
        out = Path(tempfile.mkdtemp(prefix="nobill-red-"))
        scan(proj, out=out, env={"HOME": str(home)})
        self.paste(out / "findings.json", TOKEN, "refresh-should-never-be-read")
        self.render_and_check(out, {"HOME": str(home)}, TOKEN, "refresh-should-never-be-read")

    def test_scan_without_account_redacts_a_token_found_in_project_config(self):
        # the scan quotes config lines as evidence; a credential pasted on one must not reach any output
        proj = copy_fixture("itty_open_ai")
        cfg = proj / "wrangler.json"
        cfg.write_text(cfg.read_text().replace('"subrequests": 50000 }', '"subrequests": 50000 } // list.json?key=' + TOKEN))
        out = Path(tempfile.mkdtemp(prefix="nobill-red-"))
        doc, cp = scan(proj, out=out, env={"CLOUDFLARE_API_TOKEN": TOKEN, "HOME": str(_util.temp_home())})
        for name in ("findings.json", "report.html", "report.md"):
            self.assertFalse(TOKEN in (out / name).read_text(), name)
        self.assertFalse(TOKEN in cp.stdout + cp.stderr)
        self.assertIn("list.json?key=[REDACTED]", (out / "findings.json").read_text())


class AccountScans(unittest.TestCase):
    def run_scan(self, routes, *, token_env=True, extra_env=None, args=("--account",), fixture="itty_open_ai",
                 project=None):
        proj = project or copy_fixture(fixture)
        home = _util.temp_home()
        with FakeCloudflare(routes) as fake:
            e = {"HOME": str(home), "NOBILL_CLOUDFLARE_API_BASE": fake.base, "CLOUDFLARE_ACCOUNT_ID": ACCT}
            if token_env:
                e["CLOUDFLARE_API_TOKEN"] = TOKEN
            e.update(extra_env or {})
            out = Path(tempfile.mkdtemp(prefix="nobill-acct-"))
            doc, cp = scan(proj, out=out, extra=list(args), env=e)
        self.last_out = out
        html = (out / "report.html").read_text()
        raw = (out / "findings.json").read_text()
        md = (out / "report.md").read_text()
        for blob in (cp.stdout, cp.stderr, html, raw, md):
            self.assertNotIn(TOKEN, blob)
        doc_now = json.loads(raw)
        for f in doc_now["findings"]:  # the outputs are real reports, not empty files that trivially lack the token
            self.assertIn(f["rule"], md)
            self.assertIn(f["rule"], html)
        for r in fake.requests:
            self.assertEqual(r["ua"], USER_AGENT)
            self.assertIn(r["method"], ("GET", "POST"))
            if r["method"] == "POST":
                self.assertEqual(r["path"], "/graphql")
                body = json.loads(r["body"])
                self.assertIn("query", body)
                self.assertNotIn("mutation", body["query"])
        return doc, fake

    def test_granted_token_maps_200_to_pass_and_findings(self):
        doc, fake = self.run_scan(granted_routes())
        self.assertTrue(fake.requests and all(r["auth"] == "Bearer " + TOKEN for r in fake.requests))
        self.assertEqual(by_rule(doc, "CF-NO-BILLING-ALERT")[0]["severity"], "pass")
        live = [f for f in by_rule(doc, "CF-WORKERS-DEV-ON") if f["source"] == "api"]
        self.assertEqual([f["severity"] for f in live], ["suggestion"])
        r2 = [f for f in by_rule(doc, "CF-R2-DEV-PUBLIC") if f["source"] == "api"]
        self.assertEqual([f["severity"] for f in r2], ["suggestion"])
        self.assertTrue(any("custom domain" in e.get("text", "") for e in r2[0]["evidence"]))
        self.assertEqual(by_rule(doc, "CF-AI-GATEWAY-SPEND")[0]["severity"], "pass")
        self.assertEqual(by_rule(doc, "CF-CONFIG-DRIFT")[0]["severity"], "pass")
        usage = by_rule(doc, "CF-USAGE-SNAPSHOT")[0]
        self.assertEqual(usage["severity"], "suggestion")  # 80000 subrequests / 1200 requests: fan-out outlier
        self.assertEqual(usage["details"]["rows"][0]["requests_24h"], 1200)
        rows = {r["check"]: r for r in doc["scope_requirements"]}
        self.assertEqual(rows["alert_policies"]["status"], "granted")
        self.assertEqual(rows["graphql"]["status"], "granted")
        self.assertEqual(rows["accounts"]["status"], "not run")  # account id came from the environment
        self.assertFalse([f for f in doc["findings"] if f["source"] == "api" and f["severity"] == "unknown"])

    def test_not_run_scope_distinguishes_credentials_flags_and_excluded_scope(self):
        project = copy_fixture("itty_open_ai")
        home = _util.temp_home()
        write_wrangler_auth(home / ".wrangler/config/default.toml", TOKEN,
                            dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=3))
        for args, reason in (([], "--account"), (["--account"], "expired"),
                             (["--account-wide"], "expired")):
            with self.subTest(args=args):
                doc, cp = scan(project, extra=args, env={"HOME": str(home), "XDG_CONFIG_HOME": str(home / "xdg")})
                rows = {r["check"]: r for r in doc["scope_requirements"]}
                self.assertTrue(all(r["status"] == "not run" for r in rows.values()))
                self.assertIn(reason, rows["alert_policies"]["detail"])
                self.assertNotIn(TOKEN, json.dumps(doc) + cp.stdout + cp.stderr)
                self.assertNotIn("wrangler whoami", json.dumps(doc))
                for name in ("scripts", "r2_buckets"):
                    self.assertIn("expired" if "--account-wide" in args else "not requested", rows[name]["detail"])
        doc, _ = self.run_scan(granted_routes())
        rows = {r["check"]: r for r in doc["scope_requirements"]}
        self.assertIn("CLOUDFLARE_ACCOUNT_ID", rows["accounts"]["detail"])
        self.assertEqual(rows["settings"]["status"], "granted")

    def test_unrun_reads_name_their_actual_cause(self):
        selected = "not selected for the discovered project resources"
        for route, status in ((denied(), "denied (403)"),
                              ((500, {"success": False, "errors": [{"code": 1, "message": "boom"}]}), "error (500)")):
            with self.subTest(policies=status):
                routes = granted_routes()
                routes[f"GET {A}/alerting/v3/policies"] = route
                doc, _ = self.run_scan(routes)
                rows = {r["check"]: r for r in doc["scope_requirements"]}
                self.assertEqual(rows["alert_policies"]["status"], status)
                self.assertEqual(rows["available_alerts"]["status"], "not run")
                self.assertEqual(rows["available_alerts"]["detail"],
                                 f"not attempted: alert policies read failed ({status})")
        routes = granted_routes()
        routes[f"GET {A}/r2/buckets/snapshot-shots/domains/managed"] = ok({"enabled": False})
        doc, _ = self.run_scan(routes)
        rows = {r["check"]: r for r in doc["scope_requirements"]}
        for check in ("queues", "containers"):  # the itty project configures neither
            self.assertEqual((rows[check]["status"], rows[check]["detail"]), ("not run", selected))
        self.assertEqual(rows["r2_custom"]["detail"], "not attempted: read only for a bucket with r2.dev access enabled")
        routes = {f"GET {A}/r2/buckets": denied()}
        doc, _ = self.run_scan(routes, args=("--account-wide",), fixture="clean")  # no R2 binding in the project
        rows = {r["check"]: r for r in doc["scope_requirements"]}
        for check in ("r2_managed", "r2_custom"):
            self.assertEqual(rows[check]["detail"], "not attempted: r2_buckets listing failed (denied (403))")

    def test_malformed_prerequisite_listings_are_errors_and_name_the_failed_listing(self):
        """A 2xx with a malformed body is recorded as the error it becomes after shape validation, and the
        reads that depended on it name that failure instead of claiming resource selection."""
        shape = "unexpected response shape"
        routes = granted_routes()
        routes[f"GET {A}/alerting/v3/policies"] = ok([{}])
        doc, _ = self.run_scan(routes)
        rows = {r["check"]: r for r in doc["scope_requirements"]}
        with self.subTest(row="alert_policies"):
            self.assertEqual(rows["alert_policies"]["status"], "error")
            self.assertIn(shape, rows["alert_policies"]["detail"])
        with self.subTest(row="available_alerts"):
            self.assertEqual(rows["available_alerts"]["detail"], "not attempted: alert policies read failed (error)")

        pages = Path(tempfile.mkdtemp(prefix="nobill-pages-")) / "site"  # no Worker main, no R2 binding
        (pages / "public").mkdir(parents=True)
        (pages / "wrangler.toml").write_text('name = "site"\ncompatibility_date = "2026-09-01"\n'
                                            'pages_build_output_dir = "./public"\n')
        routes = {f"GET {A}/workers/scripts": ok([{}]), f"GET {A}/r2/buckets": ok({"buckets": [{}]})}
        doc, _ = self.run_scan(routes, args=("--account-wide",), project=pages)
        rows = {r["check"]: r for r in doc["scope_requirements"]}
        for listing, dependents in (("scripts", ("settings", "subdomain", "graphql")),
                                    ("r2_buckets", ("r2_managed", "r2_custom"))):
            with self.subTest(row=listing):
                self.assertEqual(rows[listing]["status"], "error")
                self.assertIn(shape, rows[listing]["detail"])
            for check in dependents:
                with self.subTest(row=check):
                    self.assertEqual((rows[check]["status"], rows[check]["detail"]),
                                     ("not run", f"not attempted: {listing} listing failed (error)"))

    def test_scope_rows_cover_every_check_and_aggregate_repeated_reads(self):
        from nobill.providers.cloudflare.account import CHECKS, Tracker
        from nobill.providers.cloudflare.client import ApiResult
        rows = Tracker().rows()
        self.assertEqual([r["check"] for r in rows], [c.id for c in CHECKS])
        for r in rows:  # nothing recorded: no cause is claimed
            self.assertEqual((r["status"], r["detail"]), ("not run", "not run; reason not recorded"))

        def res(status):
            r = ApiResult(status)
            if 200 <= status < 300:
                r.success = True
            return r

        t = Tracker()
        reads = {"settings": (200, 404), "subdomain": (200, 403), "r2_managed": (403, 500, 403),
                 "r2_custom": (0,), "queues": (403,), "graphql": (401,)}
        for check, statuses in reads.items():
            for st in statuses:
                t.record(check, res(st))
        got = {r["check"]: r["status"] for r in t.rows()}
        self.assertEqual({k: got[k] for k in reads}, {
            "settings": "granted", "subdomain": "partial: denied (403), granted",
            "r2_managed": "denied (403), error (500)", "r2_custom": "error",
            "queues": "denied (403)", "graphql": "unauthorized (401)"})

    def assert_scope_shape_error(self, doc, check, reason):
        row = next(r for r in doc["scope_requirements"] if r["check"] == check)
        self.assertEqual(row["status"], "error")
        # The prefix appears once even when the recorded reason already carries it (Opus review of a151e85, finding 2).
        self.assertEqual(row["detail"].count("unexpected response shape"), 1, row["detail"])
        self.assertIn(reason, row["detail"])

    def test_nested_billing_policy_errors_reach_scope_without_losing_other_reads(self):
        policy = {"alert_type": "billing_usage_alert", "name": "budget", "enabled": True}
        for bad, reason in ((dict(policy, enabled="true"), "enabled is not a boolean"),
                            ({k: v for k, v in policy.items() if k != "enabled"}, "enabled is not a boolean"),
                            (dict(policy, name=None), "name is not a string")):
            with self.subTest(policy=bad):
                routes = granted_routes()
                routes[f"GET {A}/alerting/v3/policies"] = ok([policy, bad])
                doc, _ = self.run_scan(routes)
                [unknown] = by_rule(doc, "CF-NO-BILLING-ALERT")
                self.assertEqual(unknown["severity"], "unknown")
                self.assertIn(reason, unknown["missing"])
                self.assertTrue(by_rule(doc, "CF-AI-GATEWAY-SPEND", "pass"))
                rows = {r["check"]: r for r in doc["scope_requirements"]}
                self.assertEqual(rows["available_alerts"]["status"], "granted")
                self.assert_scope_shape_error(doc, "alert_policies", reason)

    def test_nested_settings_errors_reach_scope_and_preserve_binding_observations(self):
        for obs, reason in ((None, "observability is not a table"),
                            ({"enabled": "true"}, "observability.enabled is not a boolean"),
                            ({"enabled": True, "logs": None}, "observability.logs is not a table"),
                            ({"enabled": True, "head_sampling_rate": -1}, "head_sampling_rate is not a number"),
                            ({"logs": {"head_sampling_rate": 2}}, "observability.logs.head_sampling_rate")):
            with self.subTest(observability=obs):
                routes = granted_routes()
                routes[f"GET {A}/workers/scripts/snapshot-api/settings"][1]["result"]["observability"] = obs
                doc, _ = self.run_scan(routes)
                live = [f for f in by_rule(doc, "CF-LOG-SAMPLING") if f["source"] == "api"]
                self.assertEqual([f["severity"] for f in live], ["unknown"])
                self.assertIn(reason, live[0]["missing"])
                self.assertTrue(by_rule(doc, "CF-CONFIG-DRIFT", "pass"))
                self.assertTrue(by_rule(doc, "CF-WORKERS-DEV-ON", "suggestion"))
                self.assert_scope_shape_error(doc, "settings", reason)

        routes = granted_routes()
        routes[f"GET {A}/workers/scripts/snapshot-api/settings"] = ok({"bindings": [None], "observability": None})
        doc, _ = self.run_scan(routes)
        for rule in ("CF-LOG-SAMPLING", "CF-CONFIG-DRIFT"):
            self.assertEqual([f["severity"] for f in by_rule(doc, rule) if f["source"] == "api"], ["unknown"])
        self.assert_scope_shape_error(doc, "settings", "observability is not a table")
        self.assert_scope_shape_error(doc, "settings", "settings.bindings")

    def test_nested_queue_errors_reach_scope_and_preserve_valid_consumers(self):
        good = {"settings": {"max_retries": 2}, "dead_letter_queue": "jobs-dlq"}
        for bad, reason in (({}, "queue_name"),
                            ({"queue_name": "bad", "consumers": None}, "consumers is not a list"),
                            ({"queue_name": "bad", "consumers": [good, {"settings": []}]}, "consumer settings"),
                            ({"queue_name": "bad", "consumers": [good, {"settings": {"max_retries": -1}}]},
                             "max_retries"),
                            ({"queue_name": "bad", "consumers": [good, {"dead_letter_queue": None}]},
                             "dead_letter_queue")):
            with self.subTest(queue=bad):
                routes = granted_routes()
                routes[f"GET {A}/queues"] = ok([{"queue_name": "jobs", "consumers": [good]}, bad])
                doc, _ = self.run_scan(routes, args=("--account-wide",))
                live = [f for f in by_rule(doc, "CF-QUEUE-CONSUMER-BOUNDS") if f["source"] == "api"]
                self.assertTrue(any(f["target"] == "queue jobs (live)" and f["severity"] == "pass" for f in live))
                if isinstance(bad.get("consumers"), list):
                    self.assertTrue(any(f["target"] == "queue bad (live)" and f["severity"] == "pass" for f in live))
                self.assertTrue(any(f["severity"] == "unknown" and reason in f["missing"] for f in live))
                self.assert_scope_shape_error(doc, "queues", reason)

    def test_nested_container_errors_reach_scope_and_preserve_valid_bounds(self):
        good = {"name": "bounded", "max_instances": 2}
        for bad, reason in (({}, "application entries without a string name"),
                            ({"name": "bad", "max_instances": "5"}, "max_instances is not a positive integer"),
                            ({"name": "bad", "max_instances": 0}, "max_instances is not a positive integer")):
            with self.subTest(container=bad):
                routes = granted_routes()
                routes[f"GET {A}/containers/applications"] = ok([good, bad])
                doc, _ = self.run_scan(routes, args=("--account-wide",))
                live = [f for f in by_rule(doc, "CF-CONTAINER-MAX-INSTANCES") if f["source"] == "api"]
                self.assertTrue(any(f["severity"] == "unknown" and reason in f["missing"] for f in live))
                # Bad entry names abort this whole finding; bad bounds do not discard sibling bounds.
                self.assertEqual(any(f["target"] == "container bounded (live)" and f["severity"] == "pass"
                                     for f in live), "name" in bad)
                self.assertTrue(by_rule(doc, "CF-NO-BILLING-ALERT", "pass"))
                self.assert_scope_shape_error(doc, "containers", reason)

    def test_nested_gateway_errors_reach_scope_without_inventing_a_partial_pass(self):
        rule = {"limit": 5, "window": 60, "limitType": "cost"}
        for bad, reason in (({}, "gateway needs a string id"),
                            ({"id": "bad", "spend_limits": None}, "spend_limits is not a table"),
                            ({"id": "bad", "spend_limits": {"enabled": "yes"}}, "enabled is not a boolean"),
                            ({"id": "bad", "spend_limits": {"enabled": True, "rules": None}}, "rules is not a list"),
                            ({"id": "bad", "spend_limits": {"enabled": True, "rules": [dict(rule, limit=0)]}},
                             "rules[0].limit is not a finite positive number"),
                            ({"id": "bad", "spend_limits": {"enabled": True, "rules": [dict(rule, enabled=None)]}},
                             "rules[0].enabled is not a boolean")):
            with self.subTest(gateway=bad):
                routes = granted_routes()
                routes[f"GET {A}/ai-gateway/gateways"][1]["result"].append(bad)
                doc, _ = self.run_scan(routes)
                [unknown] = by_rule(doc, "CF-AI-GATEWAY-SPEND")
                self.assertEqual(unknown["severity"], "unknown")
                self.assertIn(reason, unknown["missing"])
                self.assertTrue(by_rule(doc, "CF-NO-BILLING-ALERT", "pass"))
                self.assert_scope_shape_error(doc, "ai_gateways", reason)

    def test_nested_usage_errors_reach_scope_without_inventing_partial_analytics(self):
        good = granted_routes()["POST /graphql"][1]["data"]["viewer"]["accounts"][0]["workersInvocationsAdaptive"][0]
        oversized = dict(good, sum={"requests": 1e308, "errors": 0, "subrequests": 0})
        for rows, reason in (([good, {}], "malformed dimensions/sum/quantiles"),
                             ([good, dict(good, sum={"requests": "1200", "errors": 0, "subrequests": 1})],
                              "sum.requests is not finite and non-negative"),
                             ([good, dict(good, quantiles={"cpuTimeP99": -1})], "quantiles.cpuTimeP99"),
                             ([good, dict(good, quantiles=None)], "malformed dimensions/sum/quantiles"),
                             ([oversized, oversized], "sum.requests aggregate is oversized")):
            with self.subTest(reason=reason):
                routes = granted_routes()
                routes["POST /graphql"][1]["data"]["viewer"]["accounts"][0]["workersInvocationsAdaptive"] = copy.deepcopy(rows)
                doc, _ = self.run_scan(routes)
                [unknown] = by_rule(doc, "CF-USAGE-SNAPSHOT")
                self.assertEqual(unknown["severity"], "unknown")
                self.assertIn(reason, unknown["missing"])
                self.assertTrue(by_rule(doc, "CF-NO-BILLING-ALERT", "pass"))
                self.assertTrue(by_rule(doc, "CF-CONFIG-DRIFT", "pass"))
                self.assert_scope_shape_error(doc, "graphql", reason)

    def test_api_pass_prose_states_observed_facts_and_keeps_scope(self):
        routes = granted_routes()
        routes[f"GET {A}/workers/scripts/snapshot-api/subdomain"] = ok({"enabled": False, "previews_enabled": False})
        routes[f"GET {A}/r2/buckets/snapshot-shots/domains/managed"] = ok({"enabled": False})
        routes["POST /graphql"][1]["data"]["viewer"]["accounts"][0]["workersInvocationsAdaptive"][0]["sum"]["subrequests"] = 800
        doc, _ = self.run_scan(routes)
        expected = {"CF-NO-BILLING-ALERT": "not stop",
                    "CF-WORKERS-DEV-ON": "other",
                    "CF-R2-DEV-PUBLIC": "other",
                    "CF-CONFIG-DRIFT": "names",
                    "CF-AI-GATEWAY-SPEND": "routing",
                    "CF-USAGE-SNAPSHOT": "future"}
        for rule, scope in expected.items():
            found = [f for f in by_rule(doc, rule, "pass") if f["source"] == "api"]
            self.assertEqual(len(found), 1, rule)
            finding = found[0]
            self.assertIn(finding["title"], finding["why"]["text"])
            self.assertIn(scope, finding["why"]["text"])
            self.assertIn("No configuration change", finding["fix"]["text"])
        self.assertNotIn("bindings do not match", by_rule(doc, "CF-CONFIG-DRIFT")[0]["why"]["text"])

    def test_live_queues_dead_letter_consumers_are_not_flagged(self):
        routes = granted_routes()
        routes[f"GET {A}/queues"] = ok([
            {"queue_name": "jobs", "consumers": [{"settings": {"max_retries": 5}, "dead_letter_queue": "jobs-dlq"}]},
            {"queue_name": "jobs-dlq", "consumers": [{"settings": {"max_retries": 3}, "dead_letter_queue": ""}]},
            {"queue_name": "other", "consumers": [{"settings": {"max_retries": 3}, "dead_letter_queue": ""}]},
        ], result_info={"page": 1, "per_page": 20, "total_pages": 1})
        doc, _ = self.run_scan(routes, args=("--account-wide",))
        live = {f["target"]: f["severity"] for f in by_rule(doc, "CF-QUEUE-CONSUMER-BOUNDS") if f["source"] == "api"}
        self.assertEqual(live, {"queue jobs (live)": "pass", "queue jobs-dlq (live)": "pass",
                                "queue other (live)": "suggestion"})

    def test_no_listed_cost_policy_is_a_scoped_unknown(self):
        # PIN: owner-routed engineering decision 2026-10-22 (astra advisor), docs/261022-eval-ASTRA_REWRITE_REVIEW.md
        # The Notifications API may not list Billing budget alerts, and eligible pay-as-you-go accounts get a
        # default $10 budget alert since 2026-07-20: an unlisted policy is an unknown, never an alarm or a pass.
        routes = granted_routes()
        routes[f"GET {A}/alerting/v3/policies"] = ok([{"name": "ddos", "alert_type": "dos_attack_l7", "enabled": True}])
        doc, _ = self.run_scan(routes)
        [f] = by_rule(doc, "CF-NO-BILLING-ALERT")
        self.assertEqual(f["severity"], "unknown")
        self.assertEqual(f["confidence"], "heuristic")
        self.assertEqual(f["review"]["status"], "needs-review")
        self.assertEqual(f["title"], "No cost-alert policy listed by the Notifications API")
        self.assertEqual(f["evidence"][0]["kind"], "api")
        self.assertIn("among 1 policies", json.dumps(f["evidence"][0]))
        note = " ".join(e.get("text", "") for e in f["evidence"] if e["kind"] == "note")
        for fact in ("$10 default budget alert since 2026-07-20", "Billing > Billable Usage > Budget alerts",
                     "mark this false-positive"):
            self.assertIn(fact, note)

    def test_oauth_403_maps_to_unknown_naming_the_permission(self):
        routes = granted_routes()
        routes[f"GET {A}/alerting/v3/policies"] = denied()
        routes[f"GET {A}/ai-gateway/gateways"] = denied()
        routes["POST /graphql"] = (200, {"data": None, "errors": [{"message": "not authorized for that account"}]})
        home = _util.temp_home()
        write_wrangler_auth(home / ".wrangler/config/default.toml", TOKEN, dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=3))
        proj = copy_fixture("itty_open_ai")
        with FakeCloudflare(routes) as fake:
            out = Path(tempfile.mkdtemp())
            doc, cp = scan(proj, out=out, extra=["--account"], env={
                "HOME": str(home), "XDG_CONFIG_HOME": str(home / "xdg"), "NOBILL_CLOUDFLARE_API_BASE": fake.base,
                "CLOUDFLARE_ACCOUNT_ID": ACCT})
        for blob in (cp.stdout, cp.stderr, (out / "report.html").read_text(), (out / "findings.json").read_text(),
                     (out / "report.md").read_text()):
            self.assertNotIn(TOKEN, blob)
        self.assertNotIn("refresh-should-never-be-read", (out / "findings.json").read_text())
        alert = [f for f in by_rule(doc, "CF-NO-BILLING-ALERT") if f["severity"] == "unknown"]
        self.assertTrue(any("Notifications Read" in f["missing"] and "wrangler OAuth" in f["missing"] for f in alert))
        self.assertFalse(by_rule(doc, "CF-NO-BILLING-ALERT", "pass") + by_rule(doc, "CF-NO-BILLING-ALERT", "alarm"))
        gw = by_rule(doc, "CF-AI-GATEWAY-SPEND")[0]
        self.assertEqual(gw["severity"], "unknown")
        self.assertIn("AI Gateway Read", gw["missing"])
        usage = by_rule(doc, "CF-USAGE-SNAPSHOT")[0]
        self.assertEqual(usage["severity"], "unknown")
        self.assertIn("Account Analytics Read", usage["missing"])
        rows = {r["check"]: r["status"] for r in doc["scope_requirements"]}
        self.assertEqual(rows["alert_policies"], "denied (403)")
        self.assertEqual(rows["settings"], "granted")
        self.assertIn("wrangler OAuth", doc["provider_info"]["cloudflare"]["account"]["auth"])

    def test_malformed_env_token_never_reaches_output(self):
        bad = TOKEN + "\nX-Injected: " + TOKEN
        proj = copy_fixture("itty_open_ai")
        with FakeCloudflare(granted_routes()) as fake:
            out = Path(tempfile.mkdtemp())
            cp = _util.run_cli(["scan", str(proj), "--out", str(out), "--account"], env={
                "HOME": str(_util.temp_home()), "NOBILL_CLOUDFLARE_API_BASE": fake.base,
                "CLOUDFLARE_ACCOUNT_ID": ACCT, "CLOUDFLARE_API_TOKEN": bad})
        self.assertEqual(cp.returncode, 0, "scan crashed")
        for blob in (cp.stdout, cp.stderr, (out / "report.html").read_text(), (out / "findings.json").read_text(),
                     (out / "report.md").read_text()):
            self.assertNotIn(TOKEN, blob)
        self.assertEqual(fake.requests, [])
        doc = json.loads((out / "findings.json").read_text())
        f = by_rule(doc, "CF-NO-BILLING-ALERT")[0]
        self.assertEqual(f["severity"], "unknown")
        self.assertIn("not valid in an HTTP header", f["missing"])

    def test_api_responses_echoing_the_token_are_redacted(self):
        routes = granted_routes()
        # a hostile or buggy API echoes the credential in error text and in result fields
        routes[f"GET {A}/ai-gateway/gateways"] = (400, {"success": False, "result": None,
                                                         "errors": [{"code": 1, "message": "bad auth " + TOKEN}]})
        routes[f"GET {A}/alerting/v3/policies"] = ok([{"name": "budget " + TOKEN, "alert_type": "billing_usage_alert",
                                                         "enabled": True}])
        routes[f"GET {A}/r2/buckets/snapshot-shots/domains/managed"] = ok({"domain": TOKEN + ".r2.dev", "enabled": True})
        doc, _ = self.run_scan(routes)  # run_scan asserts the token is absent from stdout/stderr/JSON/HTML
        gw = by_rule(doc, "CF-AI-GATEWAY-SPEND")[0]
        self.assertEqual(gw["severity"], "unknown")
        self.assertIn("[REDACTED]", gw["missing"])
        md = (self.last_out / "report.md").read_text()
        self.assertIn("bad auth \\[REDACTED\\]", md)  # the echoed error is in the handoff, redacted

    def test_malformed_200_responses_are_unknown_never_pass(self):
        """A 200 whose envelope says success=false, or whose fields are missing or mistyped, proves nothing."""
        failed = (200, {"success": False, "errors": [], "messages": [], "result": None})
        cases = {
            "CF-WORKERS-DEV-ON": [
                (f"GET {A}/workers/scripts/snapshot-api/subdomain", ok({})),
                (f"GET {A}/workers/scripts/snapshot-api/subdomain", ok({"enabled": "false", "previews_enabled": 0})),
                (f"GET {A}/workers/scripts/snapshot-api/subdomain", ok({"enabled": False})),
                (f"GET {A}/workers/scripts/snapshot-api/subdomain",
                 (200, {"success": False, "errors": [], "result": {"enabled": False, "previews_enabled": False}})),
                (f"GET {A}/workers/scripts/snapshot-api/subdomain",
                 (200, {"result": {"enabled": False, "previews_enabled": False}})),  # no envelope at all
            ],
            "CF-R2-DEV-PUBLIC": [
                (f"GET {A}/r2/buckets/snapshot-shots/domains/managed", ok({"enabled": "no"})),
                (f"GET {A}/r2/buckets/snapshot-shots/domains/managed", ok({"enabled": None})),
                (f"GET {A}/r2/buckets/snapshot-shots/domains/managed", failed),
            ],
            "CF-NO-BILLING-ALERT": [
                (f"GET {A}/alerting/v3/policies", failed),
                (f"GET {A}/alerting/v3/policies", ok([{"name": "budget", "alert_type": "billing_usage_alert"}])),
                (f"GET {A}/alerting/v3/policies", ok([{"name": "budget", "alert_type": "billing_usage_alert", "enabled": "true"}])),
                (f"GET {A}/alerting/v3/policies", ok(["billing_usage_alert"])),
            ],
            "CF-AI-GATEWAY-SPEND": [
                (f"GET {A}/ai-gateway/gateways", ok([{"id": "g", "spend_limits": {"enabled": "yes", "rules": "lots"}}])),
                (f"GET {A}/ai-gateway/gateways", ok([{"id": "g", "spend_limits": {"enabled": True, "rules": [{}]}}, "junk"])),
                (f"GET {A}/ai-gateway/gateways", failed),
            ],
            "CF-USAGE-SNAPSHOT": [
                ("POST /graphql", (200, {"data": {"viewer": {"accounts": [{"workersInvocationsAdaptive": [
                    {"sum": {"requests": "1200", "errors": 0, "subrequests": 1}, "quantiles": {},
                     "dimensions": {"scriptName": "snapshot-api"}}]}]}}})),
                ("POST /graphql", (200, {"data": {"viewer": {"accounts": [{"workersInvocationsAdaptive": ["x"]}]}}})),
                ("POST /graphql", (200, {"data": None})),
            ],
        }
        for rule, variants in cases.items():
            for key, resp in variants:
                with self.subTest(rule=rule, key=key, resp=resp):
                    routes = granted_routes()
                    routes[key] = resp
                    doc, _ = self.run_scan(routes)
                    live = [f for f in by_rule(doc, rule) if f["source"] == "api"]
                    self.assertTrue(live, "no live finding at all")
                    self.assertFalse([f for f in live if f["severity"] == "pass"], live)
                    self.assertTrue([f for f in live if f["severity"] == "unknown"], [f["severity"] for f in live])

    def test_non_finite_and_negative_live_numbers_are_unknown(self):
        # Python's json accepts NaN / Infinity, which compare false with every bound (and int() of them
        # raises): such a value, or a negative count, is malformed data, never a valid count or a pass
        nan, inf = float("nan"), float("inf")

        def usage(**over):
            row = {"sum": {"requests": 1200, "errors": 3, "subrequests": 80}, "quantiles": {"cpuTimeP50": 900},
                   "dimensions": {"scriptName": "snapshot-api"}}
            for k, v in over.items():
                (row["quantiles"] if k.startswith("cpu") else row["sum"])[k] = v
            return ("POST /graphql", (200, {"data": {"viewer": {"accounts": [{"workersInvocationsAdaptive": [row]}]}}}))

        def gateway(**over):
            rule = {"limit": 5, "limitType": "cost", "window": 86400, **over}
            return (f"GET {A}/ai-gateway/gateways", ok([{"id": "g", "spend_limits": {"enabled": True, "rules": [rule]}}]))

        cases = {
            "CF-USAGE-SNAPSHOT": [usage(requests=nan), usage(requests=inf), usage(subrequests=-inf),
                                  usage(requests=-5), usage(cpuTimeP50=nan)],
            "CF-AI-GATEWAY-SPEND": [gateway(limit=inf), gateway(window=nan)],
        }
        for rule, variants in cases.items():
            for key, resp in variants:
                with self.subTest(rule=rule, resp=json.dumps(resp[1])[:160]):
                    routes = granted_routes()
                    routes[key] = resp
                    doc, _ = self.run_scan(routes)
                    live = [f for f in by_rule(doc, rule) if f["source"] == "api"]
                    self.assertEqual([f["severity"] for f in live], ["unknown"])

    def test_live_sampling_of_an_unconfigured_worker(self):
        # a Worker found only with --account-wide: its live observability block decides the sampling result
        def run(observability):
            routes = granted_routes()
            routes[f"GET {A}/workers/scripts"] = ok([{"id": "snapshot-api"}, {"id": "other"}])
            routes[f"GET {A}/workers/scripts/other/settings"] = ok({"bindings": [], "observability": observability})
            routes[f"GET {A}/workers/scripts/other/subdomain"] = ok({"enabled": False, "previews_enabled": False})
            doc, _ = self.run_scan(routes, args=("--account-wide",))
            found = [f for f in by_rule(doc, "CF-LOG-SAMPLING") if f["target"] == "other (live)"]
            return [f["severity"] for f in found], found

        unknown = {
            "string rate": {"enabled": True, "head_sampling_rate": "0.1"},
            "rate above 1": {"enabled": True, "head_sampling_rate": 1.5},
            "negative rate": {"enabled": True, "logs": {"head_sampling_rate": -0.1}},
            "logs not an object": {"enabled": True, "logs": "on"},
            "observability not an object": "on",
            "enabled not a boolean": {"enabled": "true", "head_sampling_rate": 1},
        }
        for name, obs in unknown.items():
            with self.subTest(name):
                sevs, found = run(obs)
                self.assertEqual(sevs, ["unknown"], name)
                self.assertTrue(found[0]["missing"].strip())
        for name, (obs, expected) in {"unset rate": ({"enabled": True}, ["suggestion"]),
                                      "rate 1": ({"logs": {"enabled": True, "head_sampling_rate": 1}}, ["suggestion"]),
                                      "rate 0.1": ({"enabled": True, "head_sampling_rate": 0.1}, []),
                                      "logs off": ({"enabled": False}, [])}.items():
            with self.subTest(name):
                self.assertEqual(run(obs)[0], expected, name)

    def test_errors_field_that_is_not_a_list_is_a_malformed_envelope(self):
        # reviewer probe: success=true, errors={"message": "failed"}, plus a valid result
        for errors in ({"message": "failed"}, "failed", {}, 0):
            with self.subTest(errors=errors):
                routes = granted_routes()
                routes[f"GET {A}/workers/scripts/snapshot-api/subdomain"] = (200, {
                    "success": True, "errors": errors, "messages": [],
                    "result": {"enabled": False, "previews_enabled": False}})
                doc, _ = self.run_scan(routes)
                live = [f for f in by_rule(doc, "CF-WORKERS-DEV-ON") if f["source"] == "api"]
                self.assertEqual([f["severity"] for f in live], ["unknown"])
                self.assertIn("errors", live[0]["missing"])

    def test_spend_limit_passes_only_on_a_real_bound(self):
        gw = f"GET {A}/ai-gateway/gateways"

        def with_rules(rules):
            routes = granted_routes()
            routes[gw] = ok([{"id": "default", "spend_limits": {"enabled": True, "rules": rules}}])
            doc, _ = self.run_scan(routes)
            return [f["severity"] for f in by_rule(doc, "CF-AI-GATEWAY-SPEND") if f["source"] == "api"]

        good = {"limit": 5, "limitType": "cost", "window": 86400}
        cases = {
            "reviewer probe: empty rule": ([{}], "unknown"),
            "zero limit": ([{**good, "limit": 0}], "unknown"),
            "string limit": ([{**good, "limit": "5"}], "unknown"),
            "missing window": ([{"limit": 5, "limitType": "cost"}], "unknown"),
            "string window": ([{**good, "window": "1d"}], "unknown"),
            "unknown limit type": ([{**good, "limitType": "requests"}], "unknown"),
            "one bad among good": ([good, {}], "unknown"),
            "only a disabled rule": ([{**good, "enabled": False}], "suggestion"),
            "no rules": ([], "suggestion"),
            "real bound": ([good], "pass"),
            "snake_case limit_type": ([{"limit": 2.5, "limit_type": "cost", "window": 3600, "enabled": True}], "pass"),
        }
        for name, (rules, expected) in cases.items():
            with self.subTest(name):
                self.assertEqual(with_rules(rules), [expected])

    def test_gateway_context_is_collected_without_an_ai_binding(self):
        # design 261020 section 7: an SDK-only project declares no AI binding, so the Gateway check no
        # longer waits for one; it reports account facts and leaves application routing to the reviewer
        gw = f"GET {A}/ai-gateway/gateways"
        cases = {
            "no spend limits": (ok([{"id": "default", "spend_limits": {"enabled": False, "rules": []}}]),
                                "suggestion", "heuristic", "No AI Gateway spend limits observed"),
            "no gateway": (ok([]), "suggestion", "heuristic", "No AI Gateway in this account"),
            "one of two limited": (ok([{"id": "default", "spend_limits": {"enabled": True, "rules": [
                {"limit": 5, "limitType": "cost", "window": 86400}]}}, {"id": "direct"}]),
                                   "pass", "certain", "AI Gateway spend limits enabled on 1 of 2 gateway(s)"),
            "denied": (denied(), "unknown", "certain", None),
        }
        for name, (route, severity, confidence, title) in cases.items():
            with self.subTest(name):
                routes = {gw: route, f"GET {A}/alerting/v3/policies": ok([])}
                doc, fake = self.run_scan(routes, fixture="do_alarm_loop")
                self.assertIn(f"/accounts/{ACCT}/ai-gateway/gateways", [r["path"] for r in fake.requests])
                found = [f for f in by_rule(doc, "CF-AI-GATEWAY-SPEND") if f["source"] == "api"]
                self.assertEqual([(f["severity"], f["confidence"]) for f in found], [(severity, confidence)])
                f = found[0]
                if title:
                    self.assertEqual(f["title"], title)
                    notes = " ".join(e.get("text", "") for e in f["evidence"])
                    self.assertIn("whether the application's AI calls", notes)  # no claim about app routing
                if name == "one of two limited":
                    self.assertTrue(any(e.get("value") == "no enabled rule on direct" for e in f["evidence"]))
                if severity == "suggestion":
                    self.assertEqual(f["review"]["status"], "needs-review")
                    self.assertIn("no AI binding is declared", notes)

    def test_gateway_check_is_listed_offline_without_an_ai_binding(self):
        proj = copy_fixture("do_alarm_loop")
        doc, _ = scan(proj)
        gw = by_rule(doc, "CF-AI-GATEWAY-SPEND", "unknown")
        self.assertEqual(len(gw), 1)
        self.assertIn("--account", gw[0]["missing"])

    def test_malformed_live_queue_and_container_fields_are_unknown(self):
        routes = granted_routes()
        routes[f"GET {A}/queues"] = ok([
            {"queue_name": "jobs", "consumers": [{"settings": {"max_retries": "5"}, "dead_letter_queue": "jobs-dlq"}]},
            {"queue_name": "jobs-dlq", "consumers": [{"settings": {"max_retries": "3"}, "dead_letter_queue": ""}]},
            {"queue_name": "weird", "consumers": "none"},
        ])  # Pagination metadata has its own literal-input regressions in test_live_values.
        routes[f"GET {A}/containers/applications"] = ok([{"name": "snapshot-api-c", "max_instances": "5"}])
        doc, _ = self.run_scan(routes, args=("--account-wide",))
        q = {f["target"]: f["severity"] for f in by_rule(doc, "CF-QUEUE-CONSUMER-BOUNDS") if f["source"] == "api"}
        self.assertEqual(q.get("queue jobs-dlq (live)"), "unknown")
        self.assertEqual(q.get("queue weird (live)"), "unknown")
        self.assertNotEqual(q.get("queue jobs (live)"), "pass")
        c = [f for f in by_rule(doc, "CF-CONTAINER-MAX-INSTANCES") if f["source"] == "api"]
        self.assertEqual([f["severity"] for f in c], ["unknown"])

    def test_envelope_success_is_required(self):
        with FakeCloudflare({"GET /accounts": (200, {"success": False, "errors": [], "result": [{"id": "a"}]}),
                             "GET /zones": (200, {"result": []}),
                             "GET /user": ok({"id": "u"}),
                             "POST /graphql": (200, {"data": {"viewer": {}}})}) as fake:
            c = Client(auth.Secret(TOKEN), base=fake.base)
            self.assertFalse(c.get("/accounts").ok)
            self.assertIn("success", c.get("/accounts").error_text())
            self.assertFalse(c.get("/zones").ok)
            self.assertTrue(c.get("/user").ok)
            self.assertTrue(c.graphql("{ viewer { a } }").ok)

    def test_401_is_unknown_never_pass(self):
        routes = {k: unauthorized() for k in granted_routes()}
        doc, _ = self.run_scan(routes)
        api = [f for f in doc["findings"] if f["source"] == "api"]
        self.assertTrue(api)
        self.assertEqual({f["severity"] for f in api}, {"unknown"})
        self.assertTrue(all("401" in f["missing"] or "only be confirmed in the dashboard" in f["missing"] for f in api))

    def test_no_credentials_is_unknown(self):
        doc, fake = self.run_scan(granted_routes(), token_env=False)
        self.assertEqual(fake.requests, [])
        f = by_rule(doc, "CF-NO-BILLING-ALERT")[0]
        self.assertEqual(f["severity"], "unknown")
        self.assertIn("CLOUDFLARE_API_TOKEN", f["missing"])

    def test_ambiguous_account_is_unknown(self):
        routes = granted_routes()
        routes["GET /accounts"] = ok([{"id": "a1", "name": "one"}, {"id": "a2", "name": "two"}])
        doc, _ = self.run_scan(routes, extra_env={"CLOUDFLARE_ACCOUNT_ID": ""})
        f = by_rule(doc, "CF-NO-BILLING-ALERT")[0]
        self.assertEqual(f["severity"], "unknown")
        self.assertIn("--account-id", f["missing"])


if __name__ == "__main__":
    unittest.main()
