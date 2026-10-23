"""Optional live account checks (layer c), read-only.

Every check ends as pass, alarm/suggestion, or unknown. 401/403/network errors
and unparseable responses are unknown and name the permission or reason; they
are never read as "nothing configured".
"""

from __future__ import annotations

import datetime as _dt
import os
import re
from dataclasses import dataclass, field
from typing import Any

from ...findings import Evidence, Finding
from .auth import Credential
from .client import API_BASE, ApiResult, Client
from .rules import RULES
from .wrangler import Project, WorkerView
from .values import MISSING, is_int as _is_int, is_num as _is_num, shown, sampling


@dataclass(frozen=True)
class Check:
    id: str
    endpoint: str
    permission: str
    purpose: str


CHECKS: list[Check] = [
    Check("accounts", "GET /accounts", "Account Settings Read (any account-level read works)",
          "find the account id when it is not configured"),
    Check("alert_policies", "GET /accounts/{account_id}/alerting/v3/policies", "Notifications Read (or Account Settings Read)",
          "billing / budget / usage notification policies"),
    Check("available_alerts", "GET /accounts/{account_id}/alerting/v3/available_alerts", "Notifications Read (or Account Settings Read)",
          "which alert types are budget/billing alerts"),
    Check("scripts", "GET /accounts/{account_id}/workers/scripts", "Workers Scripts Read",
          "list every Worker (--account-wide)"),
    Check("subdomain", "GET /accounts/{account_id}/workers/scripts/{script}/subdomain", "Workers Scripts Read",
          "live workers.dev and preview URL state"),
    Check("settings", "GET /accounts/{account_id}/workers/scripts/{script}/settings", "Workers Scripts Read",
          "live bindings (drift) and log sampling"),
    Check("queues", "GET /accounts/{account_id}/queues", "Queues Read (or Workers Scripts Read)",
          "live consumer max_retries / dead-letter queue"),
    Check("r2_buckets", "GET /accounts/{account_id}/r2/buckets", "Workers R2 Storage Read",
          "list every bucket (--account-wide)"),
    Check("r2_managed", "GET /accounts/{account_id}/r2/buckets/{bucket}/domains/managed", "Workers R2 Storage Read",
          "public r2.dev access"),
    Check("r2_custom", "GET /accounts/{account_id}/r2/buckets/{bucket}/domains/custom", "Workers R2 Storage Read",
          "custom domains next to r2.dev"),
    Check("containers", "GET /accounts/{account_id}/containers/applications", "Containers Read",
          "deployed container max_instances"),
    Check("ai_gateways", "GET /accounts/{account_id}/ai-gateway/gateways", "AI Gateway Read",
          "AI Gateway spend limits"),
    Check("graphql", "POST /graphql (query only)", "Account Analytics Read",
          "last-24h requests, errors, subrequests, CPU per Worker"),
]
CHECK_BY_ID = {c.id: c for c in CHECKS}

TOKEN_PERMISSIONS = [
    "Account Settings Read", "Notifications Read", "Account Analytics Read", "Workers Scripts Read",
    "Queues Read", "Workers R2 Storage Read", "Containers Read", "AI Gateway Read",
]
TOKEN_INSTRUCTIONS = (
    "Create a custom read-only API token: dash.cloudflare.com > My Profile > API Tokens > Create Token > "
    "Create Custom Token; add Account permissions " + ", ".join(TOKEN_PERMISSIONS) + "; Account Resources: "
    "Include your account; then `export CLOUDFLARE_API_TOKEN=<token>` and re-run with --account. "
    "All of these are Read permissions, so the token cannot change anything."
)
OAUTH_NOTE = ("wrangler's OAuth login has no Notifications, Account Analytics or AI Gateway scope, so those checks "
              "stay unknown under it; a custom API token with the permissions above covers every check.")

PAID_LIVE_TYPES = {"ai": "Workers AI", "browser": "Browser Run", "images": "Images", "send_email": "send_email"}
NON_BINDING_TYPES = {"secret_text", "plain_text", "json", "secret_key", "version_metadata", "inherit", "assets"}


NOT_SELECTED = "not selected for the discovered project resources"
ALERT_POLICY_UNLISTED = (
    "No enabled cost-alert policy among the listed Notifications policies. Dashboard budget-alert state is "
    "unverified: this API may not list budget alerts created under Billing, and eligible pay-as-you-go "
    "accounts receive a $10 default budget alert since 2026-07-20 that can be edited or removed. Confirm in "
    "Billing > Billable Usage > Budget alerts; if one exists, mark this false-positive and say where it was "
    "seen.")


SHAPE_PREFIX = "unexpected response shape: "


def _strip_shape_prefix(reason: str) -> str:
    return reason[len(SHAPE_PREFIX):] if reason.startswith(SHAPE_PREFIX) else reason


def read_status(res: ApiResult | None) -> str:
    """The scope-row status of one read."""
    if res is None:
        return "not run"
    if res.ok:
        return "granted"
    if res.status == 403:
        return "denied (403)"
    if res.status == 401:
        return "unauthorized (401)"
    if res.status == 404:
        return "not found (404)"
    if res.status == 0:
        return "error"
    return f"error ({res.status})"


@dataclass
class Tracker:
    statuses: dict[str, list[str]] = field(default_factory=dict)
    details: dict[str, list[str]] = field(default_factory=dict)
    # Rows the code skips name their own cause; this covers only a read whose skip was never recorded.
    not_run_reason: str = "not run; reason not recorded"

    def record(self, check: str, res: ApiResult | None, note: str = "", *,
               shape_errors: list[str] | None = None) -> None:
        """Finalize a read after consumed-field validation, without invalidating sibling observations."""
        st = "error" if shape_errors else read_status(res)
        self.statuses.setdefault(check, []).append(st)
        # One "unexpected response shape:" detail per read: reasons that already carry the prefix
        # (a _bad_shape result or a prefixed reason) are folded in, not prefixed twice.
        reasons = [_strip_shape_prefix(e) for e in (shape_errors or [])]
        text = note or (res.error_text() if res is not None and not res.ok else "") or ""
        if reasons and text.startswith(SHAPE_PREFIX):
            reasons.insert(0, _strip_shape_prefix(text))
            text = ""
        if text:
            self.details.setdefault(check, []).append(text)
        if reasons:
            self.details.setdefault(check, []).append(SHAPE_PREFIX + "; ".join(reasons))

    def rows(self) -> list[dict[str, Any]]:
        rows = []
        for c in CHECKS:
            sts = self.statuses.get(c.id, [])
            if not sts:
                status = "not run"
            elif "granted" in sts and all(s == "granted" or s.startswith("not found") for s in sts):
                status = "granted"
            elif "granted" in sts:
                status = "partial: " + ", ".join(sorted(set(sts)))
            else:
                status = sorted(set(sts))[0] if len(set(sts)) == 1 else ", ".join(sorted(set(sts)))
            detail = "; ".join(dict.fromkeys(self.details.get(c.id, [])))
            if status == "not run" and not detail:
                detail = self.not_run_reason
            rows.append({"provider": "cloudflare", "check": c.id, "endpoint": c.endpoint, "permission": c.permission,
                         "purpose": c.purpose, "status": status, "detail": detail})
        return rows


def _is_bool(v: Any) -> bool:
    return isinstance(v, bool)


def _is_count(v: Any) -> bool:
    return _is_num(v) and v >= 0


def _bad_shape(res: ApiResult, what: str) -> ApiResult:
    """A 2xx whose fields are missing or mistyped proves nothing: report it as unknown."""
    res.status, res.reason = 0, f"unexpected response shape: {what} ({shown(res.result)})"
    return res


def _unknown_reason(res: ApiResult, check: Check, cred: Credential) -> str:
    if res.status == 403:
        extra = " (wrangler OAuth logins do not have it; use an API token)" if cred.kind == "wrangler-oauth" else ""
        return f"needs '{check.permission}' - denied (403){extra}"
    if res.status == 401:
        return "token rejected (401): expired or revoked; a valid read-only credential is needed, not refreshed by this audit"
    if res.status == 404:
        return f"not found (404): {res.error_text() or 'resource does not exist on this account'}"
    if res.status == 0:
        return f"could not check: {res.reason or 'no response'}"
    return f"could not check: {res.error_text() or 'HTTP ' + str(res.status)}"


class AccountAudit:
    def __init__(self, project: Project, cred: Credential, *, account_wide: bool, account_id: str | None,
                 api_base: str = API_BASE):
        self.project = project
        self.cred = cred
        self.account_wide = account_wide
        self.account_id_opt = account_id
        self.api_base = api_base
        self.track = Tracker()
        self.listings: dict[str, ApiResult] = {}  # --account-wide listings, after shape validation
        if not account_wide:
            for check in ("scripts", "r2_buckets"):
                self.track.record(check, None, "not requested: account-wide listing requires --account-wide")
        self.findings: list[Finding] = []
        self.info: dict[str, Any] = {}

    # -- helpers ---------------------------------------------------------------------
    def add(self, rule: str, severity: str, evidence: list[Evidence], **kw) -> None:
        kw.setdefault("confidence", "certain")
        kw.setdefault("source", "api")
        self.findings.append(RULES[rule].finding(severity, evidence=evidence, **kw))

    def skipped(self, checks: tuple[str, ...], listing: str) -> None:
        """Record reads skipped because no resource was selected for them; when the --account-wide
        listing that would have selected resources failed (after shape validation), that failure is the cause."""
        res = self.listings.get(listing)
        why = (f"not attempted: {listing} listing failed ({read_status(res)})" if res is not None and not res.ok
               else NOT_SELECTED)
        for check in checks:
            if check not in self.track.statuses:
                self.track.record(check, None, why)

    def unknown(self, rule: str, missing: str, target: str | None = None, endpoint: str | None = None,
                title: str | None = None) -> None:
        ev = [Evidence.api(endpoint)] if endpoint else [Evidence.note(missing)]
        self.add(rule, "unknown", ev, missing=missing, target=target,
                 title=title or ("Not checked: " + RULES[rule].title[0].lower() + RULES[rule].title[1:]))

    def project_scripts(self) -> dict[str, WorkerView]:
        return {w.name: w for w in self.project.workers if w.get("main")}

    def relevant_rules(self) -> list[tuple[str, str | None]]:
        rules: list[tuple[str, str | None]] = [("CF-NO-BILLING-ALERT", "account")]
        if any(w.paid_binding_kinds() for w in self.project.workers) or self.account_wide:
            rules.append(("CF-WORKERS-DEV-ON", "live workers.dev / preview state"))
        if any(w.r2_bindings() for w in self.project.workers) or self.account_wide:
            rules.append(("CF-R2-DEV-PUBLIC", "R2 buckets"))
        # collected whenever the account layer runs: a project can call AI through an SDK or HTTP with no binding
        rules.append(("CF-AI-GATEWAY-SPEND", "AI Gateway"))
        if any(w.containers() for w in self.project.workers):
            rules.append(("CF-CONTAINER-MAX-INSTANCES", "deployed containers"))
        if self.project_scripts() or self.account_wide:
            rules.append(("CF-USAGE-SNAPSHOT", "Worker analytics"))
        return rules

    # -- entry -----------------------------------------------------------------------
    def not_run(self, reason: str) -> None:
        self.track.not_run_reason = reason
        for rule, target in self.relevant_rules():
            self.unknown(rule, reason, target=target)

    def run(self) -> None:
        self.info["auth"] = self.cred.source
        if self.cred.problems:
            self.info["auth_problems"] = self.cred.problems
        if self.cred.token is None:
            reason = ("no usable credentials: a valid read-only CLOUDFLARE_API_TOKEN or Wrangler login is needed; "
                      "credential provisioning/refresh is outside this audit")
            if self.cred.problems:
                reason += " [" + "; ".join(self.cred.problems) + "]"
            self.not_run(reason)
            return
        try:
            client = Client(self.cred.token, base=self.api_base)
        except ValueError as exc:  # constant, token-free message
            self.not_run(f"account layer not run: {exc}")
            return
        acct = self._account_id(client)
        if acct is None:
            return
        self.info["account_id"] = acct
        if "accounts" not in self.track.statuses:
            self.track.record("accounts", None, "account id supplied by " + self.info["account_id_source"])
        a = f"/accounts/{acct}"
        scripts = self.project_scripts()
        live_scripts: dict[str, dict] = {}
        if self.account_wide:
            res = client.get_all(f"{a}/workers/scripts")
            if res.ok and not (isinstance(res.result, list) and all(
                    isinstance(x, dict) and isinstance(x.get("id"), str) and x["id"] for x in res.result)):
                _bad_shape(res, "script entries without a string id")
            self.track.record("scripts", res)
            self.listings["scripts"] = res
            if res.ok:
                for s in res.result:
                    live_scripts[s["id"]] = s
            else:
                self.unknown("CF-WORKERS-DEV-ON", _unknown_reason(res, CHECK_BY_ID["scripts"], self.cred),
                             target="all Workers in the account", endpoint=CHECK_BY_ID["scripts"].endpoint)
        names = sorted(set(scripts) | set(live_scripts))
        self._alerts(client, a)
        settings = self._scripts(client, a, names, scripts)
        self._queues(client, a)
        self._r2(client, a)
        self._containers(client, a)
        self._ai_gateway(client, a)
        self._usage(client, acct, names, settings)

    def _account_id(self, client: Client) -> str | None:
        if self.account_id_opt:
            self.info["account_id_source"] = "--account-id"
            return self.account_id_opt
        env = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
        if env:
            self.info["account_id_source"] = "CLOUDFLARE_ACCOUNT_ID"
            return env
        bad_ids = [(w, value) for w in self.project.workers for key, value, _ in w.setting_errors if key == "account_id"]
        if bad_ids:
            self.not_run("account id unknown: " + "; ".join(f"{w.label}: account_id = {shown(value)}" for w, value in bad_ids))
            return None
        cfg_ids = {w.get("account_id") for w in self.project.workers if w.get("account_id")}
        if len(cfg_ids) == 1:
            self.info["account_id_source"] = "wrangler config account_id"
            return cfg_ids.pop()
        res = client.get("/accounts")
        if res.ok and not (isinstance(res.result, list) and all(
                isinstance(x, dict) and isinstance(x.get("id"), str) and x["id"] for x in res.result)):
            _bad_shape(res, "account entries without a string id")
        self.track.record("accounts", res)
        if res.ok and isinstance(res.result, list):
            ids = [x["id"] for x in res.result]
            if len(ids) == 1:
                self.info["account_id_source"] = "the only account this token can read"
                return ids[0]
            reason = (f"this credential can read {len(ids)} accounts and the project does not name one: pass "
                      "--account-id or set CLOUDFLARE_ACCOUNT_ID")
        else:
            reason = _unknown_reason(res, CHECK_BY_ID["accounts"], self.cred)
        self.not_run("account id unknown: " + reason)
        return None

    # -- C8 alerts ---------------------------------------------------------------------
    def _alerts(self, client: Client, a: str) -> None:
        chk = CHECK_BY_ID["alert_policies"]
        pol = client.get(f"{a}/alerting/v3/policies")
        if pol.ok and not (isinstance(pol.result, list) and all(
                isinstance(p, dict) and isinstance(p.get("alert_type"), str) for p in pol.result)):
            _bad_shape(pol, "policies must be objects with a string alert_type")
        if not pol.ok:
            self.track.record("alert_policies", pol)
            self.track.record("available_alerts", None,
                              f"not attempted: alert policies read failed ({read_status(pol)})")
            self.unknown("CF-NO-BILLING-ALERT", _unknown_reason(pol, chk, self.cred), target="account",
                         endpoint=chk.endpoint, title="Not checked: billing / budget alert policies")
            self.add("CF-NO-BILLING-ALERT", "unknown", [Evidence.note(
                "Budget alerts have no verified API: confirm one exists in the dashboard (Billing > Billable Usage > "
                "Budget alerts)")], missing="budget alerts can only be confirmed in the dashboard",
                target="account", title="Confirm a budget alert in the dashboard", confidence="heuristic")
            return
        avail = client.get(f"{a}/alerting/v3/available_alerts")
        if avail.ok and not (isinstance(avail.result, dict) and all(
                isinstance(group, list) and all(isinstance(t, dict) and isinstance(t.get("type"), str)
                                               and ("display_name" not in t or isinstance(t["display_name"], str))
                                               for t in group) for group in avail.result.values())):
            _bad_shape(avail, "available_alerts groups need lists of string type/display_name entries")
        self.track.record("available_alerts", avail)
        cost_types = {"billing_usage_alert"}
        if avail.ok:
            for group in avail.result.values():
                for t in group:
                    if re.search(r"(?i)budget|billing|usage.based|spend", f"{t.get('display_name', '')} {t.get('type', '')}"):
                        cost_types.add(t["type"])
        # Only the policies this check reads are validated: an odd unrelated policy is not evidence
        # about billing alerts either way.
        candidates = [p for p in pol.result if p["alert_type"] in cost_types]
        invalid = []
        for p in candidates:
            if not _is_bool(p.get("enabled")):
                invalid.append(f"alert policy enabled is not a boolean ({shown(p.get('enabled', MISSING))})")
            if "name" in p and not isinstance(p["name"], str):
                invalid.append(f"alert policy name is not a string ({shown(p['name'])})")
        self.track.record("alert_policies", pol, shape_errors=invalid)
        if invalid:
            self.unknown("CF-NO-BILLING-ALERT", "; ".join(invalid), target="account", endpoint=chk.endpoint)
            return
        matches = [p for p in candidates if p.get("enabled") is True]
        if matches:  # an enabled cost policy is a pass on its own, whatever the list of alert types said
            self.add("CF-NO-BILLING-ALERT", "pass",
                     [Evidence.api(chk.endpoint, "alert_type", ", ".join(sorted({str(p.get('alert_type')) for p in matches}))),
                      Evidence.note(f"{len(matches)} enabled policy(ies): " + ", ".join(str(p.get("name", "?")) for p in matches[:5]))],
                     target="account", title="Billing / usage notification policy present")
        elif not avail.ok:  # no match, and the account's own list of cost alert types could not be read
            self.unknown("CF-NO-BILLING-ALERT", f"no enabled {sorted(cost_types)} among {len(pol.result)} policies, and "
                         f"the list of alert types: {_unknown_reason(avail, CHECK_BY_ID['available_alerts'], self.cred)}",
                         target="account", endpoint=CHECK_BY_ID["available_alerts"].endpoint)
        else:  # absence from this API is not absence of an alert: an unknown, never an alarm or a pass
            self.add("CF-NO-BILLING-ALERT", "unknown",
                     [Evidence.api(chk.endpoint, "alert_type", f"no enabled {sorted(cost_types)} among {len(pol.result)} policies"),
                      Evidence.note(ALERT_POLICY_UNLISTED)],
                     target="account", confidence="heuristic", missing="dashboard budget-alert state",
                     title="No cost-alert policy listed by the Notifications API")

    # -- workers.dev, drift, logging --------------------------------------------------------
    def _scripts(self, client: Client, a: str, names: list[str], scripts: dict[str, WorkerView]) -> dict[str, dict]:
        settings_by: dict[str, dict] = {}
        if not names:
            self.skipped(("settings", "subdomain"), "scripts")
        for name in names:
            view = scripts.get(name)
            st = client.get(f"{a}/workers/scripts/{name}/settings")
            target = f"{name} (live)"
            sampled = st.ok and isinstance(st.result, dict)
            sampling_errors = []
            if sampled:
                sampling_errors = self._live_sampling(name, st.result.get("observability", MISSING), target, view)
            live_bindings = []
            if st.ok and not (isinstance(st.result, dict) and isinstance(st.result.get("bindings", []), list)
                              and all(isinstance(b, dict) and isinstance(b.get("type"), str) and b["type"]
                                      and ("name" not in b and b["type"] in NON_BINDING_TYPES
                                           or isinstance(b.get("name"), str) and b["name"].strip())
                                      for b in st.result.get("bindings", []))):
                _bad_shape(st, "settings.bindings must be objects with string type/name")
            if st.ok:
                settings_by[name] = st.result
                live_bindings = st.result.get("bindings", [])
            else:
                reason = _unknown_reason(st, CHECK_BY_ID["settings"], self.cred)
                self.unknown("CF-CONFIG-DRIFT", reason, target=target, endpoint=CHECK_BY_ID["settings"].endpoint)
                if not sampled:  # a malformed bindings list does not undo a sampling block already read
                    self.unknown("CF-LOG-SAMPLING", reason, target=target, endpoint=CHECK_BY_ID["settings"].endpoint)
            paid = view.paid_binding_kinds() if view else sorted(
                {PAID_LIVE_TYPES[b.get("type")] for b in live_bindings if b.get("type") in PAID_LIVE_TYPES}
                | ({"Containers"} if any(b.get("type") == "durable_object_namespace" and "container" in str(b).lower() for b in live_bindings) else set()))
            sd = client.get(f"{a}/workers/scripts/{name}/subdomain")
            target = f"{name} (live)"
            if sd.ok and not (isinstance(sd.result, dict) and _is_bool(sd.result.get("enabled"))
                              and _is_bool(sd.result.get("previews_enabled"))):
                _bad_shape(sd, "enabled / previews_enabled are not both booleans")
            self.track.record("subdomain", sd)
            if not sd.ok:
                self.unknown("CF-WORKERS-DEV-ON", _unknown_reason(sd, CHECK_BY_ID["subdomain"], self.cred),
                             target=target, endpoint=CHECK_BY_ID["subdomain"].endpoint.replace("{script}", name))
            else:
                on = sd.result.get("enabled") is True
                prev = sd.result.get("previews_enabled") is True
                ep = CHECK_BY_ID["subdomain"].endpoint.replace("{script}", name)
                ev = [Evidence.api(ep, "enabled", sd.result.get("enabled")),
                      Evidence.api(ep, "previews_enabled", sd.result.get("previews_enabled"))]
                if (on or prev) and paid:
                    self.add("CF-WORKERS-DEV-ON", "suggestion", ev + [Evidence.note("paid bindings: " + ", ".join(paid))],
                             target=target, title=f"Live: {'workers.dev' if on else 'preview URLs'} enabled on a Worker with paid bindings")
                elif on or prev:
                    if view is None:
                        self.add("CF-WORKERS-DEV-ON", "suggestion", ev, target=target,
                                 title="Live: workers.dev / preview URLs enabled (no paid bindings seen)")
                else:
                    self.add("CF-WORKERS-DEV-ON", "pass", ev, target=target, title="Live: workers.dev and preview URLs disabled")
            if view is not None and st.ok:
                self._drift(name, view, live_bindings)
            self.track.record("settings", st, shape_errors=sampling_errors)
        return settings_by

    def _live_sampling(self, name: str, obs: Any, target: str, view: WorkerView | None) -> list[str]:
        """Validate live sampling for every Worker. A configured Worker whose live block says what its
        config already says gets no second card: the config check reports it."""
        enabled, rate, errors = sampling(obs)
        ep = CHECK_BY_ID["settings"].endpoint.replace("{script}", name)
        if errors:
            self.unknown("CF-LOG-SAMPLING", "; ".join(errors), target=target, endpoint=ep,
                         title="Not checked: live Workers Logs sampling")
            return errors
        differs = True
        if view is not None:
            cfg_enabled, cfg_rate, cfg_errors = sampling(view.get("observability", MISSING))
            differs = bool(cfg_errors) or cfg_enabled != enabled or (
                (1 if cfg_rate is MISSING else cfg_rate) != (1 if rate is MISSING else rate))
        if differs and enabled and (rate is MISSING or rate == 1):
            self.add("CF-LOG-SAMPLING", "suggestion",
                     [Evidence.api(ep, "observability.head_sampling_rate", "unset (1)" if rate is MISSING else rate)]
                     + ([Evidence.note("the deployed setting differs from the project's config")] if view is not None else []),
                     target=target)
        return []

    def _drift(self, name: str, view: WorkerView, live: list[dict]) -> None:
        binding_keys = {"kv_namespaces", "r2_buckets", "d1_databases", "services", "analytics_engine_datasets",
                        "vectorize", "hyperdrive", "workflows", "durable_objects", "send_email", "ratelimits",
                        "queues", "ai", "images", "browser", "unsafe"}
        invalid = [(k, v) for k, v, _ in view.setting_errors if k.split(".")[0].split("[")[0] in binding_keys]
        if invalid:
            self.unknown("CF-CONFIG-DRIFT", "; ".join(f"config {k} = {shown(v)} is unreadable" for k, v in invalid),
                         target=f"{name} (live)", endpoint=CHECK_BY_ID["settings"].endpoint)
            return
        live_names = {b.get("name") for b in live if b.get("type") not in NON_BINDING_TYPES and b.get("name")}
        cfg = set()
        for key in ("kv_namespaces", "r2_buckets", "d1_databases", "services", "analytics_engine_datasets",
                    "vectorize", "hyperdrive", "workflows"):
            cfg |= set(view.names(key, "binding"))  # Wrangler names these rows by `binding`; a row without one is an error
        cfg |= set(view.do_bindings()) | set(view.email_bindings()) | set(view.ratelimit_bindings())
        cfg |= set(view.names("queues.producers", "binding"))
        for single in (view.ai_binding(), view.images_binding(), view.browser_binding()):
            if single:
                cfg.add(single)
        cfg.discard(None)
        if not live_names or not cfg:
            return
        only_cfg, only_live = sorted(cfg - live_names), sorted(live_names - cfg)
        ep = CHECK_BY_ID["settings"].endpoint.replace("{script}", name)
        if only_cfg or only_live:
            self.add("CF-CONFIG-DRIFT", "suggestion",
                     [Evidence.api(ep, "bindings[].name", f"{len(live_names)} live bindings"),
                      Evidence.note(f"in config only: {', '.join(only_cfg) or '-'}; deployed only: {', '.join(only_live) or '-'}")],
                     target=f"{name} (live)")
        else:
            self.add("CF-CONFIG-DRIFT", "pass", [Evidence.api(ep, "bindings[].name", f"{len(live_names)} bindings match")],
                     target=f"{name} (live)", title="Deployed bindings match the config")

    # -- queues ------------------------------------------------------------------------
    def _queues(self, client: Client, a: str) -> None:
        cfg_queues = {n for w in self.project.workers for n in w.names("queues.consumers", "queue")}
        if not cfg_queues and not self.account_wide:
            self.track.record("queues", None, NOT_SELECTED)
            return
        res = client.get_all(f"{a}/queues")
        chk = CHECK_BY_ID["queues"]
        if res.ok and not isinstance(res.result, list):
            _bad_shape(res, "queues is not a list")
        if not res.ok:
            self.track.record("queues", res)
            self.unknown("CF-QUEUE-CONSUMER-BOUNDS", _unknown_reason(res, chk, self.cred), target="live queues",
                         endpoint=chk.endpoint)
            return

        def consumers(q: Any) -> list | None:
            """The consumer objects of a queue entry, or None when the entry is malformed."""
            if not isinstance(q, dict):
                return None
            cs = q.get("consumers", [])
            return cs if isinstance(cs, list) and all(isinstance(c, dict) for c in cs) else None

        dlqs = {c["dead_letter_queue"] for q in res.result for c in (consumers(q) or [])
                if isinstance(c.get("dead_letter_queue"), str) and c["dead_letter_queue"]}
        errors = []
        for q in res.result:
            qn = q.get("queue_name") if isinstance(q, dict) else None
            if not isinstance(qn, str):
                reason = f"unexpected response shape: a queue entry has no string queue_name ({shown(q)})"
                errors.append(reason)
                self.unknown("CF-QUEUE-CONSUMER-BOUNDS", reason, target="live queues", endpoint=chk.endpoint)
                continue
            if not self.account_wide and qn not in cfg_queues:
                continue
            cs = consumers(q)
            if cs is None:
                reason = f"consumers is not a list of objects ({shown(q.get('consumers'))})"
                errors.append(reason)
                self.unknown("CF-QUEUE-CONSUMER-BOUNDS", reason,
                             target=f"queue {qn} (live)", endpoint=chk.endpoint)
                continue
            for c in cs:
                s = c.get("settings", {})
                dlq = c.get("dead_letter_queue", "")
                retries = s.get("max_retries", MISSING) if isinstance(s, dict) else MISSING
                if (not isinstance(s, dict) or not (retries is MISSING or _is_int(retries) and retries >= 0)
                        or not isinstance(dlq, str)):
                    reason = (f"consumer settings ({shown(s)}), max_retries ({shown(retries)}) "
                              f"or dead_letter_queue ({shown(dlq)}) is malformed")
                    errors.append(reason)
                    self.unknown("CF-QUEUE-CONSUMER-BOUNDS", reason,
                                 target=f"queue {qn} (live)", endpoint=chk.endpoint)
                    continue
                ev = [Evidence.api(chk.endpoint, f"{qn}.consumers[].settings.max_retries",
                                   retries if retries is not MISSING else "(unset: default 3)"),
                      Evidence.api(chk.endpoint, f"{qn}.consumers[].dead_letter_queue", dlq or "(none)")]
                if not dlq and qn in dlqs:
                    sev = "pass" if retries is not MISSING else "suggestion"
                    self.add("CF-QUEUE-CONSUMER-BOUNDS", sev, ev, target=f"queue {qn} (live)",
                             title=f"Live dead-letter queue {qn}: consumer max_retries {retries if retries is not MISSING else 'unset'}")
                elif not dlq:
                    self.add("CF-QUEUE-CONSUMER-BOUNDS", "suggestion", ev, target=f"queue {qn} (live)",
                             title=f"Live queue {qn}: consumer has no dead-letter queue")
                else:
                    self.add("CF-QUEUE-CONSUMER-BOUNDS", "pass", ev, target=f"queue {qn} (live)",
                             title=f"Live queue {qn}: max_retries {retries if retries is not MISSING else 'default 3'}, DLQ {dlq}")
        self.track.record("queues", res, shape_errors=errors)

    # -- R2 ----------------------------------------------------------------------------
    def _r2(self, client: Client, a: str) -> None:
        buckets = {n for w in self.project.workers for n in w.r2_bindings().values() if n}
        if self.account_wide:
            res = client.get_all(f"{a}/r2/buckets", key="buckets")
            listed = res.result.get("buckets") if res.ok and isinstance(res.result, dict) else res.result
            if res.ok and not (isinstance(listed, list) and all(
                    isinstance(b, dict) and isinstance(b.get("name"), str) and b["name"] for b in listed)):
                _bad_shape(res, "bucket entries without a string name")
            self.track.record("r2_buckets", res)
            self.listings["r2_buckets"] = res
            if res.ok:
                buckets |= {b["name"] for b in listed}
            else:
                self.unknown("CF-R2-DEV-PUBLIC", _unknown_reason(res, CHECK_BY_ID["r2_buckets"], self.cred),
                             target="all R2 buckets", endpoint=CHECK_BY_ID["r2_buckets"].endpoint)
        for bucket in sorted(buckets):
            chk = CHECK_BY_ID["r2_managed"]
            ep = chk.endpoint.replace("{bucket}", bucket)
            res = client.get(f"{a}/r2/buckets/{bucket}/domains/managed")
            if res.ok and not (isinstance(res.result, dict) and _is_bool(res.result.get("enabled"))):
                _bad_shape(res, "enabled is not a boolean")
            self.track.record("r2_managed", res)
            if not res.ok:
                self.unknown("CF-R2-DEV-PUBLIC", _unknown_reason(res, chk, self.cred), target=f"bucket {bucket}", endpoint=ep)
                continue
            if res.result.get("enabled") is True:
                ev = [Evidence.api(ep, "enabled", True)]
                if isinstance(res.result.get("domain"), str) and res.result["domain"]:
                    ev.append(Evidence.api(ep, "domain", res.result["domain"]))
                # The custom-domain list only adds context to an already established public bucket.
                cust = client.get(f"{a}/r2/buckets/{bucket}/domains/custom")
                if cust.ok and not (isinstance(cust.result, dict) and isinstance(cust.result.get("domains"), list)
                                    and all(isinstance(d, dict) and isinstance(d.get("domain"), str)
                                            and ("enabled" not in d or _is_bool(d["enabled"]))
                                            for d in cust.result["domains"])):
                    _bad_shape(cust, "custom domains must be a list of domain objects")
                self.track.record("r2_custom", cust)
                if not cust.ok:
                    ev.append(Evidence.note("custom domains could not be listed ("
                                            f"{_unknown_reason(cust, CHECK_BY_ID['r2_custom'], self.cred)}); whether one "
                                            "is attached beside r2.dev is not known"))
                elif cust.result["domains"]:
                    ev.append(Evidence.note("a custom domain is also attached: r2.dev bypasses its WAF, cache and Access"))
                self.add("CF-R2-DEV-PUBLIC", "suggestion", ev, target=f"bucket {bucket}")
            else:  # enabled is False
                self.add("CF-R2-DEV-PUBLIC", "pass", [Evidence.api(ep, "enabled", False)],
                         target=f"bucket {bucket}", title="r2.dev public access disabled")
        if not buckets:
            self.skipped(("r2_managed", "r2_custom"), "r2_buckets")
        elif "r2_custom" not in self.track.statuses:
            self.track.record("r2_custom", None, "not attempted: read only for a bucket with r2.dev access enabled")

    # -- containers ----------------------------------------------------------------------
    def _containers(self, client: Client, a: str) -> None:
        cfg = [(w, c) for w in self.project.workers for c in w.containers()]
        if not cfg and not self.account_wide:
            self.track.record("containers", None, NOT_SELECTED)
            return
        chk = CHECK_BY_ID["containers"]
        res = client.get(f"{a}/containers/applications")
        if res.ok and not isinstance(res.result, list):
            _bad_shape(res, "container applications is not a list")
        if not res.ok:
            self.track.record("containers", res)
            self.unknown("CF-CONTAINER-MAX-INSTANCES", _unknown_reason(res, chk, self.cred),
                         target="deployed containers", endpoint=chk.endpoint)
            return
        names = {w.name for w, _ in cfg} | {n for w, _ in cfg for n in w.names("containers", "name")}
        matched = 0
        if not all(isinstance(app, dict) and isinstance(app.get("name"), str) for app in res.result):
            reason = f"unexpected response shape: application entries without a string name ({shown(res.result)})"
            self.track.record("containers", res, shape_errors=[reason])
            self.unknown("CF-CONTAINER-MAX-INSTANCES", reason, target="deployed containers", endpoint=chk.endpoint)
            return
        errors = []
        for app in res.result:
            nm = app["name"]
            if not self.account_wide and not any(nm == n or nm.startswith(n + "-") for n in names):
                continue
            matched += 1
            mx = app.get("max_instances", MISSING)
            ev = [Evidence.api(chk.endpoint, f"{nm}.max_instances", mx if mx is not MISSING else "(unset)")]
            if not (mx is MISSING or _is_int(mx) and mx > 0):
                reason = f"max_instances is not a positive integer ({shown(mx)})"
                errors.append(reason)
                self.unknown("CF-CONTAINER-MAX-INSTANCES", reason,
                             target=f"container {nm} (live)", endpoint=chk.endpoint)
            elif mx is MISSING or mx >= 20:
                self.add("CF-CONTAINER-MAX-INSTANCES", "suggestion", ev, target=f"container {nm} (live)",
                         title=f"Live container {nm}: max_instances {mx if mx is not MISSING else 'unset'}")
            else:
                self.add("CF-CONTAINER-MAX-INSTANCES", "pass", ev, target=f"container {nm} (live)",
                         title=f"Live container {nm}: max_instances {mx}")
        if cfg and not matched:
            self.unknown("CF-CONTAINER-MAX-INSTANCES", "no deployed container application matched the project's "
                         "Worker names (not deployed yet, or a different name)", target="deployed containers",
                         endpoint=chk.endpoint)
        self.track.record("containers", res, shape_errors=errors)

    # -- AI Gateway ---------------------------------------------------------------------
    def _ai_gateway(self, client: Client, a: str) -> None:
        """Account context, collected irrespective of declared AI bindings. It says which gateways have
        spend limits; it does not show that the application's AI calls go through any of them."""
        chk = CHECK_BY_ID["ai_gateways"]
        res = client.get_all(f"{a}/ai-gateway/gateways")
        if res.ok and not isinstance(res.result, list):
            _bad_shape(res, "gateways is not a list")
        if not res.ok:
            self.track.record("ai_gateways", res)
            self.unknown("CF-AI-GATEWAY-SPEND", _unknown_reason(res, chk, self.cred), target="AI Gateway",
                         endpoint=chk.endpoint)
            return
        limited, unlimited = [], []
        for g in res.result:
            errors = []
            if not isinstance(g, dict) or not isinstance(g.get("id"), str) or not g["id"].strip():
                errors.append(f"gateway needs a string id ({shown(g)})")
            sl = g.get("spend_limits", {}) if isinstance(g, dict) else {}
            if not isinstance(sl, dict):
                errors.append(f"spend_limits is not a table ({shown(sl)})")
                sl = {}
            enabled, rules = sl.get("enabled", False), sl.get("rules", [])
            if not _is_bool(enabled):
                errors.append(f"spend_limits.enabled is not a boolean ({shown(enabled)})")
            if enabled is not True:  # a disabled limit caps nothing: its rules are not consumed
                rules = []
            if not isinstance(rules, list):
                errors.append(f"spend_limits.rules is not a list ({shown(rules)})")
                rules = []
            for i, r in enumerate(rules):
                if not isinstance(r, dict):
                    errors.append(f"rules[{i}] is not a table ({shown(r)})")
                    continue
                for key in ("limit", "window"):
                    v = r.get(key, MISSING)
                    if not _is_num(v) or v <= 0:
                        errors.append(f"rules[{i}].{key} is not a finite positive number ({shown(v)})")
                for key in ("limitType", "limit_type"):
                    if key in r and r[key] != "cost":
                        errors.append(f"rules[{i}].{key} is not cost ({shown(r[key])})")
                if "limitType" not in r and "limit_type" not in r:
                    errors.append(f"rules[{i}].limitType is absent")
                if not _is_bool(r.get("enabled", True)):
                    errors.append(f"rules[{i}].enabled is not a boolean ({shown(r['enabled'])})")
            if errors:
                self.track.record("ai_gateways", res, shape_errors=errors)
                self.unknown("CF-AI-GATEWAY-SPEND", "; ".join(errors), target="AI Gateway", endpoint=chk.endpoint)
                return
            if enabled and any(r.get("enabled", True) is True for r in rules):
                limited.append(g["id"])
            else:
                unlimited.append(g["id"])
        self.track.record("ai_gateways", res)
        routing = Evidence.note("this lists account gateway settings only: whether the application's AI calls "
                                "(Workers AI binding, SDK or HTTP, including fallbacks) go through these gateways "
                                "is for the reviewer to establish")
        if limited:
            ev = [Evidence.api(chk.endpoint, "spend_limits.enabled", "true for " + ", ".join(limited))]
            if unlimited:
                ev.append(Evidence.api(chk.endpoint, "spend_limits", "no enabled rule on " + ", ".join(unlimited)))
            self.add("CF-AI-GATEWAY-SPEND", "pass", ev + [routing], target="AI Gateway",
                     title=f"AI Gateway spend limits enabled on {len(limited)} of {len(res.result)} gateway(s)")
            return
        what = (f"no enabled spend-limit rules on {len(res.result)} gateway(s)" if res.result
                else "no AI Gateway in this account")
        declared = self.account_wide or any(w.ai_binding() for w in self.project.workers)
        ev = [Evidence.api(chk.endpoint, "spend_limits", what), routing]
        if not declared:
            ev.append(Evidence.note("no AI binding is declared in the project's config; review whether the "
                                    "application makes paid AI calls before acting on this"))
        self.add("CF-AI-GATEWAY-SPEND", "suggestion", ev, target="AI Gateway",
                 confidence="certain" if declared else "heuristic",
                 title=("No AI Gateway spend limits observed" if res.result else "No AI Gateway in this account"))

    # -- GraphQL usage ----------------------------------------------------------------------
    USAGE_QUERY = (
        "query Usage($accountTag: string!, $since: Time!, $until: Time!, $scripts: [string!]) {\n"
        "  viewer { accounts(filter: { accountTag: $accountTag }) {\n"
        "    workersInvocationsAdaptive(limit: 100, filter: { datetime_geq: $since, datetime_leq: $until, scriptName_in: $scripts }) {\n"
        "      sum { requests errors subrequests }\n"
        "      quantiles { cpuTimeP50 cpuTimeP99 }\n"
        "      dimensions { scriptName }\n"
        "    } } } }"
    )

    def _usage(self, client: Client, acct: str, names: list[str], settings: dict[str, dict]) -> None:
        if not names:
            self.skipped(("graphql",), "scripts")
            return
        until = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
        since = until - _dt.timedelta(hours=24)
        res = client.graphql(self.USAGE_QUERY, {"accountTag": acct, "since": since.isoformat().replace("+00:00", "Z"),
                                                "until": until.isoformat().replace("+00:00", "Z"), "scripts": names[:50]})
        chk = CHECK_BY_ID["graphql"]
        rows = None
        if res.ok and isinstance(res.result, dict):
            try:
                rows = res.result["viewer"]["accounts"][0]["workersInvocationsAdaptive"]
            except (KeyError, IndexError, TypeError):
                rows = None
        if res.ok and not isinstance(rows, list):
            _bad_shape(res, "GraphQL data does not contain usage rows")
        if not isinstance(rows, list):
            self.track.record("graphql", res)
            if res.status == 200 and res.errors:
                reason = f"GraphQL error: {res.error_text()} (needs '{chk.permission}')"
            else:
                reason = _unknown_reason(res, chk, self.cred)
            self.unknown("CF-USAGE-SNAPSHOT", reason, target="Worker analytics", endpoint=chk.endpoint)
            return
        errors = []
        for i, r in enumerate(rows):
            if not (isinstance(r, dict) and isinstance(r.get("dimensions"), dict)
                    and isinstance(r["dimensions"].get("scriptName"), str) and r["dimensions"]["scriptName"]
                    and isinstance(r.get("sum"), dict) and isinstance(r.get("quantiles", {}), dict)):
                errors.append(f"usage row {i} has malformed dimensions/sum/quantiles ({shown(r)})")
                continue
            for key in ("requests", "errors", "subrequests"):
                v = r["sum"].get(key, MISSING)
                if not _is_count(v):
                    errors.append(f"{r['dimensions']['scriptName']}.sum.{key} is not finite and non-negative ({shown(v)})")
            for key, v in r.get("quantiles", {}).items():
                if key in ("cpuTimeP50", "cpuTimeP99") and not _is_count(v):
                    errors.append(f"{r['dimensions']['scriptName']}.quantiles.{key} is not finite and non-negative ({shown(v)})")
        if errors:
            self.track.record("graphql", res, shape_errors=errors)
            self.unknown("CF-USAGE-SNAPSHOT", "; ".join(errors), target="Worker analytics", endpoint=chk.endpoint)
            return
        agg: dict[str, dict[str, float]] = {}
        for r in rows:
            nm = r["dimensions"]["scriptName"]
            s = r["sum"]
            q = r.get("quantiles") or {}
            a = agg.setdefault(nm, {"requests": 0, "errors": 0, "subrequests": 0, "cpuTimeP50": 0, "cpuTimeP99": 0})
            for k in ("requests", "errors", "subrequests"):
                a[k] += s[k]
                if not _is_count(a[k]):
                    reason = f"{nm}.sum.{k} aggregate is oversized ({shown(a[k])}); last input {shown(s[k])}"
                    self.track.record("graphql", res, shape_errors=[reason])
                    self.unknown("CF-USAGE-SNAPSHOT", reason, target="Worker analytics", endpoint=chk.endpoint)
                    return
            for k in ("cpuTimeP50", "cpuTimeP99"):
                a[k] = max(a[k], q.get(k) or 0)
        self.track.record("graphql", res)
        table = [{"script": n, "requests_24h": int(v["requests"]), "errors_24h": int(v["errors"]),
                  "subrequests_24h": int(v["subrequests"]), "cpu_p50_us": v["cpuTimeP50"], "cpu_p99_us": v["cpuTimeP99"]}
                 for n, v in sorted(agg.items())]
        fanout = [t for t in table if t["requests_24h"] and t["subrequests_24h"] / t["requests_24h"] >= 20]
        details = {"columns": ["script", "requests_24h", "errors_24h", "subrequests_24h", "cpu_p50_us", "cpu_p99_us"],
                   "rows": table, "note": f"{since.isoformat()} to {until.isoformat()}; scripts with no rows had no requests."}
        ev = [Evidence.api(chk.endpoint, "workersInvocationsAdaptive", f"{len(table)} script(s) with traffic")]
        if fanout:
            self.add("CF-USAGE-SNAPSHOT", "suggestion",
                     ev + [Evidence.note("subrequests >= 20x requests (possible fan-out or loop): " + ", ".join(t["script"] for t in fanout))],
                     target="Worker analytics", details=details,
                     title="High subrequest fan-out in the last 24h")
        else:
            self.add("CF-USAGE-SNAPSHOT", "pass", ev, target="Worker analytics", details=details,
                     title="Last-24h Worker usage (no fan-out outlier)")
