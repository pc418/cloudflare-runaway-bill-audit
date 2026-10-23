"""Cloudflare rule catalogue: the deterministic checks the scan still runs.

Only rules emitted from wrangler configuration, the read-only account API or a
collector read/parse failure live here. The source-semantics rules were retired
with the analyzer (owner 2026-10-20, docs/261020-refactor-AGENT_LED_BILLING_AUDIT.md);
older findings.json files that cite them still render from their own serialized
prose, and the agent may cite any incident in nobill.incidents.

Every rule names its mistake class (C1..C10, LOG), the incidents it maps to and a
concrete fix with Cloudflare doc links. Prices and limits quoted here were checked
against developers.cloudflare.com on 2026-10-13; nothing listed as unverified in
the evidence record is asserted.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...findings import Evidence, Finding

PROVIDER = "cloudflare"
D = "https://developers.cloudflare.com"


def doc(title: str, path: str) -> dict[str, str]:
    return {"title": title, "url": D + path}


DOCS = {
    "wrangler": doc("Wrangler configuration", "/workers/wrangler/configuration/"),
    "queues_retries": doc("Queues batching and retries", "/queues/configuration/batching-retries/"),
    "queues_concurrency": doc("Queues consumer concurrency", "/queues/configuration/consumer-concurrency/"),
    "loop_limit": doc("Workers loop limit (error 1019)", "/workers/observability/errors/#loop-limit"),
    "ratelimit": doc("Rate Limiting binding", "/workers/runtime-apis/bindings/rate-limit/"),
    "aig_spend": doc("AI Gateway spend limits (changelog 2026-06-05)", "/changelog/post/2026-06-05-spend-limits/"),
    "r2_public": doc("R2 public buckets", "/r2/buckets/public-buckets/"),
    "r2_pricing": doc("R2 pricing", "/r2/pricing/"),
    "assets_routing": doc("Static assets: worker-script routing", "/workers/static-assets/routing/worker-script/"),
    "assets_billing": doc("Static assets billing", "/workers/static-assets/billing-and-limitations/"),
    "containers_pricing": doc("Containers pricing", "/containers/platform/pricing/"),
    "containers_config": doc("Wrangler containers configuration", "/workers/wrangler/configuration/#containers"),
    "limits_config": doc("Wrangler limits (cpu_ms, subrequests)", "/workers/wrangler/configuration/#limits"),
    "workers_pricing": doc("Workers pricing", "/workers/platform/pricing/"),
    "budget_alerts": doc("Budget alerts", "/billing/manage/budget-alerts/"),
    "usage_alerts": doc("Usage-based billing notifications", "/billing/understand/usage-based-billing/"),
    "default_alerts": doc("Default budget alerts (changelog 2026-06-15)", "/changelog/post/2026-06-15-budget-alerts-default-on/"),
    "workers_logs": doc("Workers Logs", "/workers/observability/logs/workers-logs/"),
    "obs_pricing": doc("Observability pricing", "/observability/pricing/"),
    "workers_dev": doc("workers.dev routing", "/workers/configuration/routing/workers-dev/"),
    "preview_urls": doc("Preview URL defaults (changelog 2025-10-23)", "/changelog/post/2025-10-23-preview-url-default-behavior/"),
}


@dataclass(frozen=True)
class Rule:
    id: str
    cls: str
    title: str
    why: str
    incidents: tuple[str, ...]
    fix: str
    docs: tuple[str, ...]
    pass_scope: str = ""

    def finding(self, severity: str, *, confidence: str, source: str, evidence: list[Evidence],
                title: str | None = None, target: str | None = None, why_extra: str = "",
                missing: str | None = None, details: dict | None = None,
                fix_extra: str = "") -> Finding:
        checked_title = title or self.title
        # A successful observation must not inherit the rule's failure explanation/remedy.
        why = f"{checked_title}. {self.pass_scope}" if severity == "pass" else self.why
        fix = "No configuration change is indicated by this result alone." if severity == "pass" else self.fix
        return Finding(
            rule=self.id, provider=PROVIDER, cls=self.cls, severity=severity,
            title=checked_title, confidence=confidence, source=source,
            why=(why + (" " + why_extra if why_extra else "")).strip(),
            incidents=list(self.incidents),
            fix=(fix + (" " + fix_extra if fix_extra else "")).strip(),
            docs=[DOCS[d] for d in self.docs], evidence=evidence, missing=missing,
            target=target, details=details,
        )


_R = [
    # ---------------------------------------------------------------- C1 loops
    Rule("CF-QUEUE-CONSUMER-BOUNDS", "C1", "Queue consumer without explicit max_retries / dead_letter_queue",
         "Platform retries are bounded (max_retries defaults to 3) and each retry is a billed read; without a "
         "dead_letter_queue, messages that keep failing are discarded. Setting both deliberately keeps retry cost "
         "and data loss visible.",
         ("cloudflare-36k",),
         "Set max_retries and dead_letter_queue on every consumer (and a retry_delay), and alert from the DLQ "
         "consumer.",
         ("wrangler", "queues_retries"),
         pass_scope="These settings bound redelivery of a failing message, not new messages sent or re-enqueued "
                    "by the application. A dead-letter consumer does not require another dead-letter queue."),
    Rule("CF-QUEUE-CONCURRENCY", "C6", "Queue consumer without max_concurrency in a Worker with paid bindings",
         "The consumer has no explicit max_concurrency and its Worker declares paid bindings. This configuration "
         "does not establish which bindings or paid APIs the consumer reaches. Inspect its work per message and "
         "retry paths before judging the cost of concurrent batches.",
         ("firebase-cloudrun-72k",),
         "Trace the consumer's actual work; if concurrent batches create material load or spending, set "
         "max_concurrency to a value that supports the intended throughput.",
         ("queues_concurrency", "wrangler")),
    Rule("CF-SELF-SERVICE-BINDING", "C1", "Service binding points at the Worker itself",
         "A service binding to the same Worker lets code call itself; in a loop or fan-out this multiplies requests "
         "up to the 16-hop loop limit.",
         ("firebase-cloudrun-72k",),
         "Call internal code directly; if self-RPC is intended (a named entrypoint), make sure no path can recurse.",
         ("loop_limit",)),
    # ---------------------------------------------------------------- C3 open paid work
    Rule("CF-NO-RATELIMIT-BINDING", "C3", "Paid bindings without any Rate Limiting binding",
         "The Worker binds metered products but declares no ratelimits binding. Rate limits may still exist as zone "
         "WAF rules (not visible in config) or in code.",
         ("cloudflare-36k", "mailgun-11k"),
         "Add a ratelimits binding and call .limit({ key }) before metered work, or confirm a WAF rate-limiting rule "
         "covers every route that triggers paid work (workers.dev routes bypass zone WAF rules).",
         ("ratelimit",),
         pass_scope="A binding declaration does not establish which paths enforce it before paid work. "
                    "A per-key burst limit is not a cumulative work budget."),
    # ---------------------------------------------------------------- C4 public objects
    Rule("CF-R2-DEV-PUBLIC", "C4", "R2 bucket has public r2.dev access enabled",
         "r2.dev is meant for non-production traffic: WAF, caching and Bot Management are not available on it, and "
         "enabling a custom domain does not disable it. Every uncached public GET is a Class B operation "
         "($0.36/M); egress is free and 401s are not billed, so this is linear cost, not a multiplier.",
         ("firebase-100k", "aws-13k"),
         "Serve public objects through a custom domain with cache rules and disable r2.dev "
         "(wrangler r2 bucket dev-url disable <BUCKET>).",
         ("r2_public", "r2_pricing"),
         pass_scope="This covers the managed r2.dev entry only; other domains and Worker delivery paths "
                    "require separate review."),
    # ---------------------------------------------------------------- C5 catch-all compute
    Rule("CF-RUN-WORKER-FIRST", "C5", "assets.run_worker_first = true sends every asset request through the Worker",
         "Static asset requests are free and unlimited, but with run_worker_first = true every request, assets "
         "included, invokes the Worker and is billed. Whether those invocations also start Containers, Durable "
         "Objects or other paid work depends on the Worker's code path, which this configuration check does not "
         "establish.",
         ("moltbot", "vercel-620"),
         "Use run_worker_first with explicit route patterns, or negative patterns (\"!/assets/*\"), instead of true.",
         ("assets_billing", "assets_routing")),
    # ---------------------------------------------------------------- C6 ceilings
    Rule("CF-CONTAINER-MAX-INSTANCES", "C6", "Container without an explicit max_instances",
         "max_instances defaults to 20 and is the ceiling between a bug and a multiplied bill (incident "
         "firebase-cloudrun-72k: \"Had we chosen max-instances to be '2'... [the] bill would've been: $144\").",
         ("firebase-cloudrun-72k", "moltbot"),
         "Set max_instances to the smallest workable number for each container (it is only enforced in production).",
         ("containers_config", "containers_pricing"),
         pass_scope="The instance ceiling does not bound active lifetime, repeated starts or total spend."),
    Rule("CF-CONTAINER-SIZE", "C6", "Large container instance type",
         "Memory and disk are billed on the provisioned size for every 10 ms the container runs.",
         (),
         "Use the smallest instance_type that works (default \"lite\": 1/16 vCPU, 256 MiB).",
         ("containers_pricing", "containers_config")),
    Rule("CF-CPU-LIMIT", "C6", "No limits.cpu_ms on a Worker",
         "Cloudflare's own pricing page: \"To prevent accidental runaway bills or denial-of-wallet attacks, configure "
         "the maximum amount of CPU time that can be used per invocation.\" The default cap is 30 s, the maximum "
         "300,000 ms. CPU limits do not bound request count, charges for downstream paid work reached through "
         "subrequests, including external-provider calls, or total spend.",
         (),
         "Set [limits] cpu_ms to a few times your p99 CPU time (Standard usage model only; enforced when deployed).",
         ("limits_config", "workers_pricing"),
         pass_scope="This is a per-invocation CPU ceiling, not a limit on invocation count, "
                    "charges for downstream paid work reached through subrequests, including external-provider "
                    "calls, or total spend."),
    Rule("CF-SUBREQUESTS-RAISED", "C6", "limits.subrequests raised above the default",
         "The default is 10,000 subrequests per invocation on paid plans; raising it widens what a loop or fan-out "
         "bug can do in one invocation.",
         (),
         "Keep the default unless a measured workload needs more.",
         ("limits_config",)),
    # ---------------------------------------------------------------- exposure
    Rule("CF-WORKERS-DEV-ON", "C3", "workers.dev / preview URL left on for a Worker with paid bindings",
         "A workers.dev URL is a second public entry point that zone-level WAF and rate-limiting rules do not cover. "
         "workers_dev defaults to true; when preview_urls is not set, new preview URLs follow workers_dev.",
         ("cloudflare-36k", "firebase-100k"),
         "Set workers_dev = false and preview_urls = false for production Workers that serve a custom domain or "
         "route (or protect them with Cloudflare Access).",
         ("workers_dev", "preview_urls"),
         pass_scope="This covers only the named URL settings, not other hosts or route controls. A local "
                    "declaration does not verify live deployment; omitted preview settings may preserve live state."),
    # ---------------------------------------------------------------- C8 alerts
    Rule("CF-NO-BILLING-ALERT", "C8", "No billing / usage notification policy found",
         "The cited incidents illustrate late discovery of unexpected usage. Notifications provide visibility, "
         "not enforcement; their availability and delivery timing depend on the current product and policy. "
         "This check does not establish a hard spending ceiling.",
         ("cloudflare-108k", "cloudflare-88k", "cloudflare-36k"),
         "Create a budget alert at ~1.5-2x normal monthly spend plus a low early-warning one (Billing > Billable "
         "Usage > Budget alerts, or Notifications > Add > Budget Alert), and per-product Usage Based Billing "
         "notifications where your plan offers them (Pro or higher). Alerts only notify. Enforce bounds before paid "
         "work and verify each one's scope: request or attempt budgets, concurrency limits and lifetime limits "
         "bound different dimensions, and none alone is an account-wide spending ceiling.",
         ("budget_alerts", "usage_alerts", "default_alerts"),
         pass_scope="The observed policy provides notification; it does not stop paid work or prove "
                    "delivery to a monitored recipient."),
    Rule("CF-AI-GATEWAY-SPEND", "C3", "No AI Gateway with spend limits enabled",
         "AI Gateway spend limits apply to matching traffic through that gateway. A gateway listing does not "
         "establish application routing, cover direct/fallback calls or prove an account-wide spending ceiling.",
         ("cloudflare-36k",),
         "Enable spend_limits on the gateway your AI calls use (up to 20 rules; scope by model, provider or "
         "metadata such as user id).",
         ("aig_spend",),
         pass_scope="The observed limits cover only applicable traffic routed through those gateways. "
                    "This listing does not establish application routing or cover direct/fallback calls."),
    # ---------------------------------------------------------------- C9 / logging
    Rule("CF-COST-INVENTORY", "C9", "What each binding of this Worker bills by",
         "Most surprise bills in the evidence set came from a metered product or billing model the owner did not "
         "know about. This lists every metered binding with its unit price and included amount (Workers Paid, as of "
         "2026-10-13). External SDK/HTTP spend is not inventoried here; a declared binding does not prove "
         "that any particular request uses it.",
         ("cloudflare-images-400", "aws-103", "webflow-1k"),
         "Check each line against expected traffic; set a budget alert sized to the expected peak.",
         ("workers_pricing",)),
    Rule("CF-LOG-SAMPLING", "LOG", "Workers Logs at 100% sampling",
         "No incident in the evidence set was driven by logs, but log volume is billed: until 2026-11-30 Workers "
         "Logs include 20M events/month then $0.60/M; from 2026-12-01 Observability bills ingestion by volume "
         "(50 GB included, then $0.25/GB; storage 10 GB-month, then $0.10/GB-month) and \"paid usage continues "
         "automatically after an allowance is exhausted\". head_sampling_rate defaults to 1 (100%).",
         (),
         "Set observability head_sampling_rate below 1 for high-traffic Workers (keep 1 for low traffic), avoid "
         "logging request/response bodies, and re-check volume before the 2026-12-01 pricing change.",
         ("workers_logs", "obs_pricing"),
         pass_scope="Sampling selects invocations, not an absolute bound on events or bytes; inspect "
                    "the volume each sampled invocation produces."),
    Rule("CF-USAGE-SNAPSHOT", "C8", "Last-24h request volume (GraphQL Analytics)",
         "A live usage snapshot is the earliest place a runaway loop shows up; the incidents ran for weeks before the "
         "invoice.",
         ("cloudflare-88k", "cloudflare-36k"),
         "Compare with your expected daily volume; a flat, round-the-clock rate on a Worker with little user traffic "
         "suggests a loop.",
         ("workers_pricing",),
         pass_scope="This is a historical usage observation, not a limit on future requests or spend."),
    Rule("CF-CONFIG-DRIFT", "C9", "Deployed bindings differ from the wrangler config",
         "The live script's bindings do not match the config in the project, so checks of that config may not describe "
         "what is actually running.",
         (),
         "Redeploy from the config, or update the config to match what is deployed, then re-run the audit.",
         ("wrangler",),
         pass_scope="This compares binding names only, not binding values, application code or every "
                    "deployment setting."),
    # ---------------------------------------------------------------- meta
    Rule("CF-CONFIG-UNREADABLE", "META", "Wrangler config could not be parsed",
         "A config the scanner cannot read is not evidence of safety; every config-based check for it is unknown.",
         (),
         "Fix the syntax error (wrangler would also reject it) and re-run.",
         ("wrangler",)),
    Rule("CF-NO-CONFIG", "META", "No wrangler config found",
         "Without a wrangler.toml / wrangler.json / wrangler.jsonc the Cloudflare config checks cannot run.",
         (),
         "Run the scanner on the directory that contains the Worker's wrangler config.",
         ("wrangler",)),
]

RULES: dict[str, Rule] = {r.id: r for r in _R}
