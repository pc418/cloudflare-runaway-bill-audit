"""Unit prices per binding type (Workers Paid, checked against developers.cloudflare.com on 2026-10-13).

Only figures confirmed in the evidence record are stated. Products whose price
was not captured point to their pricing page instead of a number.
"""

from __future__ import annotations

from .wrangler import WorkerView
from .values import MISSING, sampling

D = "https://developers.cloudflare.com"
AS_OF = "2026-10-13"

PRICES: dict[str, tuple[str, str]] = {
    "worker": ("Requests: 10M/month included, then $0.30/M. CPU: 30M CPU-ms included, then $0.02/M CPU-ms. "
               "Static asset requests are free unless the Worker runs first.", D + "/workers/platform/pricing/"),
    "kv": ("Reads 10M incl. then $0.50/M; writes, deletes and lists 1M incl. each then $5.00/M; "
           "storage 1 GB incl. then $0.50/GB-month.", D + "/workers/platform/pricing/"),
    "durable_objects": ("Requests (incl. alarm invocations) 1M incl. then $0.15/M; duration 400,000 GB-s incl. then "
                        "$12.50/M GB-s (billed at 128 MB while active or unable to hibernate). SQLite storage: rows read "
                        "25B incl. then $0.001/M; rows written 50M incl. then $1.00/M (each setAlarm() = 1 row "
                        "written); stored data 5 GB-month then $0.20/GB-month.", D + "/durable-objects/platform/pricing/"),
    "r2": ("Storage $0.015/GB-month (10 GB-month free); Class A (writes/lists) $4.50/M (1M free); Class B (reads) "
           "$0.36/M (10M free); egress free; 401s not billed.", D + "/r2/pricing/"),
    "queues": ("$0.40/M operations beyond 1M/month; ~3 operations per message (write, read, delete per 64 KB); "
               "each retry adds a read.", D + "/workers/platform/pricing/"),
    "ai": ("$0.011 per 1,000 Neurons; 10,000 Neurons/day free.", D + "/workers-ai/platform/pricing/"),
    "browser": ("10 browser-hours/month incl. then $0.09/h; concurrency beyond 10 browsers (monthly average) "
                "$2.00 each.", D + "/changelog/post/2025-07-28-br-pricing/"),
    "containers": ("Billed per 10 ms while running. Memory 25 GiB-h incl. then $0.0000025/GiB-s; CPU 375 vCPU-min "
                   "incl. then $0.000020/vCPU-s (active use); disk 200 GB-h incl. then $0.00000007/GB-s. Memory and "
                   "disk are billed on provisioned size; egress is billed separately.",
                   D + "/containers/platform/pricing/"),
    "images": ("Transformations: 5,000 unique/month incl. then $0.50 per 1,000 unique (binding included since "
               "2026-07-01); storage $5 per 100k images/month; delivery $1 per 100k.", D + "/images/pricing/"),
    "observability": ("Until 2026-11-30: 20M log events/month incl. then $0.60/M. From 2026-12-01: 50 GB ingestion "
                      "incl. then $0.25/GB; storage 10 GB-month then $0.10/GB-month; paid usage continues "
                      "automatically.", D + "/observability/pricing/"),
    "d1": ("Rows read 25B/month incl. then $0.001/M; rows written 50M/month incl. then $1.00/M (an index adds a "
           "written row per indexed write); storage 5 GB incl. then $0.75/GB-month.", D + "/d1/platform/pricing/"),
    "stream": ("Minutes stored: prepaid, $5/month per 1,000 minutes (a direct creator upload reserves its "
               "maxDurationSeconds until it completes or expires); minutes delivered $1 per 1,000.",
               D + "/stream/pricing/"),
    "vectorize": ("Price not captured in this tool's evidence base.", D + "/vectorize/platform/pricing/"),
    "workflows": ("Steps and storage billed since 2026-08-10; price not captured in this tool's evidence base.",
                  D + "/workflows/reference/pricing/"),
    "analytics_engine": ("Price not captured in this tool's evidence base.",
                         D + "/analytics/analytics-engine/pricing/"),
    "send_email": ("Price not captured in this tool's evidence base.", D + "/email-service/api/send-emails/workers-api/"),
    "hyperdrive": ("Price not captured in this tool's evidence base.", D + "/hyperdrive/platform/pricing/"),
}


def inventory(w: WorkerView) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []

    def add(kind: str, names: list[str], key: str) -> None:
        if names:
            text, url = PRICES[key]
            rows.append({"binding": kind, "names": ", ".join(sorted(set(n for n in names if n))), "bills_by": text, "url": url})

    if w.has_entry():
        add("Worker", [w.name], "worker")
    add("KV", w.kv_bindings(), "kv")
    add("Durable Objects", list(w.do_bindings()), "durable_objects")
    add("R2", [f"{b} -> {n}" if n else b for b, n in w.r2_bindings().items()], "r2")
    add("Queues", w.names("queues.producers", "binding") + w.names("queues.consumers", "queue"), "queues")
    add("Workers AI", [w.ai_binding()] if w.ai_binding() else [], "ai")
    add("Browser Run", [w.browser_binding()] if w.browser_binding() else [], "browser")
    add("Containers", [w.row_label("containers", i) for i, _ in w.rows("containers")], "containers")
    add("Images", [w.images_binding()] if w.images_binding() else [], "images")
    add("D1", w.d1_bindings(), "d1")
    add("Vectorize", w.vectorize_bindings(), "vectorize")
    add("Stream", [w.stream_binding()] if w.stream_binding() else [], "stream")
    add("Workflows", w.names("workflows", "binding", "name"), "workflows")
    add("Analytics Engine", w.names("analytics_engine_datasets", "binding"), "analytics_engine")
    add("send_email", w.email_bindings(), "send_email")
    add("Hyperdrive", w.names("hyperdrive", "binding"), "hyperdrive")
    enabled, _, errors = sampling(w.get("observability", MISSING))
    if enabled and not errors:
        add("Observability (logs)", ["enabled"], "observability")
    return rows
