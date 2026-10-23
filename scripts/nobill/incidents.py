"""Incident catalogue shared by every provider.

Each rule cites one or more of these ids. Amounts and mechanisms are as the
original sources state them (serverlesshorrors.com summaries were checked
against the linked originals; where they disagree the original wins).
Credit: https://serverlesshorrors.com/ collects these stories.
"""

from __future__ import annotations

SH = "https://serverlesshorrors.com/all/"

INCIDENTS: dict[str, dict[str, str]] = {
    "cloudflare-108k": {
        "title": "Durable Object alarm looped forever: ~6 trillion reads/writes, US$10,811 invoice, not refunded",
        "provider": "Cloudflare",
        "url": SH + "cloudflare-108k",
    },
    "cloudflare-88k": {
        "title": "Two Durable Objects infinite-looped: $8,846 (DO storage rows read $8,710), found from the bill",
        "provider": "Cloudflare",
        "url": SH + "cloudflare-88k",
    },
    "cloudflare-36k": {
        "title": "Queue consumer re-enqueued its own writes, unbatched DO puts, kv.list() on auth, empty rate limiter: ~$35k",
        "provider": "Cloudflare",
        "url": SH + "cloudflare-36k",
    },
    "moltbot": {
        "title": "Catch-all app.all('*') started a Sandbox container per favicon/static request: 499 processes, OOM",
        "provider": "Cloudflare Sandbox (user-supplied summary of a Chinese post; original not fetched)",
        "url": "",
    },
    "firebase-cloudrun-72k": {
        "title": "Service POSTed URLs back to itself (exponential recursion), default max-instances 1000: ~$72,000",
        "provider": "Google Cloud",
        "url": SH + "firebase-cloudrun-72k",
    },
    "vercel-3k": {
        "title": "Module-scope await fetch() to its own API ran on every invocation: $3,000 in 6 hours",
        "provider": "Vercel",
        "url": SH + "vercel-3k",
    },
    "vercel-620": {
        "title": "sitemap.txt served by a function instead of as a static file: $620 of function GB-hours",
        "provider": "Vercel",
        "url": SH + "vercel-620",
    },
    "vercel-96k": {
        "title": "Viral growth on per-invocation compute: 56M function invocations/day, $96,280",
        "provider": "Vercel",
        "url": SH + "vercel-96k",
    },
    "vercel-46k": {
        "title": "450M pageviews after a document release: $46,485 on-demand charges",
        "provider": "Vercel",
        "url": SH + "vercel-46k",
    },
    "vercel-23k": {
        "title": "Signup spam created accounts and trials that triggered paid functions: $23k",
        "provider": "Vercel",
        "url": SH + "vercel-23k",
    },
    "mailgun-11k": {
        "title": "Bot registered 11M users through an unprotected signup form, each sending a paid email",
        "provider": "Mailgun",
        "url": SH + "mailgun-11k",
    },
    "firebase-100k": {
        "title": "Uncached object hammered at ~35 GB/s, then the bucket URL hit directly around the CDN: ~$98k",
        "provider": "Google Cloud",
        "url": SH + "firebase-100k",
    },
    "firebase-70k": {
        "title": "A bug stored 1 PB in a day: ~$70,000 bill",
        "provider": "Google Cloud",
        "url": SH + "firebase-70k",
    },
    "netlify-104k": {
        "title": "DDoS on one 3.44 MB file: 190 TB in 4 days, $104,500",
        "provider": "Netlify",
        "url": SH + "netlify-104k",
    },
    "aws-13k": {
        "title": "Requests billed to a bucket by name (unauthorized PUTs are billed on S3): $1,300",
        "provider": "AWS",
        "url": SH + "aws-13k",
    },
    "bigquery-22k": {
        "title": "No per-query or per-day quota: ~15 minutes of queries scanned 3,000 TB, ~$22k",
        "provider": "Google BigQuery",
        "url": SH + "bigquery-22k",
    },
    "cloudflare-images-400": {
        "title": "Images prepaid storage upgrades stacked charges within a cycle: >$400/month vs $110 expected",
        "provider": "Cloudflare",
        "url": SH + "cloudflare-images-400",
    },
    "aws-103": {
        "title": "A paid SKU believed to be free tier (Aurora PostgreSQL): $103",
        "provider": "AWS",
        "url": SH + "aws-103",
    },
    "webflow-1k": {
        "title": "Image bandwidth triggered an automatic bandwidth add-on upgrade: $2,280 over two months",
        "provider": "Webflow",
        "url": SH + "webflow-1k",
    },
    "posthog-devin-1273": {
        "title": "An analytics event fired on every banner mount: 6.6M events in a week, $1,273",
        "provider": "PostHog",
        "url": SH + "posthog-devin-1273",
    },
}


def subset(ids: set[str]) -> dict[str, dict[str, str]]:
    return {i: INCIDENTS[i] for i in sorted(ids) if i in INCIDENTS}
