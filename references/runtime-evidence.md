# Runtime evidence for billing investigations

Checked **2026-10-21** against the official Cloudflare pages linked below. These are dated
provider statements, not measurements of the audited project's deployment. Read the relevant
section when caching or cancellation affects a conclusion; recheck current docs when permitted.
An offline audit may cite this record as dated evidence. Record an unknown if deployment or
provider semantics still prevent the conclusion.

## Caching: identify where the cache sits

There are distinct mechanisms; neither a custom domain nor a response header alone establishes
which one the project uses:

- **Workers Cache:** the [overview](https://developers.cloudflare.com/workers/cache/) and
  [configuration](https://developers.cloudflare.com/workers/cache/configuration/) describe an
  opt-in cache **before** Worker execution. `cache.enabled` enables it, with per-entrypoint
  overrides. On a hit, Cloudflare can return the response without running that entrypoint.
  Headerless responses can be cached: the documented default for a cacheable 200 with neither
  `Cache-Control` nor `Expires` is two hours; `private`/`no-store` explicitly opts out. The key
  omits the hostname, and a request cookie does not by itself isolate users or bypass caching.
  Inspect the actual key/access design and documented bypass conditions; do not borrow the
  `Authorization`/response `Set-Cookie` behavior for cookie-only authentication. Zone Cache Rules
  are not its configuration surface. Inspect deployed configuration and entrypoints, not just
  an old note about custom domains or the absence of `caches.default`.
- **Cache API (`caches.default`):** a programmatic lookup/store **inside** the Worker. See
  [Cache API](https://developers.cloudflare.com/workers/runtime-apis/cache/) and
  [Workers Cache limitations](https://developers.cloudflare.com/workers/cache/limitations/).
  The Worker must look up the key, return the hit before costly work, and populate misses.
  Its cache is local to the data center; a stored response is not automatically a global hit.
  A lookup/store cache alone does not establish single-flight admission: check whether concurrent
  misses can each start the costly work before the result is stored. A hit can avoid later
  work without avoiding the Worker invocation that did the lookup.
- **Zone/subrequest and browser caches:** `fetch()` can interact with the upstream hostname's
  Cloudflare cache; response headers also influence downstream browser caches. These are not
  proof that the Worker's own generation was skipped. See
  [Workers and the zone cache](https://developers.cloudflare.com/cache/interaction-cloudflare-products/workers/).

For the audit: name the cache, its effective configuration, lookup/key/population and the work
it avoids. Check cold/concurrent misses, unique-input cache busting, authorization, tenant/user
variation, expiry and revocation. Pre-execution caching can bypass in-code authorization on a
hit: do not recommend it for private responses without a sound separation/key/access design.
The [Workers Cache pricing section](https://developers.cloudflare.com/workers/cache/#pricing)
states that with caching enabled requests are billed at the standard Workers request rate,
including hits and normally free static-asset/service-binding requests; CPU is billed when the
Worker runs. Enabling this cache can **increase** some request charges while reducing compute.
Compare the actual workload and current pricing before recommending it as a cost saving.

Reject both blanket claims: “Worker responses on custom domains are never edge-cached” and
“Cache-Control makes all Worker-generated responses edge-cached.” A feature's existence does
not establish that the audited project enabled it. The scan does not decide this question.

## Disconnect: distinguish local execution from remote paid work

The [Workers limits page](https://developers.cloudflare.com/workers/platform/limits/#duration)
states that while an HTTP client remains connected the Worker can continue processing/streaming;
when the client disconnects or the response completes, associated tasks **may be canceled**.
It does not promise that all unfinished work completes or that all spending instantly stops.

The [context API](https://developers.cloudflare.com/workers/runtime-apis/context/#waituntil)
states that HTTP `ctx.waitUntil()` can extend execution for **up to 30 seconds** after the
response or disconnect. That allowance is shared across the request's `waitUntil` calls;
unsettled promises are canceled afterward. It is not a total HTTP-request duration, a fresh
allowance per call, or a guarantee of durable completion. Queued work is a separate invocation;
DO/alarm/workflow lifetimes must be checked under their own documented semantics.

The [2025-05-22 Request.signal announcement](https://developers.cloudflare.com/changelog/post/2025-05-22-handle-request-cancellation/)
and [compatibility reference](https://developers.cloudflare.com/workers/configuration/compatibility-flags/#enable-requestsignal-for-incoming-requests)
describe incoming-request cancellation signals with `enable_request_signal`. As checked on
2026-10-21, that flag's entry lists no automatic “Default as of” date; a recent compatibility
date alone does not establish that it is enabled. This differs from a response stream's own
cancel callback, which must be traced separately. Inspect the project's compatibility
configuration and its actual signal/cancellation propagation before
crediting abort handling. The existence of `AbortController` or a listener is not proof that
all downstream work observes it.

For the audit, trace three boundaries separately:

1. Did admission/reservation occur before the provider accepted work?
2. What can continue or be canceled locally (awaited work, stream, `waitUntil`, queue), and
   where do persistence, delivery and debit/refund happen relative to it?
3. What does the remote provider guarantee about accepted work, cancellation and billing?
   Local abort is not evidence of remote cancellation, non-billing or a refund.

A missed settlement after delivered output, or an attempt refunded after provider acceptance,
can be a source-proven budget exposure even if later execution is uncertain. State exactly
which branch/order is proven and which runtime/provider fact remains unknown. Do not assert
“work always continues unless the abort signal is checked,” or “disconnect prevents any charge.”

## Billing alerts

Checked **2026-10-22**. [Changelog 2026-07-20, "Budget alerts now on by default for Pay-as-you-go
accounts"](https://developers.cloudflare.com/changelog/post/2026-06-15-budget-alerts-default-on/):
eligible pay-as-you-go accounts without a budget alert get one at a $10 account-level threshold from
their next billing cycle, rolled out in cohorts. The alert is informational only and does not cap
usage. Usage is processed once per day, so budget alerts fire the day after the threshold is reached.
Recurring subscription fees are excluded; enterprise contract accounts are out of scope. A default
alert can be edited or removed, so eligibility does not establish that the audited account has one.
The Notifications API may not list budget alerts created under Billing (unverified); confirm in
Billing > Billable Usage > Budget alerts.

## AI Gateway spend limits

Checked **2026-10-22**. [Spend limits](https://developers.cloudflare.com/ai-gateway/features/spend-limits/)
set a dollar budget per rolling or fixed window, scoped by model, provider or custom metadata;
over-budget requests get a 429 (or a Dynamic Route fallback model). They apply to Unified Billing
and BYOK requests for models with known pricing. They are eventually consistent: a request's cost is
recorded after completion, so a burst of concurrent requests can briefly exceed the limit. Cost
tracking is a best-effort estimate; at most 20 rules per gateway.

## Durable Objects duration

Checked **2026-10-22**. [Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/):
duration is billed in wall-clock time, for 128 MB regardless of use, while the object is actively
running or idle in memory but unable to hibernate; an idle object eligible for hibernation is not
billed. Calling `accept()` on a WebSocket incurs duration for the whole connection; the WebSocket
Hibernation API avoids that once handlers finish. Each RPC method call on a stub is one billed
request (calls on a returned `RpcTarget` stub share the session); incoming WebSocket messages are
billed at a 20:1 ratio. [Lifecycle](https://developers.cloudflare.com/durable-objects/concepts/durable-object-lifecycle/)
and the [2026-10-01 changelog](https://developers.cloudflare.com/changelog/post/2026-10-01-pending-io-keep-alive/):
for compatibility date 2026-10-01 or later (or the `durable_object_io_tasks_prevent_eviction` flag),
each pending service-binding request, DO RPC or `fetch()`, outbound `fetch()`, `container.monitor()`,
`waitUntil` promise, `setTimeout`/`setInterval` timer, TCP socket or outbound WebSocket prevents
eviction until it completes or for up to 15 minutes from its start, per operation; duration charges
continue meanwhile, and a later operation extends time in memory. A request or alarm handler that
is still running, and any pending `setTimeout`/`setInterval` callback, prevent hibernation; a
scheduled alarm wakes a hibernated or inactive object at its time and does not by itself keep the
object in memory. Each alarm invocation is a billed request.
