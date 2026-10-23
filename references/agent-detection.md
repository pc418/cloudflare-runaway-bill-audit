# Investigate the mechanism, not the spelling

Use this guide with [SKILL.md](../SKILL.md). Consider every family, then follow the ones that
apply to the project. These are questions for source investigation, not rules for a scanner,
an exhaustive list of APIs, or findings to emit automatically. A countercase below rebuts a
particular mechanism; it is never a blanket safety certificate for that route or product.

Start with an actual unit of work: an admitted request, queue message, alarm, client action
or active resource. Follow what it causes, including later attempts and stored artifacts.
For a suspected risk ask: **what makes the bill grow, what can repeat it, and what evidence
would show that growth is contained?** Read that evidence before rating the risk.

Incident IDs below exist in the report's `incidents` map. Their stories motivate questions;
their amounts, platform behavior and prices do not transfer to this project. `moltbot` is
an unverified user-supplied summary, not a fetched original. Logging has no incident in this
catalogue. A new mechanism can be reported without inventing an incident citation.

## 1. Work creates more work — C1

**Incident lesson:** DO alarms rearmed into costly storage loops (`cloudflare-108k`,
`cloudflare-88k`); a consumer re-enqueued its own work (`cloudflare-36k`); self-HTTP calls and
module initialization restarted execution (`firebase-cloudrun-72k`, `vercel-3k`).

Follow alarm creation and rearming, producers reached by consumers, scheduled jobs, Workflow
steps/retries, service calls, self-URLs, background tasks and rescheduling helpers. Follow
success **and** failure paths. Can A cause B which causes A again, without a new external
admission? Does a state write itself trigger the next job? Does retry rearm with fresh counters?

Establish the repeated paid operations and the state transition that eventually stops them.
An attempt count must survive the relevant retry/restart boundary. Queue retry/DLQ settings
bound retries of a message, not new messages the application sends. A concurrency limit can
slow a feedback loop without terminating it. Overlapping timers and batches can multiply work.

**Countercase:** a one-shot task, a bounded retry with durable completion/deduplication, or an
intended cheap session heartbeat does not demonstrate runaway repetition. Still inspect work
per attempt and whether new requests can restart it. Platform CPU/duration limits are not
cross-request spending budgets; HTTP/DO/queue/workflow lifetimes differ. See the dated runtime
notes before treating disconnect or `waitUntil` as a termination guarantee.

**Decisive evidence:** the line that produces the next trigger, conditions reaching it, work
per iteration and the effective stopping state. Prefer breaking accidental feedback or reusing
completed work over disabling intended recovery.

## 2. One admission expands into many units — C2

**Incident lesson:** unbatched storage writes and list operations multiplied costs
(`cloudflare-36k`); unexpected retained data and query volume grew bills (`firebase-70k`,
`bigquery-22k`).

Trace user-controlled batch sizes, pagination, uploads, archive expansion, query results,
parallel calls, output sizes and persisted artifacts. Locate the validated bound at admission
and compare it with what the helper actually processes. Follow each retry layer: client, job,
SDK, provider fallback. A bounded retry at each layer can still multiply total attempts.

Separate the units billed: operations, rows scanned, bytes stored, generation units and compute.
Returned row count is not evidence of query work; inspect query predicates/indexes and provider
semantics without executing the production query. A `LIMIT` is not proof of cheap scanning.
For accumulation, ask how many new objects/versions/rows each request creates, whether keys are
reused, how retention is enforced and how this grows across requests/users—not just within a batch.

**Countercase:** a small fixed aggregation or suitably bounded/batched work may be ordinary cost,
not a finding. Legitimate retained content still consumes capacity; don't claim retention bounds
admission rate or that batching removes all billing. Escalate actual amplification, not the
existence of a loop or storage operation.

**Decisive evidence:** input origin and enforcement, fan-out and retry sites, paid unit, and
retention/reuse path. Distinguish a per-attempt improvement from a cumulative bound.

## 3. Useful output is cheaper to request than to provide — C3/C6

**Incident lesson:** cheap signup requests triggered paid downstream work (`mailgun-11k`,
`vercel-23k`), and an apparent limiter did not limit (`cloudflare-36k`).

Read paid generation, email/SMS, uploads, browser/container jobs, vector/media APIs and external
SDKs from their callers, including client-to-provider calls and exposed/bundled credentials
that bypass server admission. Include ordinary signed-in users, easy new accounts, webhook retries,
RPC callers, preview/alternate hostnames, batch variants and auth exemptions. Trace the actual
rejection before the sink; a control that logs, throws into a catch-and-continue path, or runs
after paid work does not establish admission. UI limits do not restrict direct clients.
For free/discounted paths, trace who can create or reset the qualifying state: an owned row,
entitlement or cache marker may be client-created, not evidence of prior paid/server work.
Cheap eligibility broadens spending access; it is not an authorization defect unless the product
requires server-issued eligibility. Preserve legitimate imported/client-created content in remedies.

Use SKILL's four control labels. For quotas, trace **check -> atomic reservation -> paid work ->
settlement/refund** in the actual order. Can concurrent requests each see the same remaining
credit? Can output be delivered or provider work accepted before settlement? What happens if the
client leaves, persistence fails, the provider times out after accepting work, or a fallback
uses another paid account? Can retries get a new idempotency key or refunded budget for a billable
attempt? Which failure, disconnect or refund branches can callers deliberately trigger after
paid work? Separate customer-success credits from the owner's provider-attempt budget.

A costly route with authentication and burst admission can remain sustainably repeatable.
Conversely, a real shared work budget can contain public/free use without requiring a paywall.
Verify the budget's key, period, atomicity, failure behavior, bypass branches and resource scope;
its name is not proof. Released reservations can admit new attempts: a bound on outstanding
holds is not a cumulative bound on failed or abandoned work. A provider hard limit helps only
for the billed accounts/models it covers.

**Countercase:** one bounded cheap write or owner email can merit a suggestion rather than an
alarm; operator-only invocation changes who can repeat work but does not excuse an autonomous
bug. Neither “paid API” nor “no daily quota” alone decides priority. State the actual mechanism.

**Decisive evidence:** entry/audience, paid attempt, admission and settlement sites, with distinct
branches retained. Recommend attempt containment without silently charging users for failures
or removing owner-intended free features.

## 4. Delivery bypasses the assumed protection — C4

**Incident lesson:** an object could be requested around its intended cache/origin path
(`firebase-100k`); a small public asset accumulated huge traffic (`netlify-104k`); requests could
be billed under another storage provider's access rules (`aws-13k`).

Trace browser/API URL -> host/router -> cache -> Worker/origin/bucket. Check direct bucket URLs,
custom domains, preview hosts, signed links, public access and transformation parameters. Which
paths bypass the WAF, authorization, rate control or cache? Separate reads, writes, transforms,
network transfer and stored bytes; use the actual provider's model, not another incident's tariff.

For caching, establish **which cache**, what it keys on, whether the lookup precedes the work,
how misses populate it, and how invalidation/revocation works. Inspect personal/tenant/host
variation and authorization order. Headers, a cache helper name and in-memory reuse do not
establish shared edge protection. Also consider cache-busting input and cold/concurrent misses.
For multi-stage work, follow cache options to each costly downstream call: a compose cache
is not a render cache, and a render cache does not eliminate earlier classification or later
storage writes. Credit only the stages actually covered, conditional on the relevant deployment.
See [runtime evidence](runtime-evidence.md) for Cache API versus pre-execution Workers Cache.

**Countercase:** public delivery may be intended and economical; a long-lived signed link is not
itself a bill exploit. No shared caching of private responses merely to eliminate reads. Do not
transfer S3 unauthorized-request or another provider's egress charges to Cloudflare R2.

**Decisive evidence:** alternate delivery path, actual billed unit, applicable cache/control
configuration and code. Preserve public access while containing meaningful avoidable work.

## 5. Ordinary traffic repeatedly launches expensive compute — C5/C10

**Incident lesson:** a catch-all started a Sandbox for favicon/static traffic (qualified
`moltbot`); a sitemap used per-request compute (`vercel-620`); traffic growth exposed recurring
compute costs (`vercel-96k`, `vercel-46k`).

Trace static, missing-path, favicon/probe and public GET/SSR requests through middleware into
acquisition or generation. Does expensive work occur before routing or early return? Does the
same reusable result get rebuilt on every request? Compare actual collection bounds and work,
not merely the size of a loop in isolation. Include uncached error paths and cache population.

Check `run_worker_first`, assets/Pages routing and deployed caching, but don't infer execution
from a binding or routing option alone. Determine which work a hit avoids: provider call,
query, Worker body, or only client transfer. A header added after generation is not evidence
that generation was skipped. A cache helps repeated keys, not arbitrary fresh inputs.

**Countercase:** small fixed aggregation, modest indexed reads and freshness-required responses
are not substantial generation simply because they run on GET. Appropriate static delivery or
caching must preserve authorization, personalization and freshness. Do not equate less compute
with zero request charges; distinguish cache mechanisms and verify billing if needed.

**Decisive evidence:** request path, acquisition/generation, early-return/cache order and
material work per request. Avoid a second finding for CPU work already explained by the same
paid-call fan-out unless the remedy differs.

## 6. Resources stay active, or ceilings cover the wrong work — C6

**Incident lesson:** instances/processes accumulated (qualified `moltbot`), and a high scale-out
ceiling magnified a self-calling service (`firebase-cloudrun-72k`).

Trace resource acquisition through success, exception, timeout and cancellation: containers,
Sandbox/browser sessions, WebSockets and DO activity. Does cleanup refer to the acquired
resource and actually run on each relevant exit? What prevents idle sleep—polling, health checks,
connections or crons? What bounds simultaneous resources, lifetime and repeated starts?

For Durable Objects, duration is billed while the object is active or cannot hibernate, separately
from its request count. Look for ordinary WebSocket `accept()` versus the Hibernation API and whether
handlers actually finish; `setTimeout`/`setInterval` timers, pending RPC/fetch/`waitUntil` work and
the compatibility date or flags that keep the object in memory (per-operation keep-alive up to 15
minutes from compatibility date 2026-10-01); alarms that re-arm themselves, since each invocation is
a billed request and its handler runs as billed duration; and how many objects a client can create.
Dated semantics: `runtime-evidence.md`.

For AI, inspect each material call family and its effective options/model/provider, including
SDK defaults, retries and fallback clients. A cap on one call or text modality does not cover
other calls or image/audio units. Gateway routing is separate from a configured enforced spend
limit; inspect both scope and bypass. An account Gateway listing cannot prove source routing.

**Countercase:** resource reuse can be deliberate; starting/closing per request may cost more
than controlled reuse. Missing Gateway alone is not an alarm. Image/audio work needs appropriate
unit bounds, not a text-token requirement. Instance, CPU, output and concurrency ceilings each
bound something different; no one is automatically a total spend cap.

**Decisive evidence:** acquisition/release or sleep path, applicable environment settings,
actual call options and live/dated account evidence. For disconnect behavior distinguish local
invocation termination from a remote provider's already accepted work; see runtime evidence.

## 7. A lifecycle event silently repeats billed work — C7

**Incident lesson:** an event on each banner mount generated millions of analytics events
(`posthog-devin-1273`).

Follow browser render/mount/effect, focus, reconnect, service-worker and module-startup paths;
native tasks, activation, observation, background schedulers and extensions. Read custom hooks
and helpers. Does a state change retrigger its own work? Does remount/restart reset dedupe or
attempt state? Can overlapping retries reissue work after the server/provider already succeeded?
External analytics or crash-reporting SDKs can bill without hitting a project endpoint.

Establish the actual sink, production trigger frequency, overlap, dedupe scope, backoff and
cancellation. Check server work on recovery, especially success followed by failed persistence
or delivery. Client dedupe is useful behavior, not a server-side control against direct callers.

**Countercase:** development-only duplicate effects, ordinary user actions, slow heartbeats and
intended recovery do not by themselves demonstrate material billed repetition. Do not break
recovery merely to create a finite lifetime counter. Prefer reuse/idempotency/attempt admission
where retry can repeat costly completed work.

**Decisive evidence:** lifecycle trigger -> actual sink -> repeat/recovery state and controls.
Separate a demonstrated billing multiplier from an unrelated UI/backpressure correctness issue.

## 8. Spend is visible only after the fact — C8

**Incident lesson:** the Cloudflare alarm/queue cases were discovered from invoices
(`cloudflare-108k`, `cloudflare-88k`, `cloudflare-36k`).

Relate billing/usage notifications and enforced controls to the paths above. What stops work,
what only alerts, who receives it, and which account/resource/model does it cover? Check
fail-open behavior and alternate accounts/providers. A recent usage snapshot describes recent
usage, not a bound on future demand. A limit on one project/account is not a limit on all sinks.

**Countercase / evidence limit:** a denied read is not “no alert configured”; a dated project
record is not a current verified setting. Keep an evidenced code exposure even when deployment
or account controls are unknown, with that scope clearly stated. Do not assert a timeless
platform-wide spend-cap policy or alert delay without dated authoritative evidence.

**Decisive evidence:** exact account/config fact and timestamp/source, control scope and uncovered
work. Ask for the specific permission or record needed. The scan's `--account` layer does not
read zone WAF rules, all secret deployment state or external-provider spend settings.

## 9. The billed unit or plan differs from the assumed one — C9

**Incident lesson:** prepaid upgrades stacked charges (`cloudflare-images-400`), a paid SKU was
mistaken for free tier (`aws-103`), and traffic triggered an automatic add-on (`webflow-1k`).

Compare configured/deployed products and external paid services with the project's cost model.
Check per-attempt versus successful-result billing, tokens/images/minutes/rows/bytes, retained
versions, included allocations, retry charges, automatic upgrades and fallback accounts. Which
budgets are shared? Which prices/limits are actually verified for this account and date?

**Countercase:** missing exact tariff information need not prevent finding a clear costly loop
or failed admission. It does prevent a fabricated dollar estimate. Historic incident amounts,
a provider name, a “free” comment or a customer-facing price are not current billing evidence.

**Decisive evidence:** actual service/plan/unit and dated source; separate established work units
from unknown economics. Do not require a full pricing spreadsheet before reporting a mechanism.

## 10. Observability multiplies the workload — LOG

**Incident lesson:** no logging incident is catalogued; `cloudflare-36k` is only an operation-
amplification analogy. Use applicable provider evidence for log/event pricing.

Trace logging helpers on success and failure, per-item batch/query paths, tail consumers and
analytics/export sinks. One request can produce many events or large payloads, and a tail sink
can add paid operations for each producer event. Determine volume per request/message and the
effective sampling/filtering/retention scope. Look for telemetry feedback, not only console calls.

**Countercase:** finite batches still produce per-item logs, but that fact alone is not a defect.
Sampling is not an absolute byte bound; conversely, absent a meaningful avoidable multiplier,
a console statement or 100% sampling is not automatically a serious billing exposure.

**Decisive evidence:** event-producing path, amount, billed destination and applicable controls.
Prefer dropping redundant/sensitive payloads, sampling or aggregation without losing necessary
operational visibility. Reuse a finding if the same feedback mechanism is already explained.
