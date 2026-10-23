# findings.json schema (`cloudflare-no-bill-explode/findings@1`)

`scripts/audit.py scan` writes it, the auditing agent edits it, `scripts/audit.py render`
validates and renders it. `scripts/audit.py validate <file>` runs only the validation.
The validator is `scripts/nobill/findings.py:validate_document`; this page describes the
same rules.

## Top level

| Key | Type | Meaning |
|---|---|---|
| `schema` | string | Always `cloudflare-no-bill-explode/findings@1`. |
| `tool` | object | `{name, version}` of the tool that wrote the scan. |
| `generated_at` | string | ISO-8601 UTC time of the scan. |
| `project` | string | Absolute path of the scanned directory. |
| `providers` | string[] | Providers that ran (e.g. `["cloudflare"]`). |
| `options` | object | `{account, account_wide}` flags of the run. |
| `audit_status` | string, optional | `"unreviewed"` or `"reviewed"`. `scan` writes `"unreviewed"`. The agent sets `"reviewed"` after the audit procedure; it records that the investigation happened, not that the project is safe, the review exhaustive or the document certified. `render` never changes it. A document without the key (older scans) is shown as "audit status not recorded". |
| `review_summary` | string, optional | `scan` writes `""`. Required and non-empty when `audit_status` is `"reviewed"`: the deployment and client scope inspected, how each mechanism family was disposed of, and the scope left unresolved or unexamined. |
| `findings` | Finding[] | Everything the scan and the agent concluded. Ordered alarm, suggestion, unknown, pass, not-applicable. |
| `scope_requirements` | ScopeRow[] | One row per live check: what it needs and whether it was granted. |
| `provider_info` | object | Per provider: configs found, Workers, credential source (never the value), token instructions, limits, and `source_context` (below). |
| `paid_work_inventory` | InventoryRow[] | The work paths the agent traced, with their controls. `scan` leaves it empty; the agent fills it. A missing row means not inventoried, not free or safe. |
| `incidents` | object | Incident id -> `{title, provider, url}`. `why.incidents` may cite any id in this map, or an https URL. |

## Finding

| Key | Type | Required | Meaning |
|---|---|---|---|
| `id` | string | yes | Unique in the file. Scan ids are `f001...`; use `a001...` for agent findings. Keep ids stable within a reviewed document; a new scan may number differently. |
| `rule` | string | yes | Rule id, e.g. `CF-CPU-LIMIT`. Agent findings use `AGENT-<NAME>`. |
| `provider` | string | yes | e.g. `cloudflare`. |
| `class` | string | yes | Mistake class: `C1` loop, `C2` amplification, `C3` open paid work, `C4` public objects, `C5` catch-all compute, `C6` ceilings, `C7` client lifecycle events, `C8` alerts, `C9` billing model, `C10` repeated compute under traffic, `LOG` logging, `META` collection gaps (older documents: scanner coverage). |
| `severity` | enum | yes | `alarm` (must fix), `suggestion` (better fix), `unknown` (could not check), `pass`, `not-applicable` (the check's subject is positively absent, e.g. an assets-only Worker has no code). |
| `title` | string | yes | One line. |
| `target` | string or null | no | Worker / bucket / queue / account the finding is about. |
| `evidence` | Evidence[] | yes | At least one item for alarms and suggestions. |
| `confidence` | enum | yes | `certain` means a directly established, explicitly scoped source/config/API fact; `heuristic` means an inference requiring review. Either may be corrected by the agent. A configuration fact does not establish what the code does on any path. |
| `source` | enum | yes | `config`, `api` or `agent`. `code` appears only in older documents written by the retired source analyzer; they still load and render. |
| `why` | object | yes | `{text, incidents: [incident id or https URL]}`. |
| `fix` | object | yes | `{text, docs: [{title, url}]}`; every `url` is http(s). |
| `review` | object | yes | `{status, reason, original_severity?}` (below). |
| `missing` | string | for `unknown` | The permission to grant or the reason the check could not run. |
| `details` | object | no | A table: `{columns: [..], rows: [{..}], note?}` (cost inventory, usage snapshot). |
| `coverage_ref` | string | no | Older documents only: id of the `CF-SOURCE-COVERAGE` finding that explained why a source check was `unknown`. Must name a finding in the file. Reports list such checks under that card. New scans do not write it. |

### Evidence

| `kind` | Fields |
|---|---|
| `file` | `file` (path relative to the project), `line` (integer, 1-based), `snippet` (relevant source with credential values/signed tokens replaced by `[REDACTED]`; never rely on renderer redaction of known local Cloudflare credentials to cover third-party secrets) |
| `api` | `endpoint` (e.g. `GET /accounts/{account_id}/r2/buckets/x/domains/managed`), `field`, `value` |
| `note` | `text` |

### Review

| `status` | Set by | Meaning |
|---|---|---|
| `not-required` | scan | Certain finding (config/API fact). |
| `needs-review` | scan | Heuristic finding; the agent must decide it. |
| `confirmed` | agent | The agent reviewed the evidence and supports the finding's current scoped disposition. For `unknown`, this confirms the stated remaining gap, not the presence of a risk or a control. For `pass` or `not-applicable`, the reason identifies the source/configuration scope establishing that result. |
| `false-positive` | agent | Dismissed. `reason` is required. Rendered under "Dismissed by review", not counted. |

If the agent changes `severity`, it records the old value in `review.original_severity`.

### Illustrative agent finding

This is a format example, not evidence about a real project. Replace its paths, observations
and remedy with the audited code's actual facts. The sink and admission ordering both matter;
a route citation alone would not establish the conclusion. No incident citation is required
when none explains the mechanism.

```json
{
  "id": "a001", "rule": "AGENT-POST-WORK-ADMISSION",
  "provider": "cloudflare", "class": "C3", "severity": "alarm",
  "title": "Concurrent generation requests can spend before the work budget is debited",
  "target": "example-api", "confidence": "certain", "source": "agent",
  "evidence": [
    {"kind": "file", "file": "src/generate.ts", "line": 18,
     "snippet": "if (await remaining(user.id) < 1) return exhausted();"},
    {"kind": "file", "file": "src/generate.ts", "line": 32,
     "snippet": "const result = await generateImage(input);"},
    {"kind": "file", "file": "src/generate.ts", "line": 48,
     "snippet": "await debit(user.id, 1);"}
  ],
  "why": {"text": "The ordinary-user path in the inspected source permits concurrent requests to pass a non-reserving balance read before one paid image attempt each; debit follows completion. The burst limiter bounds arrivals, not a shared pre-work reservation. Scope: this route and its inspected helpers; deployment and external WAF controls were not verified.", "incidents": []},
  "fix": {"text": "Reserve an attempt atomically before generation; define retry and refund behavior for provider-accepted work separately from customer success credits. Preserve the free feature.", "docs": []},
  "review": {"status": "confirmed", "reason": "Traced ordinary-user admission, limiter, remaining/debit helpers and generation ordering in src/generate.ts:10-52; no reservation covers the provider attempt."}
}
```

### Legacy source coverage

Documents written before 2026-10-20 may contain `source: "code"` findings from the retired
source analyzer, `CF-SOURCE-COVERAGE` cards and `coverage_ref` links. They still validate and
render from their serialized text; nothing re-runs the analyzer. New scans write none of
them, and a missing automated source verdict is not a coverage failure.

## Source context

`provider_info.cloudflare.source_context`:

```json
{"configs": ["wrangler.toml", "apps/api/wrangler.jsonc"],
 "entries": [{"worker": "api", "env": "production", "kind": "main", "path": "src/index.ts", "exists": true},
             {"worker": "api", "env": "production", "kind": "assets", "path": "public", "exists": false}],
 "source_identity": {"vcs": "git", "head": "<sha>", "dirty": false, "detail": "..."}}
```

`configs` are the config paths found; `entries` are the declared paths per Worker and
environment: `kind` is `main`, `assets` or `pages_build_output_dir`, `path` is relative to the
scanned project, and `exists` is true, false, or null when the filesystem could not be asked.
Declared paths are declared, not verified deployments, and the list is not exhaustive:
clients, other services and dynamic registrations are the agent's to find.
`source_identity.vcs` is `git`, `none` or `unknown`;
`head` is a commit SHA or null; `dirty` is true, false, or null when it could not be
established; `detail` explains. A failed read is null/unknown, never a clean tree.

## ScopeRow

`{provider, check, endpoint, permission, purpose, status, detail}`. Each read of a check yields
`granted`, `denied (403)`, `unauthorized (401)`, `not found (404)`, `error` (a network or
transport error, a 2xx body that is not JSON, incomplete pagination or an unexpected response
shape), `error (<status>)` (any other HTTP status, including a 2xx whose envelope does not report
success) or `not run`. A check read more than once (per Worker or bucket) reports `granted` when
at least one read was granted and the rest were granted or `not found (404)`; `partial: ` followed
by its distinct statuses, sorted and joined with `, `, when some reads were granted and others
not; otherwise its single status, or its distinct statuses sorted and joined with `, ` (for
example `denied (403), error (500)`). `detail` carries the error text or, for `not run`, the
cause, or `not run; reason not recorded` when the code recorded none.

## InventoryRow

`{worker, file, line, method, path, paid_work: [kinds], review}`. The agent writes one row
per materially distinct work path, cheap and guarded ones included. Group variants only
when audience, controls, sinks and remedy match; name the grouped entries and different work
multipliers in `review`. Split different admission/bypass/budget paths, even if they call the
same helper. This is not a row per source call or a claim of an exhaustive route census.
`file`/`line` locate the entry
(route registration or handler); `paid_work` names the billed resources reached (e.g.
`workers-ai`, `email`, `r2-write`, `external:<host>`). For an HTTP route `method` is the HTTP
method and `path` the route. For other triggers `method` is the trigger kind (`alarm`,
`queue`, `scheduled`, `client`, `email`, `rpc`, `workflow`, `tail`) and `path` the handler
or binding name (e.g. `queue` with `jobs-queue`, `client` with `ios/SyncService.swift`).

Keep `review` as text, using the labels `audience`, `rate`, `cumulative budget` and
`per-request work`, with decisive evidence and remaining gaps; add the multiplier, lifecycle
or cache control that applies. Older documents also carry `reached_via` and
`guard_signals` (scanner observations, not proof of enforcement); agent rows may omit them.
Validation checks only each row's shape (an object, with `review` a string when present), not
its labels, evidence or completeness.
