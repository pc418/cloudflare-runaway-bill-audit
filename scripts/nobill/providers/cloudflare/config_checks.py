"""Checks that read only the wrangler config (layer a)."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from ...findings import Evidence, Finding
from . import pricing
from .rules import RULES
from .wrangler import Project, WorkerView
from .values import MISSING, is_int as _is_int, is_num as _is_num, shown as _shown, sampling

LARGE_INSTANCE_TYPES = {"standard-3", "standard-4"}
CPU_MS_MAX = 300_000  # the platform maximum for limits.cpu_ms (rule CF-CPU-LIMIT)


def _ev(w: WorkerView, key: str, value: str | None = None) -> Evidence:
    rel, ln, text = w.where(key, value)
    return Evidence.at(rel, ln, text)


def _ev_consumer(w: WorkerView, queue: str) -> Evidence:
    anchor = w.config.find_line("consumers", w.env_line)
    ln = w.config.find_line("queue", anchor, queue)
    return Evidence.at(w.config.rel, ln, w.config.line_text(ln))


def _note(text: str) -> Evidence:
    return Evidence.note(text)


_ALL_PATHS = {"/*", "*", "/**", "/"}


def _retry_scope() -> Evidence:
    return Evidence.note("max_retries and a dead-letter queue bound redelivery of failing messages; they do not "
                         "bound messages the code sends or re-enqueues")
_MAX_ROUTES_JSON = 100_000


def _project_path(base: Path, cfg_dir: str, p: Path) -> str:
    """p relative to the project root (the config's directory is cfg_dir there); a declared path
    outside the project keeps its ../ form, and one relpath cannot express stays absolute."""
    try:
        return os.path.normpath(os.path.join(cfg_dir, os.path.relpath(p, base))).replace(os.sep, "/")
    except ValueError:  # e.g. another drive on Windows
        return str(p)


def _pages_routes(w: WorkerView) -> tuple[tuple[str, int, str] | None, list[tuple[str, str]]]:
    """For a Pages project: ((file, line, text) of a _routes.json that includes every path, or None,
    [(file, reason)] for each _routes.json that exists but could not be read or parsed). Read-only;
    a missing file (not built yet) is no evidence either way, an unreadable one is an unknown."""
    out_dir = w.get("pages_build_output_dir")
    if not isinstance(out_dir, str):
        return None, []
    base = w.config.path.parent
    cfg_dir = w.config.rel.rsplit("/", 1)[0] + "/" if "/" in w.config.rel else ""
    failed: list[tuple[str, str]] = []
    for cand in (base / out_dir / "_routes.json", base / "functions" / "_routes.json", base / "_routes.json"):
        rel = _project_path(base, cfg_dir, cand)
        try:
            st = cand.stat()
        except (FileNotFoundError, NotADirectoryError):
            continue  # genuinely absent (not built yet): no evidence either way
        except (OSError, ValueError) as exc:  # e.g. an output directory this user cannot search
            failed.append((rel, f"cannot check: {type(exc).__name__}"))
            continue
        if not stat.S_ISREG(st.st_mode):
            failed.append((rel, "not a regular file"))
            continue
        try:
            if st.st_size > _MAX_ROUTES_JSON:
                failed.append((rel, f"larger than {_MAX_ROUTES_JSON} bytes, not read"))
                continue
            text = cand.read_text(encoding="utf-8")
            data = json.loads(text)
        except (OSError, UnicodeDecodeError) as exc:
            failed.append((rel, f"cannot read: {type(exc).__name__}"))
            continue
        except ValueError as exc:
            failed.append((rel, f"not valid JSON: {exc}"[:160]))
            continue
        inc = data.get("include") if isinstance(data, dict) else None
        if not (isinstance(inc, list) and all(isinstance(p, str) for p in inc)):
            failed.append((rel, f"'include' is missing or not a list of strings ({_shown(inc)})"))
            continue
        if any(p in _ALL_PATHS for p in inc):
            lines = text.splitlines() or [""]
            ln = next((i + 1 for i, line in enumerate(lines) if '"include"' in line), 1)
            return (rel, ln, lines[ln - 1].strip()), failed  # clipped after redaction (clip_evidence)
    return None, failed


def check_config(project: Project) -> list[Finding]:
    out: list[Finding] = []
    if not project.configs:
        out.append(RULES["CF-NO-CONFIG"].finding(
            "unknown", confidence="certain", source="config",
            evidence=[_note("no wrangler.toml / wrangler.json / wrangler.jsonc outside node_modules and dot-directories")],
            missing="no wrangler config in the scanned directory"))
    for where, reason in project.unlisted:
        out.append(RULES["CF-CONFIG-UNREADABLE"].finding(
            "unknown", confidence="certain", source="config", target=where,
            title="Directory could not be listed while finding wrangler configs",
            evidence=[_note(f"{where}: {reason} while listing the directory")],
            missing=(f"directory {where} could not be listed ({reason}); a wrangler config inside it was not read, "
                     "so the config inventory may be incomplete")))
    for cfg in project.configs:
        if cfg.error:
            out.append(RULES["CF-CONFIG-UNREADABLE"].finding(
                "unknown", confidence="certain", source="config", target=cfg.rel,
                # Decoder details can quote a value from the file. Keep them in missing,
                # which is redacted before rendering, not in a pre-clipped snippet.
                evidence=[Evidence.at(cfg.rel, 1, "config unreadable; decoder details below")],
                missing=f"config unreadable ({cfg.error}); its config checks were not run"))
    for w in project.workers:
        out.extend(_worker_checks(w))
    return out


def _worker_checks(w: WorkerView) -> list[Finding]:
    out: list[Finding] = []
    target = w.label
    paid = w.paid_binding_kinds()
    # A malformed paid-binding declaration is dropped from `paid`, so the set may be incomplete:
    # a known paid binding keeps its checks with that note; none known is unknown, never "no paid work".
    paid_broken = sorted({p for p, _, _ in w.setting_errors if p.split(".")[0].split("[")[0] in _PAID_SECTIONS})
    incomplete = [_note("paid-binding set may be incomplete: " + ", ".join(paid_broken) + " unreadable")] if paid_broken else []
    not_established = f"paid bindings could not be established: {', '.join(paid_broken)} unreadable"

    # -- workers.dev / preview URLs -----------------------------------------------
    if not paid and paid_broken:
        out.append(RULES["CF-WORKERS-DEV-ON"].finding(
            "unknown", confidence="certain", source="config", target=target,
            title="workers.dev / preview URL exposure not checked", evidence=[_ev(w, p.split(".")[-1].split("[")[0]) for p in paid_broken],
            missing=not_established))
    if paid:
        wd = w.get("workers_dev")
        pv = w.get("preview_urls")
        rule = RULES["CF-WORKERS-DEV-ON"]
        bad = [k for k, v in (("workers_dev", wd), ("preview_urls", pv)) if v is not None and not isinstance(v, bool)]
        if bad:
            out.append(rule.finding("unknown", confidence="certain", source="config", target=target,
                                    title="workers.dev / preview URL setting unreadable",
                                    evidence=[_ev(w, k) for k in bad],
                                    missing=" and ".join(f"{k} is not a boolean ({_shown(w.get(k))})" for k in bad)))
        elif wd is False and pv is not True:
            out.append(rule.finding("pass", confidence="certain", source="config", target=target,
                                    title="workers.dev disabled for a Worker with paid bindings",
                                    evidence=[_ev(w, "workers_dev")] + incomplete))
        else:
            ev = []
            if wd is None:
                ev.append(_note(f"workers_dev is not set (defaults to true); paid bindings: {', '.join(paid)}"))
            else:
                ev.append(_ev(w, "workers_dev"))
            if pv is True:
                ev.append(_ev(w, "preview_urls"))
            elif pv is None:
                ev.append(_note("preview_urls is not set: wrangler leaves an existing setting unchanged; a new "
                                "Worker's preview URLs follow workers_dev"))
            title = ("Preview URLs enabled for a Worker with paid bindings" if wd is False
                     else "workers.dev URL left on for a Worker with paid bindings")
            out.append(rule.finding("suggestion", confidence="certain", source="config", target=target,
                                    title=title, evidence=ev + incomplete))

    # -- run_worker_first ---------------------------------------------------------
    assets = w.get("assets")
    rwf = assets.get("run_worker_first") if isinstance(assets, dict) and w.ok("assets.run_worker_first") else None
    everything = rwf is True or (isinstance(rwf, list) and any(p in _ALL_PATHS for p in rwf if isinstance(p, str)))
    pages_all, pages_failed = _pages_routes(w)
    for rel, reason in pages_failed:
        out.append(RULES["CF-RUN-WORKER-FIRST"].finding(
            "unknown", confidence="certain", source="config", target=target,
            title="Pages _routes.json could not be read", evidence=[Evidence.at(rel, 1, reason)],
            missing=f"{rel}: {reason}; which paths run the Functions is not known"))
    if everything or pages_all:
        # binding presence is not evidence that an asset request starts that resource: a reviewable
        # recommendation, never an automatic alarm (design 261020 section 7, config heuristics)
        heavy = [k for k in ("Containers", "Browser Run") if k in paid] + (["Durable Objects"] if w.do_bindings() else [])
        if everything:
            ev = [_ev(w, "run_worker_first")]
            title = None
            if isinstance(rwf, list):
                ev.append(_note(f"run_worker_first = {rwf}: the pattern list covers every path, like true"
                                + (" (with exclusions)" if any(str(p).startswith("!") for p in rwf) else "")))
                title = "assets.run_worker_first patterns cover every path: every asset request runs the Worker"
        else:
            ev = [Evidence.at(pages_all[0], pages_all[1], pages_all[2]),
                  _note("Pages _routes.json includes every path: each static-asset request runs the Functions")]
            title = "Pages _routes.json includes every path: every asset request runs the Functions"
        out.append(RULES["CF-RUN-WORKER-FIRST"].finding(
            "suggestion", confidence="heuristic" if heavy else "certain", source="config", target=target,
            **({"title": title} if title else {}),
            evidence=ev + ([_note("expensive bindings in this Worker: " + ", ".join(heavy) + ". Whether an asset "
                                  "or stray request reaches them depends on the code path; binding presence does "
                                  "not show that every request starts them")] if heavy else [])))

    # -- containers -----------------------------------------------------------------
    for i, c in w.rows("containers"):
        cname = w.row_label("containers", i)
        mi = c.get("max_instances")
        if "max_instances" not in c:
            out.append(RULES["CF-CONTAINER-MAX-INSTANCES"].finding(
                "suggestion", confidence="certain", source="config", target=f"{target} / {cname}",
                evidence=[_ev(w, "class_name", str(cname)), _note("max_instances not set (defaults to 20)")]))
        elif not _is_int(mi) or mi < 1:
            out.append(RULES["CF-CONTAINER-MAX-INSTANCES"].finding(
                "unknown", confidence="certain", source="config", target=f"{target} / {cname}",
                title="Container max_instances unreadable", evidence=[_ev(w, "max_instances")],
                missing=f"max_instances is not a positive integer ({_shown(mi)})"))
        elif mi >= 20:
            out.append(RULES["CF-CONTAINER-MAX-INSTANCES"].finding(
                "suggestion", confidence="certain", source="config", target=f"{target} / {cname}",
                title="Container max_instances at or above the default (20)",
                evidence=[_ev(w, "max_instances")]))
        else:
            out.append(RULES["CF-CONTAINER-MAX-INSTANCES"].finding(
                "pass", confidence="certain", source="config", target=f"{target} / {cname}",
                title=f"Container max_instances = {mi}", evidence=[_ev(w, "max_instances"), _note(
                    "caps concurrently running instances of this container class; it does not bound how long they "
                    "run, how often requests start them, or total spend")]))
        size = w.field("containers", i, c, "instance_type")
        if isinstance(size, str) and size in LARGE_INSTANCE_TYPES:  # a custom size table is not a named size
            out.append(RULES["CF-CONTAINER-SIZE"].finding(
                "suggestion", confidence="certain", source="config", target=f"{target} / {cname}",
                evidence=[_ev(w, "instance_type")]))

    # -- queues -------------------------------------------------------------------
    consumers = w.rows("queues.consumers")
    dlqs = {w.field("queues.consumers", i, c, "dead_letter_queue") for i, c in consumers
            if isinstance(w.field("queues.consumers", i, c, "dead_letter_queue"), str)}
    for i, cons in consumers:
        qname = w.row_label("queues.consumers", i)  # "queue <name>", or the row's position
        raw = w.field("queues.consumers", i, cons, "queue")  # the validated name, for DLQ membership
        is_dlq = isinstance(raw, str) and raw in dlqs
        ev = [_ev_consumer(w, raw if isinstance(raw, str) and raw else "consumers")]
        missing = [k for k in ("max_retries", "dead_letter_queue") if k not in cons]
        bad = []
        if "max_retries" in cons and not (_is_int(cons["max_retries"]) and cons["max_retries"] >= 0):
            bad.append(f"max_retries is not a non-negative integer ({_shown(cons['max_retries'])})")
        if "dead_letter_queue" in cons and not (isinstance(cons["dead_letter_queue"], str)
                                                and cons["dead_letter_queue"].strip()):
            bad.append(f"dead_letter_queue is not a queue name ({_shown(cons['dead_letter_queue'])})")
        if bad:
            out.append(RULES["CF-QUEUE-CONSUMER-BOUNDS"].finding(
                "unknown", confidence="certain", source="config", target=f"{target} / {qname}",
                title=f"Queue consumer {qname} retry settings unreadable", evidence=ev,
                missing="; ".join(bad)))
        elif is_dlq:
            # a dead-letter queue's own consumer: a further DLQ is optional; it only needs bounded retries
            if "max_retries" in cons:
                out.append(RULES["CF-QUEUE-CONSUMER-BOUNDS"].finding(
                    "pass", confidence="certain", source="config", target=f"{target} / {qname}",
                    title=f"Dead-letter queue consumer {qname}: max_retries={cons.get('max_retries')} set",
                    evidence=ev + [_retry_scope()]))
            else:
                out.append(RULES["CF-QUEUE-CONSUMER-BOUNDS"].finding(
                    "suggestion", confidence="certain", source="config", target=f"{target} / {qname}",
                    title=f"Dead-letter queue consumer {qname} without explicit max_retries",
                    evidence=ev + [_note("max_retries not set (defaults to 3)")]))
        elif missing:
            out.append(RULES["CF-QUEUE-CONSUMER-BOUNDS"].finding(
                "suggestion", confidence="certain", source="config", target=f"{target} / {qname}",
                evidence=ev + [_note("not set: " + ", ".join(missing)
                                     + (" (max_retries defaults to 3)" if "max_retries" in missing else "")
                                     + ("; failing messages are discarded" if "dead_letter_queue" in missing else ""))]))
        else:
            out.append(RULES["CF-QUEUE-CONSUMER-BOUNDS"].finding(
                "pass", confidence="certain", source="config", target=f"{target} / {qname}",
                title=(f"Queue consumer {qname}: max_retries={cons.get('max_retries')} and dead_letter_queue "
                       f"{cons.get('dead_letter_queue')} set"),
                evidence=ev + [_retry_scope()]))
        if "max_concurrency" in cons and not (_is_int(cons["max_concurrency"]) and cons["max_concurrency"] > 0):
            out.append(RULES["CF-QUEUE-CONCURRENCY"].finding(
                "unknown", confidence="certain", source="config", target=f"{target} / {qname}", evidence=ev,
                missing=f"max_concurrency is not a positive integer ({_shown(cons['max_concurrency'])})"))
        elif not is_dlq and paid and "max_concurrency" not in cons:
            out.append(RULES["CF-QUEUE-CONCURRENCY"].finding(
                "suggestion", confidence="certain", source="config", target=f"{target} / {qname}",
                evidence=ev + [_note("paid bindings in this Worker: " + ", ".join(paid))] + incomplete))
        elif not is_dlq and paid_broken and "max_concurrency" not in cons:
            out.append(RULES["CF-QUEUE-CONCURRENCY"].finding(
                "unknown", confidence="certain", source="config", target=f"{target} / {qname}",
                title=f"Queue consumer {qname} concurrency not checked", evidence=ev, missing=not_established))

    # -- self service binding -------------------------------------------------------
    for i, s in w.rows("services"):
        if w.field("services", i, s, "service") == w.name:
            out.append(RULES["CF-SELF-SERVICE-BINDING"].finding(
                "suggestion", confidence="heuristic", source="config", target=target,
                evidence=[_ev(w, "service", str(s.get("service")))]
                + ([_note(f"entrypoint {s['entrypoint']} (self-RPC to a named entrypoint can be intended)")] if s.get("entrypoint") else [])))

    # -- rate limit binding ---------------------------------------------------------
    if not paid and paid_broken:
        out.append(RULES["CF-NO-RATELIMIT-BINDING"].finding(
            "unknown", confidence="certain", source="config", target=target,
            title="Rate Limiting binding not checked", evidence=[_ev(w, p.split(".")[-1].split("[")[0]) for p in paid_broken],
            missing=not_established))
    if paid:
        rl = w.ratelimit_bindings()
        if not rl:
            out.append(RULES["CF-NO-RATELIMIT-BINDING"].finding(
                "suggestion", confidence="certain", source="config", target=target,
                evidence=[_note("no ratelimits / unsafe ratelimit binding; paid bindings: " + ", ".join(paid))] + incomplete))
        else:
            out.append(RULES["CF-NO-RATELIMIT-BINDING"].finding(
                "pass", confidence="certain", source="config", target=target,
                title="Rate Limiting binding declared: " + ", ".join(rl),
                evidence=[_ev(w, "ratelimits") if w.list_of("ratelimits") else _ev(w, "type", '"ratelimit"'), _note(
                    "a declaration only: which paths call .limit() before paid work and act on its result is for "
                    "review, and a burst limit per key and location is not a cumulative work budget")] + incomplete))

    # -- limits -------------------------------------------------------------------
    limits = w.get("limits", {})
    if not isinstance(limits, dict):  # neither cpu_ms nor subrequests can be read from it
        out.append(RULES["CF-CPU-LIMIT"].finding(
            "unknown", confidence="certain", source="config", target=target, title="limits unreadable",
            evidence=[_ev(w, "limits")], missing=f"limits is not a table ({_shown(limits)})"))
        limits = None
    if w.get("main") and limits is not None:
        cpu = limits.get("cpu_ms", MISSING)
        if cpu is MISSING:
            out.append(RULES["CF-CPU-LIMIT"].finding(
                "suggestion", confidence="certain", source="config", target=target,
                evidence=[_note("[limits] cpu_ms not set (default cap 30,000 ms per invocation)")]))
        elif not _is_num(cpu) or not 0 < cpu <= CPU_MS_MAX:
            out.append(RULES["CF-CPU-LIMIT"].finding(
                "unknown", confidence="certain", source="config", target=target, title="limits.cpu_ms unreadable",
                evidence=[_ev(w, "cpu_ms")],
                missing=f"cpu_ms is not a positive number up to {CPU_MS_MAX:,} ms ({_shown(cpu)})"))
        elif cpu == CPU_MS_MAX:
            out.append(RULES["CF-CPU-LIMIT"].finding(
                "suggestion", confidence="certain", source="config", target=target,
                title="limits.cpu_ms raised to the maximum (300,000 ms)", evidence=[_ev(w, "cpu_ms")]))
        else:
            out.append(RULES["CF-CPU-LIMIT"].finding(
                "pass", confidence="certain", source="config", target=target,
                title=f"limits.cpu_ms = {cpu}", evidence=[_ev(w, "cpu_ms"), _note(
                    "a per-invocation CPU ceiling: it does not bound how many invocations run or total spend")]))
    sub = limits.get("subrequests", MISSING) if limits is not None else MISSING
    if sub is not MISSING and not (_is_int(sub) and sub >= 0):
        out.append(RULES["CF-SUBREQUESTS-RAISED"].finding(
            "unknown", confidence="certain", source="config", target=target, title="limits.subrequests unreadable",
            evidence=[_ev(w, "subrequests")],
            missing=f"subrequests is not a non-negative integer ({_shown(sub)})"))
    elif sub is not MISSING and sub > 10000:
        out.append(RULES["CF-SUBREQUESTS-RAISED"].finding(
            "suggestion", confidence="certain", source="config", target=target, evidence=[_ev(w, "subrequests")]))

    # -- logging -------------------------------------------------------------------
    enabled, rate, bad_obs = sampling(w.get("observability", MISSING))
    if bad_obs:
        out.append(RULES["CF-LOG-SAMPLING"].finding(
            "unknown", confidence="certain", source="config", target=target,
            title="Workers Logs settings unreadable", evidence=[_ev(w, "observability")], missing="; ".join(bad_obs)))
    elif enabled:
        if rate is MISSING or rate == 1:
            ev = [_ev(w, "head_sampling_rate") if rate is not MISSING else _ev(w, "observability")]
            ev.append(_note("head_sampling_rate " + ("not set (defaults to 1 = 100%)" if rate is MISSING else f"= {rate}")))
            out.append(RULES["CF-LOG-SAMPLING"].finding(
                "suggestion", confidence="certain", source="config", target=target, evidence=ev))
        else:
            out.append(RULES["CF-LOG-SAMPLING"].finding(
                "pass", confidence="certain", source="config", target=target,
                title=f"Workers Logs head sampling at {rate}", evidence=[_ev(w, "head_sampling_rate"), _note(
                    "sampling picks which invocations are logged; each sampled invocation still writes every line "
                    "it logs, so the rate does not bound log volume")]))

    # -- cost inventory --------------------------------------------------------------
    rows = pricing.inventory(w)
    metered = [r for r in rows if r["binding"] != "Worker"]
    if metered and w.has_entry():
        out.append(RULES["CF-COST-INVENTORY"].finding(
            "suggestion", confidence="certain", source="config", target=target,
            title=f"Declared Cloudflare binding costs for {w.name} ({len(metered)} metered binding types)",
            evidence=[Evidence.at(w.config.rel, w.env_line, f"{len(metered)} metered binding types in this Worker")],
            details={"columns": ["binding", "names", "bills_by", "url"], "rows": rows,
                     "note": f"Workers Paid prices as of {pricing.AS_OF}. Declared bindings only, not verified "
                             "execution; external SDK/HTTP spend is not inventoried here."}))
    # A malformed field must not yield an absence/default/equality result for the conclusion that
    # reads it: the finding with the same rule and row target is replaced, once, by one unknown
    # naming every malformed path under it; sibling rows and other rules keep theirs. The
    # inventory stays, marked incomplete.
    if w.setting_errors:
        for f in out:
            if f.rule == "CF-COST-INVENTORY":
                f.evidence.append(_note("may be incomplete: " + ", ".join(p for p, _, _ in w.setting_errors) + " unreadable"))
    grouped: dict[tuple[str, str], list[tuple[str, Any, str]]] = {}
    for path, value, expected in w.setting_errors:
        rule, scope = _setting_scope(path, w)
        grouped.setdefault((rule, target if scope is None else f"{target} / {scope}"), []).append((path, value, expected))
    for (rule, tgt), errs in grouped.items():
        out = [f for f in out if not (f.rule == rule and f.target == tgt)]
        out.append(RULES[rule].finding(
            "unknown", confidence="certain", source="config", target=tgt,
            title="Configuration setting unreadable: " + ", ".join(p for p, _, _ in errs),
            evidence=[_ev(w, p.split(".")[-1].split("[")[0]) for p, _, _ in errs],
            missing="; ".join(f"{p} is not {e} ({_shown(v)})" for p, v, e in errs)))
    return out


_PAID_SECTIONS = {"ai", "browser", "images", "containers", "send_email"}
_ROW_KEYS = ("containers", "queues.consumers")


def _setting_scope(path: str, w: WorkerView) -> tuple[str, str | None]:
    """(rule, row target suffix) for a malformed setting path: the conclusion it invalidates. Row
    targets use the same label the checks use (a valid name, else the row's position)."""
    for key in _ROW_KEYS:
        if path.startswith(key + "[") and "]" in path:
            i = int(path[len(key) + 1:path.index("]")])
            tail = path[path.index("]") + 1:]
            if tail in (".class_name", ".name", ".queue"):  # the row's identity, not a bound
                return "CF-CONFIG-UNREADABLE", w.row_label(key, i)
            return _setting_rule(path), w.row_label(key, i)
    if path.startswith("queues.producers"):  # no retained rule concludes anything from a producer row
        return "CF-CONFIG-UNREADABLE", None
    return _setting_rule(path), None


def _setting_rule(path: str) -> str:
    if path.startswith(("workers_dev", "preview_urls")):
        return "CF-WORKERS-DEV-ON"
    if path.startswith(("assets", "pages_build_output_dir")):
        return "CF-RUN-WORKER-FIRST"
    if path.startswith("containers"):
        return "CF-CONTAINER-SIZE" if path.endswith("instance_type") else "CF-CONTAINER-MAX-INSTANCES"
    if path.startswith("queues"):
        return "CF-QUEUE-CONCURRENCY" if path.endswith("max_concurrency") else "CF-QUEUE-CONSUMER-BOUNDS"
    if path.startswith(("ratelimits", "unsafe")):
        return "CF-NO-RATELIMIT-BINDING"
    if path.startswith("services"):
        return "CF-SELF-SERVICE-BINDING"
    return "CF-CONFIG-UNREADABLE"
