"""One projection of the findings document, shared by the HTML and markdown reports.

Both formats read findings only through this module, so they carry the same
findings in the same order with the same evidence, review decision and fix;
a format may present them more or less compactly but never drops any of it.
"""

from __future__ import annotations

from typing import Any

from .findings import audit_status, is_safe_url

ACTION_SEVERITIES = ("alarm", "suggestion", "unknown")

# What each audit status means, said the same way in both reports.
AUDIT = {
    "unreviewed": (
        "UNREVIEWED: raw scan",
        "This is a raw scan: configuration and account facts only. No investigation of the application source "
        "is recorded, so zero alarms, passed checks or an empty paid-work inventory say nothing about the "
        "application's billing exposure. An agent investigates the project, then sets audit_status to "
        "\"reviewed\" with a review_summary and re-renders."),
    "reviewed": (
        "Reviewed by an agent",
        "An agent recorded its investigation (summary below). This records the review that was done and its "
        "remaining gaps; it is not a certification that every spending path is bounded."),
    None: (
        "Audit status not recorded",
        "This document predates the audit_status field. Its finding counts do not show whether the application "
        "source was reviewed."),
}
INVENTORY_NOTE = ("Paths the reviewing agent traced to paid work, with the controls it recorded (audience, rate, "
                  "cumulative budget, per-request work). A missing row means not inventoried, not free or safe.")
SOURCE_NOTE = ("Paths declared by the wrangler configuration: not verified deployments, and not an exhaustive "
               "list of the application's routes, clients or background work.")


def _text(v: Any) -> str:
    return "" if v is None else str(v)


def inventory_row(r: dict) -> dict[str, Any]:
    """One paid-work row: what triggers it (HTTP method and path, or a trigger kind such as queue/alarm
    and the handler or binding name), where, the paid work and the recorded controls."""
    where = ""
    if r.get("file") is not None:
        where = _text(r.get("file")) + (f":{r.get('line')}" if r.get("line") is not None else "")
    g = r.get("guard_signals") if isinstance(r.get("guard_signals"), dict) else {}
    signals = "; ".join(f"{k}: {len(v)}" for k, v in g.items() if isinstance(v, list))
    paid = r.get("paid_work")
    return {
        "entry": " ".join(x for x in (_text(r.get("method")), _text(r.get("path"))) if x),
        "worker": _text(r.get("worker")),
        "where": where,
        "paid_work": [_text(x) for x in paid] if isinstance(paid, list) else ([_text(paid)] if paid else []),
        "review": _text(r.get("review")),
        "signals": signals,
    }


def source_context(info: dict) -> list[dict[str, Any]]:
    """Per provider: config files, declared entry/asset paths and the source identity, if recorded."""
    out = []
    for name, pi in (info or {}).items():
        sc = pi.get("source_context") if isinstance(pi, dict) else None
        if not isinstance(sc, dict):
            continue
        ident = sc.get("source_identity") if isinstance(sc.get("source_identity"), dict) else {}
        vcs, head, dirty = ident.get("vcs"), ident.get("head"), ident.get("dirty")
        if vcs == "git" and head:
            state = {True: "working tree has changes", False: "no uncommitted changes"}.get(
                dirty, "working tree state unknown")
            identity = f"{vcs} {_text(head)[:12]}, {state}"
        elif vcs == "none":
            identity = "not a version-controlled work tree: no source revision"
        else:
            identity = "unknown"
        if ident.get("detail"):
            identity += f" ({_text(ident.get('detail'))})"
        entries = [e for e in sc.get("entries") or [] if isinstance(e, dict)]
        out.append({
            "provider": name,
            "identity": identity,
            "configs": [_text(c) for c in sc.get("configs") or []],
            "entries": [{"worker": _text(e.get("worker")), "env": _text(e.get("env")), "kind": _text(e.get("kind")),
                         "path": _text(e.get("path")),
                         "exists": {True: "yes", False: "no"}.get(e.get("exists"), "unknown")} for e in entries],
        })
    return out


def incident(ref: Any, incidents: dict) -> dict[str, Any]:
    """An incident reference: its id, a safe URL if there is one, and its title if known."""
    inc = incidents.get(ref) if isinstance(incidents, dict) and isinstance(ref, str) else None
    if isinstance(inc, dict):
        url = inc.get("url")
        return {"ref": ref, "url": url if is_safe_url(url) else None, "title": inc.get("title") or ""}
    return {"ref": ref, "url": ref if is_safe_url(ref) else None, "title": None}


def finding(f: dict, incidents: dict) -> dict[str, Any]:
    review = f.get("review") if isinstance(f.get("review"), dict) else {}
    sev = f.get("severity") or ""
    status = review.get("status") or "not-required"
    was = review.get("original_severity")
    why = f.get("why") if isinstance(f.get("why"), dict) else {}
    fix = f.get("fix") if isinstance(f.get("fix"), dict) else {}
    details = f.get("details")
    return {
        "id": f.get("id"), "rule": f.get("rule"), "provider": f.get("provider"), "class": f.get("class"),
        "severity": sev, "title": f.get("title"), "target": f.get("target") or None,
        "confidence": f.get("confidence"), "source": f.get("source"),
        "review": {"status": status, "reason": review.get("reason") or "", "was": was if was and was != sev else None},
        "dismissed": status == "false-positive",
        "missing": f.get("missing") if sev == "unknown" and f.get("missing") else None,
        "evidence": [e for e in f.get("evidence") or [] if isinstance(e, dict)],
        "why": why.get("text") or "",
        "incidents": [incident(r, incidents) for r in why.get("incidents") or []],
        "fix": fix.get("text") or "",
        "docs": [{"url": d.get("url"), "title": d.get("title") or d.get("url"), "safe": is_safe_url(d.get("url"))}
                 for d in fix.get("docs") or [] if isinstance(d, dict)],
        "details": details if isinstance(details, dict) and isinstance(details.get("rows"), list) else None,
        "coverage_ref": f.get("coverage_ref") if isinstance(f.get("coverage_ref"), str) else None,
        "affected": [],
    }


def project(doc: dict[str, Any]) -> dict[str, Any]:
    """The findings grouped the way both reports present them, each group in findings.json order."""
    incidents = doc.get("incidents") if isinstance(doc.get("incidents"), dict) else {}
    views = [finding(f, incidents) for f in doc.get("findings") or [] if isinstance(f, dict)]
    active = [v for v in views if not v["dismissed"]]
    # results that only wait on a coverage card are listed under that card, not repeated as cards
    cards = {v["id"]: v for v in active}
    grouped = set()
    for v in active:
        card = cards.get(v["coverage_ref"])
        if v["severity"] == "unknown" and card is not None and card is not v and card["severity"] == "unknown":
            card["affected"].append(v)
            grouped.add(id(v))
    active = [v for v in active if id(v) not in grouped]
    return {
        "token_providers": {v["provider"] for v in views if not v["dismissed"] and v["severity"] == "unknown"
                            and v["source"] == "api" and any(term in (v["missing"] or "").lower()
                            for term in ("token", "credential", "oauth", "permission", "denied (403)", "--account"))},
        "incidents": incidents,
        "by_severity": {s: [v for v in active if v["severity"] == s]
                        for s in (*ACTION_SEVERITIES, "pass", "not-applicable")},
        "dismissed": [v for v in views if v["dismissed"]],
        "needs_review": sum(1 for v in views if v["review"]["status"] == "needs-review"),
        "audit": {"status": audit_status(doc), "label": AUDIT[audit_status(doc)][0],
                  "meaning": AUDIT[audit_status(doc)][1],
                  "summary": doc.get("review_summary") if isinstance(doc.get("review_summary"), str) else ""},
        "inventory": [inventory_row(r) for r in doc.get("paid_work_inventory") or [] if isinstance(r, dict)],
        "source_context": source_context(doc.get("provider_info") if isinstance(doc.get("provider_info"), dict) else {}),
    }
