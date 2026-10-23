"""Cloudflare findings model, JSON document and validation.

The findings JSON is the contract between the scanner, the reviewing agent and
the HTML renderer. Its shape is documented in references/findings-schema.md;
`validate_document` enforces the same rules so a hand-edited file fails loudly
instead of rendering something misleading.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCHEMA_ID = "cloudflare-runaway-bill-audit/findings@1"
# Documents written before the skill was renamed carry this id; the structure is identical.
LEGACY_SCHEMA_IDS = ("cloudflare-no-bill-explode/findings@1",)
ACCEPTED_SCHEMA_IDS = (SCHEMA_ID, *LEGACY_SCHEMA_IDS)
TOOL_NAME = "cloudflare-runaway-bill-audit"
TOOL_VERSION = "0.1.0"

SEVERITIES = ("alarm", "suggestion", "unknown", "pass", "not-applicable")
CONFIDENCES = ("certain", "heuristic")
SOURCES = ("config", "code", "api", "agent")
REVIEW_STATUSES = (
    "not-required",   # certain finding; the agent may still review it
    "needs-review",   # heuristic finding; the agent must confirm or dismiss it
    "confirmed",      # the agent read the evidence and agrees
    "false-positive", # the agent read the evidence and dismisses it (reason required)
)
EVIDENCE_KINDS = ("file", "api", "note")
# Optional top-level audit_status: a scan writes "unreviewed"; the agent sets "reviewed" (with a
# non-empty review_summary) after investigating the application. Only the agent changes it:
# render never promotes it. A document without the key predates it ("not recorded").
AUDIT_STATUSES = ("unreviewed", "reviewed")

_URL_RE = re.compile(r"^https?://[^\s<>\"']+$")


@dataclass
class Evidence:
    kind: str
    file: str | None = None
    line: int | None = None
    snippet: str | None = None
    endpoint: str | None = None
    field: str | None = None
    value: str | None = None
    text: str | None = None

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": self.kind}
        for key in ("file", "line", "snippet", "endpoint", "field", "value", "text"):
            val = getattr(self, key)
            if val is not None:
                out[key] = val
        return out

    # Snippets and values keep their full text here: clipping happens in clip_evidence(), after
    # credential redaction, so a credential that straddles the clip point is scrubbed, not cut.
    @staticmethod
    def at(file: str, line: int, snippet: str) -> "Evidence":
        return Evidence(kind="file", file=file, line=line, snippet=" ".join(str(snippet).split()))

    @staticmethod
    def api(endpoint: str, field: str | None = None, value: Any = None) -> "Evidence":
        return Evidence(kind="api", endpoint=endpoint, field=field,
                        value=None if value is None else " ".join(str(value).split()))

    @staticmethod
    def note(text: str) -> "Evidence":
        return Evidence(kind="note", text=text)


@dataclass
class Finding:
    rule: str
    provider: str
    cls: str
    severity: str
    title: str
    confidence: str
    source: str
    why: str
    incidents: list[str]
    fix: str
    docs: list[dict[str, str]]
    evidence: list[Evidence] = field(default_factory=list)
    missing: str | None = None
    target: str | None = None
    details: dict[str, Any] | None = None

    def to_json(self, fid: str) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": fid,
            "rule": self.rule,
            "provider": self.provider,
            "class": self.cls,
            "severity": self.severity,
            "title": self.title,
            "target": self.target,
            "evidence": [e.to_json() for e in self.evidence],
            "confidence": self.confidence,
            "source": self.source,
            "why": {"text": self.why, "incidents": list(self.incidents)},
            "fix": {"text": self.fix, "docs": list(self.docs)},
            "review": {
                "status": "needs-review" if self.confidence == "heuristic" else "not-required",
                "reason": "",
            },
        }
        if self.missing is not None:
            out["missing"] = self.missing
        if self.details is not None:
            out["details"] = self.details
        return out


def clip(text: str, limit: int = 240) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def clip_evidence(doc: dict[str, Any], limit: int = 240) -> dict[str, Any]:
    """Clip evidence snippets and API values in place. Call it after redaction: a credential
    that straddles the clip point must be scrubbed whole, never cut into a surviving prefix."""
    for f in doc.get("findings", []):
        for ev in f.get("evidence", []) if isinstance(f, dict) else []:
            for key in ("snippet", "value"):
                if isinstance(ev, dict) and isinstance(ev.get(key), str):
                    ev[key] = clip(ev[key], limit)
    return doc


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def build_document(*, project: str, providers: list[str], options: dict[str, Any],
                   findings: list[Finding], scope_requirements: list[dict[str, Any]],
                   provider_info: dict[str, Any], inventory: list[dict[str, Any]],
                   incidents: dict[str, dict[str, str]]) -> dict[str, Any]:
    order = {s: i for i, s in enumerate(SEVERITIES)}
    ordered = sorted(findings, key=lambda f: (order[f.severity], f.provider, f.cls, f.rule))
    return {
        "schema": SCHEMA_ID,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "generated_at": now_iso(),
        "project": project,
        "providers": providers,
        "options": options,
        "audit_status": "unreviewed",
        "review_summary": "",
        "findings": [f.to_json(f"f{i + 1:03d}") for i, f in enumerate(ordered)],
        "scope_requirements": scope_requirements,
        "provider_info": provider_info,
        "paid_work_inventory": inventory,
        "incidents": incidents,
    }


class SchemaError(ValueError):
    pass


def _req(obj: dict, key: str, typ: type | tuple, where: str, errors: list[str]) -> Any:
    if key not in obj:
        errors.append(f"{where}: missing '{key}'")
        return None
    val = obj[key]
    if not isinstance(val, typ):
        errors.append(f"{where}.{key}: expected {getattr(typ, '__name__', typ)}")
        return None
    return val


def validate_document(doc: Any) -> list[str]:
    """Return a list of problems; an empty list means the document renders faithfully."""
    errors: list[str] = []
    if not isinstance(doc, dict):
        return ["document: expected a JSON object"]
    schema = doc.get("schema")
    if not (isinstance(schema, str) and schema in ACCEPTED_SCHEMA_IDS):
        errors.append(f"schema: expected '{SCHEMA_ID}' (or the legacy "
                      + ", ".join(f"'{s}'" for s in LEGACY_SCHEMA_IDS) + ")")
    findings = _req(doc, "findings", list, "document", errors) or []
    incidents = doc.get("incidents") if isinstance(doc.get("incidents"), dict) else {}
    seen_ids: set[str] = set()
    for i, f in enumerate(findings):
        where = f"findings[{i}]"
        if not isinstance(f, dict):
            errors.append(f"{where}: expected object")
            continue
        fid = _req(f, "id", str, where, errors)
        if fid:
            if fid in seen_ids:
                errors.append(f"{where}.id: duplicate '{fid}'")
            seen_ids.add(fid)
            where = f"finding {fid}"
        for key in ("rule", "provider", "class", "title"):
            _req(f, key, str, where, errors)
        sev = _req(f, "severity", str, where, errors)
        if sev is not None and sev not in SEVERITIES:
            errors.append(f"{where}.severity: '{sev}' not in {SEVERITIES}")
        conf = _req(f, "confidence", str, where, errors)
        if conf is not None and conf not in CONFIDENCES:
            errors.append(f"{where}.confidence: '{conf}' not in {CONFIDENCES}")
        src = _req(f, "source", str, where, errors)
        if src is not None and src not in SOURCES:
            errors.append(f"{where}.source: '{src}' not in {SOURCES}")
        if sev == "unknown" and not (isinstance(f.get("missing"), str) and f["missing"].strip()):
            errors.append(f"{where}: an 'unknown' finding must name the missing permission or reason in 'missing'")
        ev = _req(f, "evidence", list, where, errors) or []
        if sev in ("alarm", "suggestion") and not ev:
            errors.append(f"{where}: alarms and suggestions need at least one evidence item")
        for j, e in enumerate(ev):
            ew = f"{where}.evidence[{j}]"
            if not isinstance(e, dict) or e.get("kind") not in EVIDENCE_KINDS:
                errors.append(f"{ew}: kind must be one of {EVIDENCE_KINDS}")
                continue
            if e["kind"] == "file" and not (isinstance(e.get("file"), str) and isinstance(e.get("line"), int)):
                errors.append(f"{ew}: file evidence needs 'file' (string) and 'line' (integer)")
            if e["kind"] == "api" and not isinstance(e.get("endpoint"), str):
                errors.append(f"{ew}: api evidence needs 'endpoint'")
            if e["kind"] == "note" and not isinstance(e.get("text"), str):
                errors.append(f"{ew}: note evidence needs 'text'")
        why = _req(f, "why", dict, where, errors)
        if why is not None:
            _req(why, "text", str, f"{where}.why", errors)
            inc = _req(why, "incidents", list, f"{where}.why", errors) or []
            for ref in inc:
                if not isinstance(ref, str):
                    errors.append(f"{where}.why.incidents: ids must be strings")
                elif ref not in incidents and not _URL_RE.match(ref):
                    errors.append(f"{where}.why.incidents: '{ref}' is neither a known incident id nor an http(s) URL")
        fix = _req(f, "fix", dict, where, errors)
        if fix is not None:
            _req(fix, "text", str, f"{where}.fix", errors)
            docs = _req(fix, "docs", list, f"{where}.fix", errors) or []
            for d in docs:
                if not (isinstance(d, dict) and isinstance(d.get("url"), str) and _URL_RE.match(d["url"])):
                    errors.append(f"{where}.fix.docs: each doc needs an http(s) 'url'")
        review = _req(f, "review", dict, where, errors)
        if review is not None:
            st = _req(review, "status", str, f"{where}.review", errors)
            if st is not None and st not in REVIEW_STATUSES:
                errors.append(f"{where}.review.status: '{st}' not in {REVIEW_STATUSES}")
            if st == "false-positive" and not str(review.get("reason", "")).strip():
                errors.append(f"{where}.review: a false-positive needs a 'reason'")
            if "original_severity" in review and review["original_severity"] not in SEVERITIES:
                errors.append(f"{where}.review.original_severity: not a severity")
    by_id = {f.get("id") for f in findings if isinstance(f, dict)}
    for i, f in enumerate(findings):
        if isinstance(f, dict) and "coverage_ref" in f and f["coverage_ref"] not in by_id:
            errors.append(f"findings[{i}].coverage_ref: '{f['coverage_ref']}' is not the id of a finding")
    status = doc.get("audit_status")
    if "audit_status" in doc and status not in AUDIT_STATUSES:
        errors.append(f"audit_status: expected one of {AUDIT_STATUSES}")
    summary = doc.get("review_summary")
    if "review_summary" in doc and not isinstance(summary, str):
        errors.append("review_summary: expected a string")
    if status == "reviewed" and not (isinstance(summary, str) and summary.strip()):
        errors.append("review_summary: a reviewed document needs a non-empty summary of the inspected scope, "
                      "mechanism dispositions and remaining gaps")
    for key in ("scope_requirements", "paid_work_inventory"):
        if key in doc and not isinstance(doc[key], list):
            errors.append(f"{key}: expected a list")
    if isinstance(doc.get("paid_work_inventory"), list):
        for i, row in enumerate(doc["paid_work_inventory"]):
            if not isinstance(row, dict):
                errors.append(f"paid_work_inventory[{i}]: expected an object")
            elif "review" in row and not isinstance(row["review"], str):
                errors.append(f"paid_work_inventory[{i}].review: expected a string")
    return errors


def load_document(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SchemaError(f"cannot read {path}: {exc.strerror or exc}") from None
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SchemaError(f"{path} is not valid JSON: line {exc.lineno} col {exc.colno}: {exc.msg}") from None
    problems = validate_document(doc)
    if problems:
        raise SchemaError(f"{path} is not a valid findings document:\n  - " + "\n  - ".join(problems))
    return doc


def is_safe_url(url: Any) -> bool:
    return isinstance(url, str) and bool(_URL_RE.match(url))


def audit_status(doc: dict[str, Any]) -> str | None:
    """'reviewed', 'unreviewed', or None when the document does not record it."""
    status = doc.get("audit_status")
    return status if status in AUDIT_STATUSES else None


def counts(doc: dict[str, Any]) -> dict[str, int]:
    """Counts by severity; findings dismissed as false positives are counted separately."""
    out = {s: 0 for s in SEVERITIES}
    out["dismissed"] = 0
    for f in doc.get("findings", []):
        if f.get("review", {}).get("status") == "false-positive":
            out["dismissed"] += 1
        elif f.get("severity") in out:
            out[f["severity"]] += 1
    return out
