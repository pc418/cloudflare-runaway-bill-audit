"""Render a findings document to report.md: a compact handoff for a coding agent.

Action first: must-fix alarms, then suggestions, then unknowns, each complete (stable
id, rule, target, every evidence item, the review decision, the full why, the fix
and its doc links; unknowns also say what to grant or check), then dismissed summaries
and complete scoped passes/not-applicable results. Findings come from the same projection as the HTML
(nobill/view.py), so both reports hold the same findings in the same order.

Everything that came from the project, the API or the agent is neutralised:
free text is put on one line with the characters that start links, images,
autolinks, raw HTML, code spans and headings backslash-escaped; file paths,
endpoints and values go in inline code spans; snippets go in fenced blocks
whose fence is longer than any backtick run inside them. Words a GFM renderer
would autolink (bare URLs, www. hosts, emails) are put in inline code. Only the
report's own doc and incident URLs (http(s), no spaces or angle brackets) are links.
"""

from __future__ import annotations

import re
from typing import Any

from . import view
from .findings import counts

_MD_SPECIAL = re.compile(r"([\\`\[\]<>#])")
_SAFE_LINK = re.compile(r"^https?://[^\s<>()`\\]+$")


# A word GFM could turn into a link on its own: a scheme URL (https://, ftp://...), a www. host,
# or anything with an @ (emails, mailto:/xmpp: forms). Such words are printed as inline code.
_AUTOLINK_WORD = re.compile(r"(?i)\S*(?:[a-z][a-z0-9+.-]*://|www\.|@)\S*")


def text(value: Any) -> str:
    """Project/agent text as inert inline markdown on a single line: link, image, HTML,
    code-span and heading characters are escaped, and words a GFM renderer would
    autolink (bare URLs, www. hosts, emails) become inline code."""
    s = " ".join(("" if value is None else str(value)).split())
    out, pos = [], 0
    for m in _AUTOLINK_WORD.finditer(s):
        out.append(_MD_SPECIAL.sub(r"\\\1", s[pos:m.start()]))
        out.append(code(m.group(0)))
        pos = m.end()
    out.append(_MD_SPECIAL.sub(r"\\\1", s[pos:]))
    return "".join(out)


def code(value: Any) -> str:
    """An inline code span that no backtick inside the value can close."""
    s = " ".join(("" if value is None else str(value)).split())
    if not s:
        return "``"
    run = max((len(m) for m in re.findall(r"`+", s)), default=0)
    fence = "`" * (run + 1)
    pad = " " if s.startswith("`") or s.endswith("`") else ""
    return f"{fence}{pad}{s}{pad}{fence}"


def fenced(value: Any) -> str:
    """A fenced block that no line of the value can close."""
    body = ("" if value is None else str(value)).replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")
    run = max((len(m) for m in re.findall(r"`+", body)), default=0)
    fence = "`" * max(3, run + 1)
    return f"{fence}\n{body}\n{fence}"


def link(url: Any) -> str:
    u = "" if url is None else str(url)
    return f"<{u}>" if _SAFE_LINK.match(u) else code(u)


def _evidence(v: dict) -> tuple[list[str], list[str]]:
    """(blocks for file evidence with snippets, one-line evidence items)."""
    blocks, lines = [], []
    for e in v["evidence"]:
        kind = e.get("kind")
        if kind == "file":
            where = code(f"{e.get('file')}:{e.get('line')}")
            if e.get("snippet"):
                blocks.append(f"{where}\n\n{fenced(e.get('snippet'))}")
            else:
                lines.append(where)
        elif kind == "api":
            s = code(e.get("endpoint"))
            if e.get("field") is not None:
                s += f" {code(e.get('field'))}"
            if e.get("value") is not None:
                s += f" = {code(e.get('value'))}"
            lines.append(s)
        else:
            lines.append(text(e.get("text")))
    return blocks, lines


def _incidents(v: dict) -> str:
    out = []
    for i in v["incidents"]:
        if i["url"] and i["url"] != i["ref"]:
            out.append(f"{text(i['ref'])} {link(i['url'])}")
        else:
            out.append(link(i["url"]) if i["url"] else text(i["ref"]))
    return "; ".join(out)


def _details(d: dict | None) -> list[str]:
    if not d:
        return []
    cols = d.get("columns") if isinstance(d.get("columns"), list) else (
        list(d["rows"][0]) if d["rows"] and isinstance(d["rows"][0], dict) else [])
    rows = []
    for row in d["rows"]:
        if isinstance(row, dict):
            rows.append("  - " + "; ".join(f"{text(c)}: {text(row.get(c, ''))}" for c in cols if c != "url"))
    note = [f"  - {text(d.get('note'))}"] if d.get("note") else []
    return ["- Details:"] + rows + note if rows or note else []


def _meta(v: dict) -> str:
    review = f"review {text(v['review']['status'])}" + (f" (was {text(v['review']['was'])})" if v["review"]["was"] else "")
    return " · ".join(x for x in (code(v["id"]), code(v["rule"]), text(v["class"]), f"source {text(v['source'])}",
                                  f"target {code(v['target'])}" if v["target"] else "",
                                  f"confidence {text(v['confidence'])}", review) if x)


def _item(n: str, v: dict) -> str:
    """One finding, complete: compactness removes repetition, never evidence or the review decision."""
    parts = [f"### {n}. {text(v['title'])}", "", _meta(v)]
    blocks, lines = _evidence(v)
    said = {text(v["missing"]), text(v["review"]["reason"])} - {""}
    lines = [x for x in lines if x not in said]  # a note that repeats the missing reason is said once
    for b in blocks:
        parts += ["", b]
    bullets = []
    if v["missing"]:
        bullets.append(f"- Missing: {text(v['missing'])}")
    if v["review"]["reason"]:
        bullets.append(f"- Review: {text(v['review']['reason'])}")
    if lines:
        bullets.append("- Evidence:")
        bullets += [f"  - {x}" for x in lines]
    inc = _incidents(v)
    bullets.append(f"- Why: {text(v['why'])}" + (f" Incidents: {inc}" if inc else ""))
    bullets.append(f"- Fix: {text(v['fix'])}")
    docs = [link(d["url"]) for d in v["docs"] if d["url"]]
    if docs:
        bullets.append("- Docs: " + " ".join(docs))
    bullets += _details(v["details"])
    if v["affected"]:
        bullets.append(f"- Checks waiting on this coverage (unknown, not passed) ({len(v['affected'])}):")
        for a in v["affected"]:
            obs = "; ".join(text(x.get("text")) for x in a["evidence"] if x.get("kind") == "note")
            bullets.append(f"  - {code(a['id'])} {code(a['rule'])} {text(a['title'])}" + (f": {obs}" if obs else ""))
    return "\n".join(parts + [""] + bullets)


def _layers(doc: dict) -> str:
    opts = doc.get("options") or {}
    info = doc.get("provider_info") if isinstance(doc.get("provider_info"), dict) else {}
    layers = ["config"]
    auth = [f"{text(n)}: {text((pi or {}).get('account', {}).get('auth'))}" for n, pi in info.items()
            if isinstance(pi, dict) and isinstance(pi.get("account"), dict) and pi["account"].get("auth")]
    if opts.get("account"):
        layers.append("account" + (" (" + "; ".join(auth) + ")" if auth else "")
                      + (", account-wide" if opts.get("account_wide") else ""))
    else:
        layers.append("account not run")
    return ", ".join(layers)


def render_md(doc: dict[str, Any], html_name: str = "report.html") -> str:
    p = view.project(doc)
    c = counts(doc)
    needs = p["needs_review"]
    tool = doc.get("tool") or {}
    audit = p["audit"]
    out = [
        "# Cloudflare bill-risk handoff",
        "",
        f"**Audit status: {text(audit['label'])}.** {text(audit['meaning'])}",
        "",
        "Fix the must-fix alarms first, then the suggestions. Each item cites the evidence and the fix; "
        "unknowns say what to grant or check. The audit was read-only and changed nothing. "
        "Ids (`f001`...) are the finding ids in findings.json.",
        "",
        f"- Project: {code(doc.get('project'))}",
        f"- Scanned: {text(doc.get('generated_at'))} by {text(tool.get('name'))} {text(tool.get('version'))}",
        f"- Providers: {text(', '.join(str(x) for x in doc.get('providers') or []))}",
        f"- Layers: {_layers(doc)}",
        f"- Counts: {c['alarm']} alarms (must fix), {c['suggestion']} suggestions, {c['unknown']} unknown, "
        f"{c['pass']} passed, {c['dismissed']} dismissed",
        f"- Audit status: {text(audit['label'])}",
        f"- Needs review: {needs} finding(s) still marked needs-review",
        f"- Human report: {code(html_name)} (same folder)",
    ]
    if audit["summary"].strip():
        # one bullet per line, inert like all agent text (a bare line could otherwise form a setext heading)
        out += ["", "## Review summary", ""]
        out += [f"- {text(line)}" for line in audit["summary"].splitlines() if line.strip()]
    for sev, heading, prefix in (("alarm", "Must fix (alarms)", "A"), ("suggestion", "Suggestions", "S"),
                                 ("unknown", "Unknowns", "U")):
        items = p["by_severity"][sev]
        out += ["", f"## {heading} ({len(items)})"]
        if not items:
            out += ["", "None."]
        for i, v in enumerate(items, 1):
            out += ["", _item(f"{prefix}{i}", v)]
        if sev == "unknown" and items:
            info = doc.get("provider_info") if isinstance(doc.get("provider_info"), dict) else {}
            for name, pi in info.items():
                if name in p["token_providers"] and isinstance(pi, dict) and pi.get("token_instructions"):
                    out += ["", f"Read-only token ({text(name)}): {text(pi.get('token_instructions'))}"]

    dismissed = p["dismissed"]
    out += ["", f"## Dismissed by review ({len(dismissed)})", ""]
    out += [f"- {code(v['id'])} {code(v['rule'])} {text(v['title'])}"
            + (f" ({text(v['target'])})" if v["target"] else "")
            + f": false-positive (was {text(v['severity'])}): {text(v['review']['reason'])}"
            for v in dismissed] or ["None."]
    for severity, heading, prefix in (("pass", "Passed", "P"), ("not-applicable", "Not applicable", "NA")):
        items = p["by_severity"][severity]
        if severity == "not-applicable" and not items:
            continue
        out += ["", f"## {heading} ({len(items)})", ""]
        out += [_item(f"{prefix}{i}", v) for i, v in enumerate(items, 1)] or ["None."]

    inv = p["inventory"]
    out += ["", f"## Paid-work inventory ({len(inv)})", "", text(view.INVENTORY_NOTE), ""]
    for r in inv:
        line = f"- {code(r['entry'])}" + (f" ({text(r['worker'])})" if r["worker"] else "")
        line += (f" at {code(r['where'])}" if r["where"] else "")
        line += f": paid work {text(', '.join(r['paid_work']) or 'not recorded')}"
        if r["signals"]:
            line += f"; scanner guard signals {text(r['signals'])}"
        line += f"; controls: {text(r['review']) or 'not recorded'}"
        out.append(line)
    if not inv:
        out.append("None recorded by the review. An empty inventory is not a pass." if audit["status"] == "reviewed"
                   else "Empty: the scan does not trace application source; the reviewing agent fills this. "
                        "An empty inventory is not a pass.")
    for sc in p["source_context"]:
        out += ["", f"## Source context ({text(sc['provider'])})", "", text(view.SOURCE_NOTE), "",
                f"- Source identity: {text(sc['identity'])}"]
        if sc["configs"]:
            out.append("- Configs: " + ", ".join(code(c) for c in sc["configs"]))
        for x in sc["entries"]:
            out.append(f"- {text(x['worker'])}" + (f" env {text(x['env'])}" if x["env"] else "")
                       + f": {text(x['kind'])} {code(x['path'])} (exists: {text(x['exists'])})")
    return "\n".join(out) + "\n"
