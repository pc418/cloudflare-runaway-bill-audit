"""Render a findings document to one self-contained HTML file.

Inline CSS only, no scripts, no external requests (links are navigation only).
Every value that came from the project, the API or the agent is escaped; only
http(s) URLs become links.
"""

from __future__ import annotations

import html
import urllib.parse
from typing import Any

from . import view
from .findings import counts, is_safe_url

SECTIONS = [
    ("alarm", "Alarms", "Must fix: an unbounded multiplier with incident evidence."),
    ("suggestion", "Suggestions", "Better fix: linear cost, defence in depth, or weaker evidence. Each has a best-practice fix."),
    ("unknown", "Unknowns", "Could not be checked. Each names the permission to grant or the reason."),
    ("pass", "Passed checks", "Each covers only the setting, resource or path it names; none certifies other code "
                              "or total spend (heuristic passes are not proof)."),
    ("not-applicable", "Not applicable", "Checks ruled out for this project (for example, no Worker code is deployed)."),
]

CSS = """
:root{--bg:#fbfaf8;--fg:#1d1d1f;--muted:#5f6368;--card:#ffffff;--line:#e3e1dc;--code:#f3f1ec;
--alarm:#b42318;--alarm-bg:#fdecea;--sugg:#9a6700;--sugg-bg:#fff6dd;--unk:#4a5ab3;--unk-bg:#eef0fb;
--pass:#1a7f37;--pass-bg:#e7f5ea;--dis:#6e6e73;--dis-bg:#efefef;--link:#0b57d0}
@media (prefers-color-scheme: dark){:root{--bg:#141416;--fg:#ececf0;--muted:#a1a1aa;--card:#1d1d21;--line:#33333a;
--code:#26262c;--alarm:#ff8a80;--alarm-bg:#3a1714;--sugg:#f5c451;--sugg-bg:#332a10;--unk:#a5b1ff;--unk-bg:#1f2340;
--pass:#7ee09a;--pass-bg:#15301d;--dis:#a1a1aa;--dis-bg:#2a2a2e;--link:#8ab4f8}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:1.6rem;margin:0 0 4px}h2{font-size:1.25rem;margin:36px 0 4px;padding-top:8px;border-top:1px solid var(--line)}
h3{font-size:1.02rem;margin:0}p{margin:6px 0}a{color:var(--link);overflow-wrap:anywhere}
.muted{color:var(--muted)}.small{font-size:.86rem}
.meta{display:grid;grid-template-columns:max-content 1fr;gap:2px 12px;font-size:.88rem;color:var(--muted);margin:10px 0}
.meta dd{margin:0;color:var(--fg);overflow-wrap:anywhere}.meta dt{font-weight:600}
.counts{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:16px 0}
.count{border-radius:10px;padding:12px 14px;border:1px solid var(--line);background:var(--card)}
.count b{display:block;font-size:1.7rem;line-height:1.1}.count span{font-size:.85rem;color:var(--muted)}
.count.alarm b{color:var(--alarm)}.count.suggestion b{color:var(--sugg)}.count.unknown b{color:var(--unk)}.count.pass b{color:var(--pass)}
.card{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--line);border-radius:10px;padding:14px 16px;margin:12px 0}
.card.alarm{border-left-color:var(--alarm)}.card.suggestion{border-left-color:var(--sugg)}.card.unknown{border-left-color:var(--unk)}
.card.pass{border-left-color:var(--pass)}.card.dismissed{border-left-color:var(--dis);opacity:.85}
.tags{display:flex;flex-wrap:wrap;gap:6px;margin:6px 0 8px}
.tag{font-size:.75rem;padding:1px 8px;border-radius:999px;background:var(--code);color:var(--muted);white-space:nowrap}
.tag.alarm{background:var(--alarm-bg);color:var(--alarm)}.tag.suggestion{background:var(--sugg-bg);color:var(--sugg)}
.tag.unknown{background:var(--unk-bg);color:var(--unk)}.tag.pass{background:var(--pass-bg);color:var(--pass)}
.tag.review{background:var(--dis-bg);color:var(--fg)}
.label{font-weight:600;font-size:.82rem;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);margin-top:10px}
ul.ev{margin:4px 0;padding-left:18px}ul.ev li{margin:3px 0}
code,.code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.84rem;background:var(--code);
border-radius:4px;padding:1px 5px;white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word}
.tablewrap{overflow-x:auto;margin:8px 0;border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:.84rem;background:var(--card)}
th,td{text-align:left;vertical-align:top;padding:6px 8px;border-bottom:1px solid var(--line)}
th{background:var(--code);font-weight:600}td{overflow-wrap:anywhere}
.passlist li{margin:2px 0}details summary{cursor:pointer;color:var(--muted);margin:6px 0}
.missing{background:var(--unk-bg);color:var(--fg);border-radius:6px;padding:6px 10px;margin:6px 0}
.callout{background:var(--code);border-radius:8px;padding:10px 14px;margin:10px 0;font-size:.9rem}
.status{border-radius:10px;padding:12px 16px;margin:14px 0;border:2px solid var(--unk);background:var(--unk-bg)}
.status.unreviewed{border-color:var(--alarm);background:var(--alarm-bg)}.status.reviewed{border-color:var(--pass);background:var(--pass-bg)}
.status b{font-size:1.05rem}.summary{white-space:pre-wrap;overflow-wrap:anywhere}
"""


def e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def link(url: Any, text: Any) -> str:
    if is_safe_url(url):
        return f'<a href="{e(url)}" rel="noopener noreferrer">{e(text)}</a>'
    return e(text)


def _evidence(ev: list[dict]) -> str:
    items = []
    for x in ev:
        kind = x.get("kind")
        if kind == "file":
            loc = f"{x.get('file')}:{x.get('line')}"
            snip = x.get("snippet")
            items.append(f"<li><code>{e(loc)}</code>" + (f" <span class=\"code\">{e(snip)}</span>" if snip else "") + "</li>")
        elif kind == "api":
            parts = f"<code>{e(x.get('endpoint'))}</code>"
            if x.get("field") is not None:
                parts += f" <span class=\"muted\">{e(x.get('field'))}</span>"
            if x.get("value") is not None:
                parts += f" = <span class=\"code\">{e(x.get('value'))}</span>"
            items.append(f"<li>{parts}</li>")
        else:
            items.append(f"<li>{e(x.get('text'))}</li>")
    return '<ul class="ev">' + "".join(items) + "</ul>" if items else ""


def _details(d: Any) -> str:
    if not isinstance(d, dict) or not isinstance(d.get("rows"), list):
        return ""
    cols = d.get("columns") if isinstance(d.get("columns"), list) else (list(d["rows"][0]) if d["rows"] and isinstance(d["rows"][0], dict) else [])
    head = "".join(f"<th>{e(c)}</th>" for c in cols if c != "url")
    body = []
    for row in d["rows"]:
        if not isinstance(row, dict):
            continue
        cells = []
        for c in cols:
            if c == "url":
                continue
            val = row.get(c, "")
            if c == "bills_by" and row.get("url"):
                cells.append(f"<td>{e(val)} {link(row.get('url'), 'pricing')}</td>")
            else:
                cells.append(f"<td>{e(val)}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    note = f"<p class=\"small muted\">{e(d.get('note'))}</p>" if d.get("note") else ""
    return f'<div class="tablewrap"><table><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table></div>{note}'


def _incident_links(items: list[dict]) -> str:
    out = []
    for i in items:
        label = f"{i['ref']}: {i['title']}" if i["title"] is not None else i["ref"]
        out.append(link(i["url"], label) if i["url"] else e(label))
    return "<ul class=\"ev\">" + "".join(f"<li>{x}</li>" for x in out) + "</ul>" if out else ""


def _card(v: dict, dismissed: bool = False) -> str:
    sev, review = v["severity"], v["review"]
    tags = [f'<span class="tag {e(sev)}">{e(sev)}</span>', f'<span class="tag">{e(v["class"])}</span>',
            f'<span class="tag">{e(v["rule"])}</span>', f'<span class="tag">confidence: {e(v["confidence"])}</span>',
            f'<span class="tag">source: {e(v["source"])}</span>',
            f'<span class="tag review">review: {e(review["status"])}</span>']
    if review["was"]:
        tags.append(f'<span class="tag review">was {e(review["was"])}</span>')
    parts = [f'<div class="card {"dismissed" if dismissed else e(sev)}">',
             f"<h3>{e(v['title'])}</h3>",
             f'<div class="tags">{"".join(tags)}</div>']
    ident = f'<span class="muted">({e(v["id"])}, {e(v["provider"])})</span>'
    parts.append(f'<p class="small muted">Target: {e(v["target"])} {ident}</p>' if v["target"]
                 else f'<p class="small muted">{ident}</p>')
    if review["reason"]:
        parts.append(f'<p class="small"><b>Review:</b> {e(review["reason"])}</p>')
    if v["missing"]:
        parts.append(f'<div class="missing"><b>Missing:</b> {e(v["missing"])}</div>')
    parts.append('<div class="label">Evidence</div>' + _evidence(v["evidence"]))
    parts.append(f'<div class="label">Why</div><p>{e(v["why"])}</p>' + _incident_links(v["incidents"]))
    docs = " &middot; ".join(link(d["url"], d["title"]) for d in v["docs"])
    parts.append(f'<div class="label">Fix</div><p>{e(v["fix"])}</p>' + (f'<p class="small">Docs: {docs}</p>' if docs else ""))
    parts.append(_details(v["details"]))
    if v["affected"]:
        items = "".join(f"<li><code>{e(a['id'])}</code> <span class=\"tag\">{e(a['rule'])}</span> {e(a['title'])}"
                        + "".join(f"<br><span class=\"small muted\">{e(x.get('text'))}</span>" for x in a["evidence"]
                                  if x.get("kind") == "note") + "</li>" for a in v["affected"])
        parts.append(f'<div class="label">Checks waiting on this coverage ({len(v["affected"])})</div>'
                     f'<p class="small muted">Each is unknown, not passed, until the blockers above are resolved.</p>'
                     f'<ul class="ev">{items}</ul>')
    parts.append("</div>")
    return "".join(parts)


def _pass_item(v: dict) -> str:
    # Compact by default, but never discard the caveats/evidence behind a scoped pass.
    return (f'<li><details><summary>{e(v["id"])} · {e(v["rule"])} · {e(v["title"])}</summary>'
            + _card(v) + "</details></li>")


def render(doc: dict[str, Any], md_name: str = "report.md") -> str:
    findings = doc.get("findings") or []
    p = view.project(doc)
    incidents = p["incidents"]
    c = counts(doc)
    needs = p["needs_review"]
    dismissed = p["dismissed"]
    info = doc.get("provider_info") if isinstance(doc.get("provider_info"), dict) else {}
    out = ["<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
           '<meta name="viewport" content="width=device-width,initial-scale=1">',
           '<meta name="color-scheme" content="light dark">',
           "<title>Cloudflare Bill Risk</title>", f"<style>{CSS}</style></head><body><main>"]
    out.append("<h1>Cloudflare bill-risk report</h1>")
    out.append('<p class="muted">Configuration and account facts collected by the scan, and the application audit '
               "recorded by the reviewing agent, read against real runaway-bill incidents. "
               "Alarms are must-fix; suggestions are better-fix.</p>")
    audit = p["audit"]
    out.append(f'<div class="status {e(audit["status"] or "not-recorded")}" id="audit-status">'
               f'<b>Audit status: {e(audit["label"])}</b><p>{e(audit["meaning"])}</p></div>')
    acct = []
    for name, pi in info.items():
        a = (pi or {}).get("account") or {}
        if a.get("auth"):
            acct.append(f"{name}: {a.get('auth')}" + (f" (account {a['account_id']})" if a.get("account_id") else ""))
    meta = [("Project", doc.get("project")), ("Generated", doc.get("generated_at")),
            ("Tool", f"{(doc.get('tool') or {}).get('name')} {(doc.get('tool') or {}).get('version')}"),
            ("Providers", ", ".join(doc.get("providers") or [])),
            ("Account layer", "; ".join(acct) or "not run"),
            ("Audit status", audit["label"]),
            ("Needs review", f"{needs} finding(s) still marked needs-review")]
    out.append('<dl class="meta">' + "".join(f"<dt>{e(k)}</dt><dd>{e(v)}</dd>" for k, v in meta) + "</dl>")
    if audit["summary"].strip():
        out.append('<h2 id="summary">Review summary</h2><p class="muted small">Written by the reviewing agent: '
                   "inspected scope, mechanism dispositions and remaining gaps.</p>"
                   f'<div class="callout summary">{e(audit["summary"].strip())}</div>')
    out.append(f'<p class="small">Agent handoff: <a href="{e(urllib.parse.quote(md_name))}">{e(md_name)}</a> '
               "(same folder): the same findings as compact markdown, action first, to give to a coding agent "
               "that will fix them.</p>")
    if needs:
        out.append('<div class="callout">This report still has findings marked needs-review. An agent (or you) should '
                   "check the cited evidence against the code and configuration, mark each confirmed or false-positive, "
                   "and re-render.</div>")
    out.append('<div class="counts">' + "".join(
        f'<div class="count {k}"><b>{c[k]}</b><span>{lbl}</span></div>'
        for k, lbl in (("alarm", "alarms (must fix)"), ("suggestion", "suggestions"), ("unknown", "unknown (grant / check)"),
                       ("pass", "passed"), ("dismissed", "dismissed by review"))) + "</div>")

    for sev, title, blurb in SECTIONS:
        items = p["by_severity"][sev]
        out.append(f'<h2 id="{sev}">{e(title)} ({len(items)})</h2><p class="muted small">{e(blurb)}</p>')
        if not items:
            out.append('<p class="muted">None.</p>')
        elif sev in ("pass", "not-applicable"):
            out.append('<ul class="passlist">' + "".join(_pass_item(v) for v in items) + "</ul>")
        else:
            out.extend(_card(v) for v in items)

    if dismissed:
        out.append(f'<h2 id="dismissed">Dismissed by review ({len(dismissed)})</h2>'
                   '<p class="muted small">Findings the reviewer read and marked false-positive, with the reason.</p>'
                   "<details><summary>Show dismissed findings</summary>" + "".join(_card(v, True) for v in dismissed) + "</details>")

    scope = doc.get("scope_requirements") or []
    out.append('<h2 id="scope">Scope requirements</h2><p class="muted small">Each live check, the token permission it needs, '
               "and whether this run's credential had it. All checks are read-only.</p>")
    if scope:
        rows = "".join(
            f"<tr><td>{e(r.get('provider'))}</td><td>{e(r.get('check'))}</td><td><code>{e(r.get('endpoint'))}</code></td>"
            f"<td>{e(r.get('permission'))}</td><td>{e(r.get('status'))}</td><td>{e(r.get('detail'))}</td></tr>"
            for r in scope if isinstance(r, dict))
        out.append('<div class="tablewrap"><table><thead><tr><th>Provider</th><th>Check</th><th>Endpoint</th><th>Permission</th>'
                   f"<th>Status</th><th>Detail</th></tr></thead><tbody>{rows}</tbody></table></div>")
    for name, pi in info.items():
        pi = pi or {}
        if name in p["token_providers"] and pi.get("token_instructions"):
            out.append(f'<div class="callout"><b>{e(name)}: read-only token.</b> {e(pi.get("token_instructions"))}'
                       + (f"<br><span class=\"muted\">{e(pi.get('oauth_note'))}</span>" if pi.get("oauth_note") else "") + "</div>")
        probs = (pi.get("account") or {}).get("auth_problems")
        if probs:
            out.append('<p class="small muted">Credential notes: ' + e("; ".join(probs)) + "</p>")

    inv = p["inventory"]
    out.append(f'<h2 id="inventory">Paid-work inventory ({len(inv)})</h2><p class="muted small">{e(view.INVENTORY_NOTE)}</p>')
    if inv:
        legacy = any(r["signals"] for r in inv)  # guard signals only exist in documents of the retired scanner
        rows = []
        for r in inv:
            rows.append(f"<tr><td><code>{e(r['entry'])}</code></td><td>{e(r['worker'])}</td><td><code>{e(r['where'])}</code></td>"
                        f"<td>{e(', '.join(r['paid_work']))}</td>" + (f"<td>{e(r['signals'])}</td>" if legacy else "")
                        + f"<td>{e(r['review'])}</td></tr>")
        out.append('<div class="tablewrap"><table><thead><tr><th>Trigger / route</th><th>Worker</th><th>Where</th>'
                   "<th>Paid work</th>" + ("<th>Guard signals (scanner)</th>" if legacy else "")
                   + f"<th>Controls / review</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>")
    elif audit["status"] == "reviewed":
        out.append('<p class="muted">No rows recorded by the review. An empty inventory is not a pass.</p>')
    else:
        out.append('<p class="muted">Empty: the scan does not trace application source; the reviewing agent fills this. '
                   "An empty inventory is not a pass.</p>")

    for sc in p["source_context"]:
        out.append(f'<h2 id="source">Source context ({e(sc["provider"])})</h2><p class="muted small">{e(view.SOURCE_NOTE)}</p>')
        out.append(f'<p class="small"><b>Source identity:</b> {e(sc["identity"])}</p>')
        if sc["configs"]:
            out.append('<p class="small"><b>Configs:</b> ' + ", ".join(f"<code>{e(c)}</code>" for c in sc["configs"]) + "</p>")
        if sc["entries"]:
            rows = "".join(f"<tr><td>{e(x['worker'])}</td><td>{e(x['env'])}</td><td>{e(x['kind'])}</td>"
                           f"<td><code>{e(x['path'])}</code></td><td>{e(x['exists'])}</td></tr>" for x in sc["entries"])
            out.append('<div class="tablewrap"><table><thead><tr><th>Worker</th><th>Env</th><th>Declared</th><th>Path</th>'
                       f"<th>Exists</th></tr></thead><tbody>{rows}</tbody></table></div>")

    lim = [x for pi in info.values() for x in ((pi or {}).get("limits") or [])]
    if lim:
        out.append('<h2 id="limits">What this audit cannot see</h2><ul class="ev">' + "".join(f"<li>{e(x)}</li>" for x in lim) + "</ul>")

    cited = []
    for f in findings:
        for ref in (f.get("why") or {}).get("incidents") or []:
            if ref not in cited:
                cited.append(ref)
    out.append('<h2 id="incidents">Incident references</h2><p class="muted small">Stories collected by '
               f'{link("https://serverlesshorrors.com/", "serverlesshorrors.com")}; amounts as the original sources state them.</p>')
    out.append(_incident_links([view.incident(r, incidents) for r in cited]) or '<p class="muted">None cited.</p>')
    out.append("</main></body></html>")
    return "\n".join(out)
