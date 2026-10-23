"""Command line: scan -> (agent review edits findings.json) -> render."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from . import incidents as _incidents
from . import registry
from . import view
from .findings import SchemaError, audit_status, build_document, counts, load_document, validate_document, clip_evidence
from .providers.base import ScanOptions
from .markdown import render_md
from .redaction import redact_doc, redact_text, secret_values
from .output import OutputError, check_destinations, destination, inside as _inside, write_all
from .render import render


def _temp_base() -> Path:
    """The default output base, chosen WITHOUT tempfile.gettempdir(): that function probes
    candidate directories by creating and writing a file in them, which could touch the
    project before containment is checked. Same order as tempfile: TMPDIR, TEMP, TMP, then
    the platform default."""
    for var in ("TMPDIR", "TEMP", "TMP"):
        val = os.environ.get(var)
        if val:
            return Path(val).expanduser().resolve()
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return (Path(local) / "Temp").resolve()
    return Path("/tmp").resolve()


def _print_paths(html: Path, md: Path, findings: Path) -> None:
    """The CLI's last lines: where the outputs are, labelled and aligned. Nothing follows them."""
    rows = [("report (html):", html), ("report (md, give to agents):", md), ("findings (edit, then render):", findings)]
    width = max(len(label) for label, _ in rows) + 1
    for label, path in rows:
        print(f"{label:<{width}}{destination(path)}")


def cmd_scan(args: argparse.Namespace) -> int:
    project = Path(args.project).expanduser().resolve()
    if not project.is_dir():
        print(f"error: {args.project} is not a directory", file=sys.stderr)
        return 2
    names = args.provider or [n for n in registry.PROVIDERS if registry.load(n).detect(project)]
    if not names:
        unread = [p for n in registry.PROVIDERS for p in getattr(registry.load(n), "detect_unread", lambda _: [])(project)]
        if unread:
            print("error: no wrangler config or Cloudflare dependency found, but these paths could not be read: "
                  f"{', '.join(unread)}; this may be a Cloudflare project whose config could not be read; "
                  "fix the permissions or pass --provider cloudflare to scan anyway", file=sys.stderr)
        else:
            print("error: not a Cloudflare project (no wrangler config or Cloudflare dependency found); "
                  "pass --provider cloudflare to scan anyway", file=sys.stderr)
        return 2
    if args.out:
        out = Path(args.out).expanduser().resolve()
        if _inside(out, project):
            print("error: --out must be outside the scanned project (the scanner never writes into it)", file=sys.stderr)
            return 2
        out.mkdir(parents=True, exist_ok=True)
    else:
        base = _temp_base()
        if _inside(base, project):  # decided before anything is created or probed
            print(f"error: the temp directory {base} is inside the scanned project; pass --out <dir> outside it",
                  file=sys.stderr)
            return 2
        try:
            out = Path(tempfile.mkdtemp(prefix="nobill-report-", dir=base)).resolve()
        except OSError as exc:
            print(f"error: cannot create a report directory under {base} ({type(exc).__name__}); pass --out <dir>",
                  file=sys.stderr)
            return 2
        if _inside(out, project):  # belt and braces: never write reports into the project
            out.rmdir()
            print("error: the report directory would be inside the scanned project; pass --out <dir> outside it",
                  file=sys.stderr)
            return 2
    opts = ScanOptions(account=args.account or args.account_wide, account_wide=args.account_wide, account_id=args.account_id)
    findings, inventory, scope, info, inc_ids, secrets = [], [], [], {}, set(), []
    for name in names:
        mod = registry.load(name)
        res = mod.scan(project, opts)
        findings.extend(res.findings)
        inventory.extend(res.inventory)
        scope.extend(res.scope_requirements)
        info[name] = res.info
        inc_ids |= res.incident_ids
        secrets.extend(res.redact)
    cited = {i for f in findings for i in f.incidents}
    doc = build_document(project=str(project), providers=names,
                         options={"account": opts.account, "account_wide": opts.account_wide},
                         findings=findings, scope_requirements=scope, provider_info=info,
                         inventory=inventory, incidents=_incidents.subset(cited | inc_ids))
    problems = validate_document(doc)
    if problems:  # a scanner bug: fail loudly rather than write a misleading report
        print("internal error: scanner produced an invalid document:\n  " + "\n  ".join(problems), file=sys.stderr)
        return 3
    try:
        f_out, h_out, m_out = check_destinations([out / "findings.json", out / "report.html", out / "report.md"], project)
    except OutputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    values = secret_values(secrets)
    doc = clip_evidence(redact_doc(doc, values))  # redact first: a clipped credential prefix would survive
    try:
        write_all([(f_out, redact_text(json.dumps(doc, indent=2, ensure_ascii=False), values) + "\n"),
                   (h_out, redact_text(render(doc), values)),
                   (m_out, redact_text(render_md(doc), values))])
    except OutputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    c = counts(doc)
    needs = sum(1 for f in doc["findings"] if f["review"]["status"] == "needs-review")
    print(f"alarms {c['alarm']}, suggestions {c['suggestion']}, unknown {c['unknown']}, passed {c['pass']}; "
          f"{needs} scan finding(s) marked needs-review; audit status: {view.AUDIT[audit_status(doc)][0]} "
          "(configuration and account facts only: the agent investigates the application source)")
    _print_paths(out / "report.html", out / "report.md", out / "findings.json")
    return 0


def cmd_render(args: argparse.Namespace) -> int:
    src = Path(args.findings).expanduser().resolve()
    try:
        doc = load_document(src)
    except SchemaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    out = destination(Path(args.out)) if args.out else src.with_name("report.html")
    if out.suffix.casefold() == ".md":
        print("error: --out must name the HTML file, not a .md file (in any case): the same file on a "
              "case-insensitive file system (report.md is written next to it)", file=sys.stderr)
        return 2
    md_out = out.with_suffix(".md")
    project = doc.get("project")
    if not (isinstance(project, str) and Path(project).is_absolute()):
        print("error: findings.json has no absolute 'project' path, so the outputs cannot be kept outside it",
              file=sys.stderr)
        return 2
    try:
        out, md_out = check_destinations([out, md_out], Path(project).resolve(), inputs=[src])
        values = secret_values()  # review edits can paste a credential the scan never saw
        doc = clip_evidence(redact_doc(doc, values))  # redact first: a clipped credential prefix would survive
        write_all([(out, redact_text(render(doc, md_name=md_out.name), values)),
                   (md_out, redact_text(render_md(doc, html_name=out.name), values))])
    except OutputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    c = counts(doc)
    print(f"alarms {c['alarm']}, suggestions {c['suggestion']}, unknown {c['unknown']}, passed {c['pass']}, "
          f"dismissed {c['dismissed']}; audit status: {view.AUDIT[audit_status(doc)][0]}")
    _print_paths(out, md_out, src)
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    try:
        load_document(Path(args.findings).expanduser().resolve())
    except SchemaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print("ok")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="audit.py", description="Audit a Cloudflare project for runaway-bill mistakes.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="collect configuration / account facts (read-only) and write an unreviewed "
                       "findings.json + reports for the agent's audit")
    s.add_argument("project", help="project directory to scan (never written to)")
    s.add_argument("--out", help="output directory (default: a new directory under the system temp dir)")
    s.add_argument("--provider", action="append", choices=sorted(registry.PROVIDERS),
                   help="provider to run (repeatable; default: every provider detected in the project)")
    s.add_argument("--account", action="store_true",
                   help="also run read-only live account checks (Cloudflare: CLOUDFLARE_API_TOKEN, else the wrangler login)")
    s.add_argument("--account-wide", action="store_true",
                   help="account checks cover every Worker / bucket in the account, not just the project's (implies --account)")
    s.add_argument("--account-id", help="account id when the credential can read several accounts")
    s.set_defaults(func=cmd_scan)
    r = sub.add_parser("render", help="render findings.json (after agent review) to HTML")
    r.add_argument("findings")
    r.add_argument("--out", help="output HTML path (default: report.html next to the findings file)")
    r.set_defaults(func=cmd_render)
    v = sub.add_parser("validate", help="check findings.json against the schema")
    v.add_argument("findings")
    v.set_defaults(func=cmd_validate)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
