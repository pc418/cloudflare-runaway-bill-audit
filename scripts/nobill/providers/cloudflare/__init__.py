"""Cloudflare provider: wrangler configuration facts, read-only live account checks, and the
source-location context the reviewing agent starts from.

There is no source analysis here (owner 2026-10-20, docs/261020-refactor-AGENT_LED_BILLING_AUDIT.md):
the agent reads and traces the application itself and fills the paid-work inventory.
"""

from __future__ import annotations

import os
from pathlib import Path

from ... import incidents as _incidents
from ..base import ProviderResult, ScanOptions
from . import account as _account
from . import auth as _auth
from .client import API_BASE
from .config_checks import check_config
from .context import source_context
from .wrangler import discover, load_project

NAME = "cloudflare"
TITLE = "Cloudflare (Workers, Durable Objects, Queues, R2, Containers/Sandbox, Browser Run, Images, AI)"
API_BASE_ENV = "NOBILL_CLOUDFLARE_API_BASE"  # test hook: only a local http server is accepted


def local_secrets() -> list:
    """Credential values resolvable on this machine (env, wrangler login), for output redaction."""
    return _auth.local_secrets()


def _detect(root: Path) -> tuple[bool, list[str]]:
    """(detected, paths detection could not read, each as "relpath (reason)")."""
    unlisted: list[tuple[str, str]] = []
    if discover(root, unlisted):
        return True, []
    unread = [f"{where} ({why})" for where, why in unlisted]
    pkg = root / "package.json"
    try:
        text = pkg.read_text(encoding="utf-8") if pkg.is_file() else ""
    except (OSError, UnicodeDecodeError) as exc:
        return False, unread + [f"package.json ({type(exc).__name__})"]
    return "wrangler" in text or "@cloudflare/" in text, unread


def detect(root: Path) -> bool:
    return _detect(root)[0]


def detect_unread(root: Path) -> list[str]:
    """Paths an undetected project could not be read at; a config may sit behind them."""
    found, unread = _detect(root)
    return [] if found else unread


def scan(root: Path, opts: ScanOptions) -> ProviderResult:
    project = load_project(root)
    findings = check_config(project)

    audit = _account.AccountAudit(
        project, _auth.Credential(None, "none", "account layer not run"), account_wide=opts.account_wide,
        account_id=opts.account_id, api_base=os.environ.get(API_BASE_ENV) or API_BASE)
    redact = []
    if opts.account:
        cred = _auth.resolve()
        audit.cred = cred
        if cred.token is not None:
            redact.append(cred.token)
        audit.run()
    else:
        audit.info["auth"] = "account layer not run"
        audit.not_run("account layer not run: re-run with --account (read-only GET requests plus one GraphQL "
                      "query) to check live settings")
    findings.extend(audit.findings)

    info = {
        "title": TITLE,
        "configs": [{"file": c.rel, "error": c.error} for c in project.configs],
        "workers": [w.label for w in project.workers],
        "source_context": source_context(project),
        "account": audit.info,
        "token_instructions": _account.TOKEN_INSTRUCTIONS,
        "token_permissions": _account.TOKEN_PERMISSIONS,
        "oauth_note": _account.OAUTH_NOTE,
        "limits": [
            "The scan reads configuration and, with --account, live account settings. It does not read or trace "
            "application source: routes, clients, background work, paid calls and their controls are established "
            "by the reviewing agent, and the paid-work inventory stays empty until it does.",
            "Configuration and account checks describe only the setting, resource and time they name: a declared "
            "binding or limit does not show which code paths use it, and no check bounds total spend.",
            "Notifications are not enforcement. Verify current product limits and notification timing against "
            "dated provider evidence; this audit does not establish an account-wide spending ceiling.",
            "The alert-policy API is not a complete inventory of billing-dashboard controls; check any remaining "
            "dashboard-only facts separately.",
            "Zone WAF / rate-limiting rules, bot settings, the Images Transformations 'Sources' setting and Durable "
            "Object storage analytics are not checked.",
        ],
    }
    return ProviderResult(findings=findings, inventory=[], scope_requirements=audit.track.rows(),
                          info=info, incident_ids=set(_incidents.INCIDENTS), redact=redact)
