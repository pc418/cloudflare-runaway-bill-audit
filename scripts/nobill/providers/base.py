"""The interface every provider module implements.

A provider module exposes:
    NAME: str                      short id used on the command line
    TITLE: str                     human title for the report
    detect(root: Path) -> bool     does this project use the provider?
    scan(root: Path, opts: ScanOptions) -> ProviderResult
and optionally
    detect_unread(root: Path) -> list[str]
                                   paths detect() could not read ("relpath (reason)"); named in the
                                   refusal when no provider is detected
    local_secrets() -> list[Secret]  credential values resolvable on this machine; scan and
                                   render redact them from every output, account layer or not
and is listed in nobill/registry.py. The core never imports a provider directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..findings import Finding


@dataclass
class ScanOptions:
    account: bool = False          # run the live, read-only account layer
    account_wide: bool = False     # widen the account layer from project resources to the whole account
    account_id: str | None = None


@dataclass
class ProviderResult:
    findings: list[Finding]
    inventory: list[dict[str, Any]] = field(default_factory=list)
    scope_requirements: list[dict[str, Any]] = field(default_factory=list)
    info: dict[str, Any] = field(default_factory=dict)
    incident_ids: set[str] = field(default_factory=set)
    redact: list[Any] = field(default_factory=list)  # Secret objects whose values must never reach any output
