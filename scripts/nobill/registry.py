"""Cloudflare provider registry."""

from __future__ import annotations

import importlib
from types import ModuleType

PROVIDERS: dict[str, str] = {
    "cloudflare": "nobill.providers.cloudflare",
}


def load(name: str) -> ModuleType:
    if name not in PROVIDERS:
        raise KeyError(f"unknown provider '{name}' (known: {', '.join(sorted(PROVIDERS))})")
    mod = importlib.import_module(PROVIDERS[name])
    for attr in ("NAME", "TITLE", "detect", "scan"):
        if not hasattr(mod, attr):
            raise TypeError(f"provider module {PROVIDERS[name]} lacks '{attr}'")
    return mod
