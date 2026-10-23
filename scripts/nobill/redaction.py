"""One redaction pipeline for every output of scan and render.

The values come from the scan itself (the credential it used) and from every
provider's local_secrets() (env tokens, wrangler logins), so a credential pasted
into findings.json during review is caught at render time too. The document is
redacted string by string before it is rendered (so no escaping can hide a value
from the match) and each rendered text is redacted again.
"""

from __future__ import annotations

from typing import Any

from . import registry

MARK = "[REDACTED]"
MIN_LEN = 8  # shorter values are not usable credentials, and replacing them would garble the report


def secret_values(found: list | None = None) -> list[str]:
    raw: list[str] = []
    for s in found or []:
        raw.append(s.reveal() if hasattr(s, "reveal") else str(s))
    for name in registry.PROVIDERS:
        fn = getattr(registry.load(name), "local_secrets", None)
        if fn is not None:
            raw.extend(s.reveal() if hasattr(s, "reveal") else str(s) for s in fn())
    vals: set[str] = set()
    for v in raw:
        for piece in [v, v.strip(), *v.split()]:  # a malformed value may be printed in parts
            if len(piece) >= MIN_LEN:
                vals.add(piece)
    return sorted(vals, key=len, reverse=True)


def redact_text(text: str, values: list[str]) -> str:
    for v in values:
        text = text.replace(v, MARK)
    return text


def redact_doc(obj: Any, values: list[str]) -> Any:
    if not values:
        return obj
    if isinstance(obj, str):
        return redact_text(obj, values)
    if isinstance(obj, list):
        return [redact_doc(x, values) for x in obj]
    if isinstance(obj, dict):
        return {redact_text(k, values) if isinstance(k, str) else k: redact_doc(v, values) for k, v in obj.items()}
    return obj
