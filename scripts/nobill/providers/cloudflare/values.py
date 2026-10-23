"""Value checks shared by config and live settings; omission is not JSON null."""

from __future__ import annotations

import json
import math
import sys
from typing import Any

MISSING = object()


def is_num(value: Any) -> bool:
    # math.isfinite coerces integers to double and raises on oversized integers.
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return -sys.float_info.max <= value <= sys.float_info.max
    return isinstance(value, float) and math.isfinite(value)


def is_int(value: Any) -> bool:
    return isinstance(value, int) and is_num(value)


def shown(value: Any) -> str:
    if value is MISSING:
        return "<absent>"
    # TOML dates/times are legitimate decoded values, but not legitimate settings here.
    # Leave clipping to the output layer, after credential redaction. Clipping here
    # can cut a credential in half so the subsequent exact-value scrub misses it.
    try:
        return json.dumps(value, default=str, ensure_ascii=True)
    except (ValueError, RecursionError):
        return f'"{type(value).__name__} value cannot be displayed completely"'


def sampling(obs: Any) -> tuple[bool, Any, list[str]]:
    """Validate every supplied flag/rate, including disabled and overridden rates."""
    if obs is MISSING:
        return False, MISSING, []
    if not isinstance(obs, dict):
        return False, MISSING, [f"observability is not a table ({shown(obs)})"]
    errors = []
    logs = obs.get("logs", {})
    if not isinstance(logs, dict):
        errors.append(f"observability.logs is not a table ({shown(logs)})")
        logs = {}
    for prefix, block in (("observability", obs), ("observability.logs", logs)):
        if "enabled" in block and not isinstance(block["enabled"], bool):
            errors.append(f"{prefix}.enabled is not a boolean ({shown(block['enabled'])})")
        if "head_sampling_rate" in block:
            rate = block["head_sampling_rate"]
            if not is_num(rate) or not 0 <= rate <= 1:
                errors.append(f"{prefix}.head_sampling_rate is not a number from 0 to 1 ({shown(rate)})")
    return (obs.get("enabled") is True or logs.get("enabled") is True,
            logs.get("head_sampling_rate", obs.get("head_sampling_rate", MISSING)), errors)
