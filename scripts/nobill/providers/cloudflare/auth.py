"""Credential resolution for the read-only account layer.

Order: CLOUDFLARE_API_TOKEN, then wrangler's OAuth token from its config file.
The token value lives only inside `Secret`; its repr/str are redacted, and it
is only unwrapped when the HTTP client builds the Authorization header. Only
the `oauth_token` and `expiration_time` keys of the wrangler file are used;
the file is never printed, logged or copied. `local_secrets()` also reads the
credential values (env token or key, the file's oauth and refresh tokens, valid or
not) solely so they can be redacted from every output.
"""

from __future__ import annotations

import datetime as _dt
import os
import platform
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


class Secret:
    __slots__ = ("_value",)

    def __init__(self, value: str):
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret('[REDACTED]')"

    __str__ = __repr__

    def __reduce__(self):  # refuse pickling/copying into other stores
        raise TypeError("Secret cannot be serialized")


_HEADER_SAFE = re.compile(r"[\x21-\x7e]+")
MALFORMED = "contains characters that are not valid in an HTTP header (value not shown)"


def header_safe(value: str) -> bool:
    """A bearer credential must be visible ASCII with no spaces or line breaks; anything else
    could split the Authorization header, and urllib would echo it in its exception."""
    return bool(_HEADER_SAFE.fullmatch(value))


@dataclass
class Credential:
    token: Secret | None
    kind: str            # "api-token" | "wrangler-oauth" | "none"
    source: str          # human description, never the value
    problems: list[str] = field(default_factory=list)


def _home() -> Path:
    return Path(os.environ.get("HOME") or Path.home())


def display_path(p: Path) -> str:
    home = str(_home())
    s = str(p)
    return "~" + s[len(home):] if home and s.startswith(home + os.sep) else s


def _xdg_config_dir() -> Path:
    env = os.environ.get("XDG_CONFIG_HOME")
    system = platform.system()
    if env:
        return Path(env)
    if system == "Darwin":
        return _home() / "Library" / "Preferences"
    if system == "Windows":
        appdata = os.environ.get("APPDATA") or str(_home() / "AppData" / "Roaming")
        return Path(appdata) / "xdg.config"
    return _home() / ".config"


def wrangler_config_candidates() -> list[Path]:
    """Auth files in wrangler's own order: the legacy ~/.wrangler dir wins when it
    exists, else the XDG config dir (~/Library/Preferences/.wrangler on macOS).
    Both are returned (wrangler's choice first) so an expired file can fall back."""
    env = os.environ.get("CLOUDFLARE_API_ENVIRONMENT", "production")
    base = "default" if env == "production" else env
    legacy = _home() / ".wrangler"
    xdg = _xdg_config_dir() / ".wrangler"
    dirs = [legacy, xdg] if legacy.is_dir() else [xdg, legacy]
    return [d / "config" / f"{base}.toml" for d in dirs]


def _parse_expiry(value) -> _dt.datetime | None:
    if isinstance(value, _dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=_dt.timezone.utc)
    if isinstance(value, str):
        try:
            d = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            return d if d.tzinfo else d.replace(tzinfo=_dt.timezone.utc)
        except ValueError:
            return None
    return None


def resolve(now: _dt.datetime | None = None) -> Credential:
    now = now or _dt.datetime.now(_dt.timezone.utc)
    env_token = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    if env_token:
        if not header_safe(env_token):
            return Credential(None, "none", "CLOUDFLARE_API_TOKEN is set but malformed",
                              [f"CLOUDFLARE_API_TOKEN {MALFORMED}"])
        return Credential(Secret(env_token), "api-token", "CLOUDFLARE_API_TOKEN environment variable")
    problems: list[str] = []
    fallback: tuple[Path, Secret] | None = None
    for path in wrangler_config_candidates():
        if not path.is_file():
            enc = path.with_suffix(".enc")
            if enc.is_file():
                problems.append(f"{display_path(enc)}: wrangler stores this login encrypted; it cannot be read here")
            continue
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            problems.append(f"{display_path(path)}: unreadable ({type(exc).__name__})")
            continue
        tok = data.get("oauth_token")
        if not isinstance(tok, str) or not tok.strip():
            problems.append(f"{display_path(path)}: no oauth_token")
            continue
        if not header_safe(tok.strip()):
            problems.append(f"{display_path(path)}: oauth_token {MALFORMED}")
            continue
        exp = _parse_expiry(data.get("expiration_time"))
        if exp is None:
            problems.append(f"{display_path(path)}: expiration_time missing or unparseable; treated as unknown")
            fallback = fallback or (path, Secret(tok.strip()))
            continue
        if exp <= now:
            problems.append(f"{display_path(path)}: OAuth token expired {exp.isoformat()}; "
                            "a valid credential is needed (this audit does not refresh logins)")
            continue
        return Credential(Secret(tok.strip()), "wrangler-oauth",
                          f"wrangler OAuth token from {display_path(path)} (expires {exp.isoformat()})", problems)
    if fallback:
        return Credential(fallback[1], "wrangler-oauth",
                          f"wrangler OAuth token from {display_path(fallback[0])} (expiry unknown)", problems)
    return Credential(None, "none", "no CLOUDFLARE_API_TOKEN and no usable wrangler login", problems)


_SECRET_ENV = ("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_KEY")
_SECRET_KEYS = ("oauth_token", "refresh_token")
_SECRET_LINE = re.compile(r"""(?m)^\s*(?:oauth_token|refresh_token)\s*=\s*["']([^"'\r\n]+)["']""")


def local_secrets() -> list[Secret]:
    """Every credential value this machine would hand the scanner, whether or not the account
    layer runs and whether or not the value is valid, expired or malformed: the output is
    redacted against all of them. Never used to authenticate."""
    out: list[Secret] = []
    for var in _SECRET_ENV:
        val = os.environ.get(var)
        if val and val.strip():
            out.append(Secret(val))
    for path in wrangler_config_candidates():
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue  # unreadable here means the scanner could not have read it either
        try:
            data = tomllib.loads(raw)
            vals = [data.get(k) for k in _SECRET_KEYS]
        except tomllib.TOMLDecodeError:
            vals = _SECRET_LINE.findall(raw)  # a broken file can still hold a live token
        out.extend(Secret(v) for v in vals if isinstance(v, str) and v.strip())
    return out
