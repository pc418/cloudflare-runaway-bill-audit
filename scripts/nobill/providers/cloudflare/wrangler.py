"""Wrangler config discovery and parsing (toml / json / jsonc, with [env.*] overrides)."""

from __future__ import annotations

import json
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .values import MISSING, shown

CONFIG_RE = re.compile(r"^wrangler(?:[.-][\w.-]+)?\.(toml|json|jsonc)$")
SKIP_DIRS = {"node_modules", "bower_components", "vendor", "__pycache__", "venv", "dist", "build", "coverage"}

# From wrangler's notInheritable() list: bindings and vars are per environment.
NON_INHERITABLE = {
    "agent_memory", "ai_search_namespaces", "ai_search", "ai", "analytics_engine_datasets", "artifacts",
    "browser", "cloudchamber", "connect", "containers", "define", "dispatch_namespaces", "durable_objects",
    "flagship", "hyperdrive", "images", "kv_namespaces", "media", "mtls_certificates", "pipelines", "queues",
    "ratelimits", "secrets_store_secrets", "secrets", "send_email", "services", "stream",
    "streaming_tail_consumers", "tail_consumers", "unsafe_hello_world", "unsafe", "vars", "vectorize",
    "version_metadata", "vpc_networks", "vpc_services", "worker_loaders", "workflows", "d1_databases",
    "r2_buckets",
}


def skip_dir(name: str) -> bool:
    return name.startswith(".") or name in SKIP_DIRS


def discover(root: Path, unlisted: list[tuple[str, str]] | None = None) -> list[Path]:
    """Wrangler configs under root. A directory that cannot be listed is appended to `unlisted` as
    (path relative to root, reason): a config inside it was not found, so the list may be incomplete."""
    found = []

    def onerror(exc: OSError) -> None:
        if unlisted is not None:
            where = os.path.relpath(exc.filename, root) if exc.filename else "."
            unlisted.append((where.replace(os.sep, "/"), type(exc).__name__))

    for dirpath, dirnames, filenames in os.walk(root, onerror=onerror, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if not skip_dir(d))
        for fn in sorted(filenames):
            if CONFIG_RE.match(fn):
                found.append(Path(dirpath) / fn)
    return found


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas outside strings."""
    out = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            seg = text[i:(n if j < 0 else j + 2)]
            out.append("\n" * seg.count("\n"))
            i = n if j < 0 else j + 2
            continue
        if c == "," and _next_significant(text, i + 1) in ("}", "]"):
            i += 1  # trailing comma (outside any string): dropped
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _next_significant(text: str, i: int) -> str:
    """The next character after whitespace and comments, or '' at the end."""
    n = len(text)
    while i < n:
        if text[i].isspace():
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            return text[i]
    return ""


@dataclass
class ConfigFile:
    path: Path
    rel: str
    fmt: str
    text: str = ""
    raw: dict[str, Any] | None = None
    error: str | None = None

    def find_line(self, key: str, after_line: int = 1, value: str | None = None) -> int:
        """Best-effort line of a key (toml `key =`, `[key]`, `[[key]]`, json `"key":`)."""
        lines = self.text.splitlines()
        k = re.escape(key)
        pats = [rf'^\s*"?{k}"?\s*[=:]', rf"^\s*\[\[?\s*(?:[\w.]+\.)?{k}\s*\]\]?", rf'"{k}"\s*:']
        if value is not None:
            v = re.escape(value)
            pats = [rf'"?{k}"?\s*[=:]\s*["\']?{v}["\']?(?![\w.-])', rf"{v}"]
        for start in ([after_line, 1] if after_line > 1 else [1]):
            for p in pats:  # the exact pattern over every line before the looser fallback
                for idx in range(start - 1, len(lines)):
                    if re.search(p, lines[idx]):
                        return idx + 1
        return 1

    def line_text(self, line: int) -> str:
        lines = self.text.splitlines()
        return lines[line - 1].strip() if 0 < line <= len(lines) else ""


@dataclass
class WorkerView:
    """One deployable Worker: a config file's top level, or one of its [env.*] sections."""
    config: ConfigFile
    env: str | None
    name: str
    eff: dict[str, Any]
    env_line: int = 1
    setting_errors: list[tuple[str, Any, str]] = field(default_factory=list)
    invalid: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        # The effective config stays as declared. A malformed field or row is recorded by path and
        # never read: the consumer that would read it reports an unknown for exactly that path, no
        # default stands in for it, and valid siblings keep their own conclusions.
        self.setting_errors.extend(_setting_errors(self.eff))
        self.invalid = {p for p, _, _ in self.setting_errors}

    def ok(self, path: str) -> bool:
        """True when neither `path` nor an ancestor of it is a malformed setting."""
        return not any(path == p or path.startswith(p + ".") or path.startswith(p + "[") for p in self.invalid)

    @property
    def label(self) -> str:
        return f"{self.name} ({self.config.rel}{' env ' + self.env if self.env else ''})"

    def get(self, key: str, default: Any = None) -> Any:
        return self.eff.get(key, default) if self.ok(key) else default

    def line(self, key: str, value: str | None = None) -> int:
        return self.config.find_line(key, self.env_line, value)

    def where(self, key: str, value: str | None = None) -> tuple[str, int, str]:
        ln = self.line(key, value)
        return self.config.rel, ln, self.config.line_text(ln)

    # binding helpers: every reader skips a malformed row or field by path -------------
    def rows(self, key: str) -> list[tuple[int, dict[str, Any]]]:
        """(original index, row) for each valid table row of a list-of-tables or single-table setting;
        `key` may be dotted (queues.consumers, durable_objects.bindings)."""
        if not self.ok(key):
            return []
        node: Any = self.eff
        for part in key.split("."):
            node = node.get(part) if isinstance(node, dict) else None
        if isinstance(node, dict):
            node = [node]
        if not isinstance(node, list):
            return []
        return [(i, r) for i, r in enumerate(node) if isinstance(r, dict) and self.ok(f"{key}[{i}]")]

    def field(self, key: str, i: int, row: dict[str, Any], name: str, default: Any = None) -> Any:
        """A row's field: its value when present and valid, `default` when absent, None when malformed."""
        return (row.get(name, default)) if self.ok(f"{key}[{i}].{name}") else None

    def names(self, key: str, *fields: str) -> list[str]:
        """The first present valid string among `fields` for each valid row (inventory and drift)."""
        out = []
        for i, row in self.rows(key):
            for name in fields:
                v = self.field(key, i, row, name)
                if isinstance(v, str) and v:
                    out.append(v)
                    break
        return out

    def row_label(self, key: str, i: int) -> str:
        """A stable identity for a row in targets: its valid name, else its position."""
        row = dict(self.rows(key)).get(i)
        if row is not None:
            for name in ("class_name", "name", "queue", "binding"):
                v = self.field(key, i, row, name)
                if isinstance(v, str) and v.strip():
                    return f"queue {v}" if key == "queues.consumers" else v
        return f"{key}[{i}]"

    def list_of(self, key: str) -> list[dict[str, Any]]:
        return [row for _, row in self.rows(key)]

    def _single(self, key: str, default_name: str) -> str | None:
        v = self.eff.get(key)
        if not isinstance(v, dict) or not self.ok(key):
            return None
        if "binding" not in v:
            return default_name
        return v["binding"] if self.ok(f"{key}.binding") else None  # malformed: not established, no default

    def ai_binding(self) -> str | None:
        return self._single("ai", "AI")

    def browser_binding(self) -> str | None:
        return self._single("browser", "BROWSER")

    def images_binding(self) -> str | None:
        return self._single("images", "IMAGES")

    def stream_binding(self) -> str | None:
        return self._single("stream", "STREAM")

    def r2_bindings(self) -> dict[str, str]:
        out = {}
        for i, b in self.rows("r2_buckets"):
            name = self.field("r2_buckets", i, b, "binding")
            if isinstance(name, str) and name:
                bucket = self.field("r2_buckets", i, b, "bucket_name", "")
                out[name] = bucket if isinstance(bucket, str) else ""
        return out

    def kv_bindings(self) -> list[str]:
        return self.names("kv_namespaces", "binding")

    def email_bindings(self) -> list[str]:
        return self.names("send_email", "name")

    def do_bindings(self) -> dict[str, str]:
        out = {}
        for i, b in self.rows("durable_objects.bindings"):
            name = self.field("durable_objects.bindings", i, b, "name")
            cls = self.field("durable_objects.bindings", i, b, "class_name", "")
            if isinstance(name, str) and name and isinstance(cls, str):
                out[name] = cls
        return out

    def d1_bindings(self) -> list[str]:
        return self.names("d1_databases", "binding")

    def vectorize_bindings(self) -> list[str]:
        return self.names("vectorize", "binding")

    def containers(self) -> list[dict[str, Any]]:
        return self.list_of("containers")

    def container_bindings(self) -> list[str]:
        classes = set(self.names("containers", "class_name"))
        return [n for n, cls in self.do_bindings().items() if cls in classes]

    def queues(self) -> dict[str, list[dict[str, Any]]]:
        return {"producers": self.list_of("queues.producers"), "consumers": self.list_of("queues.consumers")}

    def ratelimit_bindings(self) -> list[str]:
        names = self.names("ratelimits", "name")
        for i, b in self.rows("unsafe.bindings"):
            if self.field("unsafe.bindings", i, b, "type") == "ratelimit":
                name = self.field("unsafe.bindings", i, b, "name")
                if isinstance(name, str) and name:
                    names.append(name)
        return names

    def paid_binding_kinds(self) -> list[str]:
        kinds = []
        if self.ai_binding():
            kinds.append("Workers AI")
        if self.browser_binding():
            kinds.append("Browser Run")
        if self.containers():
            kinds.append("Containers")
        if self.images_binding():
            kinds.append("Images")
        if self.email_bindings():
            kinds.append("send_email")
        return kinds

    def hostnames(self) -> set[str]:
        hosts: set[str] = set()
        routes = []
        if self.get("route"):
            routes.append(self.eff["route"])
        if isinstance(self.get("routes"), list):
            routes.extend(r for i, r in enumerate(self.eff["routes"]) if self.ok(f"routes[{i}]"))
        for r in routes:
            pattern = r.get("pattern") if isinstance(r, dict) else r
            if isinstance(pattern, str):
                host = pattern.split("/", 1)[0].lstrip("*.")
                if host and "*" not in host:
                    hosts.add(host.lower())
        return hosts

    def has_entry(self) -> bool:
        return bool(self.get("main") or self.get("pages_build_output_dir") or self.get("assets"))

def parse(path: Path, root: Path) -> ConfigFile:
    rel = os.path.relpath(path, root)
    fmt = path.suffix.lstrip(".")
    cfg = ConfigFile(path=path, rel=rel, fmt=fmt)
    try:
        cfg.text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        cfg.error = f"cannot read: {type(exc).__name__}"
        return cfg
    try:
        if fmt == "toml":
            data = tomllib.loads(cfg.text)
        else:
            data = json.loads(strip_jsonc(cfg.text))
    except tomllib.TOMLDecodeError as exc:
        cfg.error = f"TOML parse error: {exc}"
        return cfg
    except json.JSONDecodeError as exc:
        cfg.error = f"JSON parse error at line {exc.lineno} col {exc.colno}: {exc.msg}"
        return cfg
    except (ValueError, RecursionError) as exc:
        # The decoder's message only: never the file, whose vars/secrets would land in the report.
        cfg.error = f"config value cannot be decoded ({type(exc).__name__}): {str(exc)[:200]}"
        return cfg
    if not isinstance(data, dict):
        cfg.error = f"top level is not an object/table ({shown(data)})"
        return cfg
    cfg.raw = data
    return cfg


def views(cfg: ConfigFile) -> list[WorkerView]:
    raw = cfg.raw or {}
    top = {k: v for k, v in raw.items() if k != "env"}
    base_name = raw.get("name") if isinstance(raw.get("name"), str) and raw["name"].strip() else Path(cfg.rel).parent.name or "worker"
    out = [WorkerView(cfg, None, base_name, top)]
    envs = raw.get("env")
    if "env" in raw and not isinstance(envs, dict):
        out[0].setting_errors.append(("env", envs, "a table"))
    if isinstance(envs, dict):
        for env_name, env_cfg in envs.items():
            if not isinstance(env_cfg, dict):
                out[0].setting_errors.append((f"env.{env_name}", env_cfg, "a table"))
                continue
            eff = {k: v for k, v in top.items() if k not in NON_INHERITABLE}
            eff.update(env_cfg)
            name = env_cfg.get("name") if isinstance(env_cfg.get("name"), str) and env_cfg["name"].strip() else f"{base_name}-{env_name}"
            line = 1
            for i, ln in enumerate(cfg.text.splitlines(), 1):
                if re.search(rf'^\s*\[\[?env\.{re.escape(env_name)}[\].]|"{re.escape(env_name)}"\s*:\s*\{{', ln):
                    line = i
                    break
            out.append(WorkerView(cfg, env_name, name, eff, env_line=line))
    return out


def _setting_errors(eff: dict[str, Any]) -> list[tuple[str, Any, str]]:
    """Only the fields this collector reads; not a Wrangler schema or source analyzer."""
    errors = []

    def text_fields(block, prefix, fields):
        for key in fields:
            if key in block and not (isinstance(block[key], str) and block[key].strip() and "\0" not in block[key]):
                errors.append((prefix + key, block[key], "a non-empty string without NUL"))

    def table(block, key, prefix=""):
        if key not in block:
            return {}
        if not isinstance(block[key], dict):
            errors.append((prefix + key, block[key], "a table"))
            return {}
        return block[key]

    def records(block, key, prefix="", single=False):
        """(original index, row) for the table rows; a non-table row is an error at its own index."""
        if key not in block:
            return []
        value = block[key]
        if single and isinstance(value, dict):
            return [(0, value)]
        if not isinstance(value, list):
            errors.append((prefix + key, value, "a list of tables"))
            return []
        for i, row in enumerate(value):
            if not isinstance(row, dict):
                errors.append((f"{prefix}{key}[{i}]", row, "a table"))
        return [(i, row) for i, row in enumerate(value) if isinstance(row, dict)]

    text_fields(eff, "", ("name", "main", "account_id", "pages_build_output_dir"))
    for key in ("workers_dev", "preview_urls"):
        if key in eff and not isinstance(eff[key], bool):
            errors.append((key, eff[key], "a boolean"))
    for key in ("ai", "browser", "images", "stream"):
        text_fields(table(eff, key), key + ".", ("binding",))
    fields = {
        "r2_buckets": ("binding", "bucket_name"), "kv_namespaces": ("binding",), "send_email": ("name",),
        "d1_databases": ("binding",), "vectorize": ("binding",), "containers": ("class_name", "name"),
        "services": ("binding", "name", "service", "entrypoint"), "ratelimits": ("name",),
        "workflows": ("binding", "name"), "analytics_engine_datasets": ("binding",), "hyperdrive": ("binding",),
    }
    # The field that names each binding row; a row without it declares nothing readable.
    required = {"r2_buckets": "binding", "kv_namespaces": "binding", "d1_databases": "binding", "vectorize": "binding",
                "services": "binding", "workflows": "binding", "analytics_engine_datasets": "binding",
                "hyperdrive": "binding", "send_email": "name", "ratelimits": "name", "containers": "class_name"}
    for key, names in fields.items():
        for i, row in records(eff, key, single=True):
            text_fields(row, f"{key}[{i}].", names)
            if key in required and required[key] not in row:
                errors.append((f"{key}[{i}].{required[key]}", MISSING, "declared (the field that names this binding)"))
            if key == "containers" and "instance_type" in row:  # a size name, or a custom size table
                it = row["instance_type"]
                if not (isinstance(it, str) and it.strip() or isinstance(it, dict) and it):
                    errors.append((f"containers[{i}].instance_type", it, "a size name or a table of vcpu/memory_mib/disk_mb"))
    do = table(eff, "durable_objects")
    for i, row in records(do, "bindings", "durable_objects."):
        text_fields(row, f"durable_objects.bindings[{i}].", ("name", "class_name"))
    queues = table(eff, "queues")
    for key in ("producers", "consumers"):
        for i, row in records(queues, key, "queues."):
            text_fields(row, f"queues.{key}[{i}].", ("binding", "queue", "dead_letter_queue"))
    unsafe = table(eff, "unsafe")
    for i, row in records(unsafe, "bindings", "unsafe."):
        text_fields(row, f"unsafe.bindings[{i}].", ("type", "name"))
    assets = table(eff, "assets")
    text_fields(assets, "assets.", ("directory", "binding"))
    if "run_worker_first" in assets:
        value = assets["run_worker_first"]
        if not (isinstance(value, bool) or isinstance(value, list) and all(isinstance(p, str) for p in value)):
            errors.append(("assets.run_worker_first", value, "a boolean or a list of strings"))
    routes = []
    if "route" in eff:
        routes.append(("route", eff["route"]))
    if "routes" in eff:
        if isinstance(eff["routes"], list):
            routes.extend((f"routes[{i}]", r) for i, r in enumerate(eff["routes"]))
        else:
            errors.append(("routes", eff["routes"], "a list"))
    for key, route in routes:
        if isinstance(route, dict):
            if "pattern" not in route:
                errors.append((key, route, "a route with a pattern"))
            text_fields(route, key + ".", ("pattern",))
        elif not isinstance(route, str) or not route.strip():
            errors.append((key, route, "a route string or table"))
    return errors


@dataclass
class Project:
    root: Path
    configs: list[ConfigFile] = field(default_factory=list)
    workers: list[WorkerView] = field(default_factory=list)
    unlisted: list[tuple[str, str]] = field(default_factory=list)  # directories discovery could not list


def load_project(root: Path) -> Project:
    proj = Project(root=root)
    for p in discover(root, proj.unlisted):
        cfg = parse(p, root)
        proj.configs.append(cfg)
        if cfg.raw is not None:
            proj.workers.extend(views(cfg))
    return proj
