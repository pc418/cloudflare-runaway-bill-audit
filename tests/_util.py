"""Shared test setup: imports from scripts/, a temp HOME, no Cloudflare credentials, no network.

Every test module imports this first. HOME points at a fresh temp directory so
no test can read the developer's real wrangler login, and CLOUDFLARE_* variables
are removed so no test can pick up a real token.
"""

from __future__ import annotations

import atexit
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
FIXTURES = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(SCRIPTS))
sys.dont_write_bytecode = True

_HOME = tempfile.mkdtemp(prefix="nobill-test-home-")
atexit.register(shutil.rmtree, _HOME, True)
os.environ["HOME"] = _HOME
os.environ.pop("XDG_CONFIG_HOME", None)
for _k in list(os.environ):
    if _k.startswith("CLOUDFLARE_") or _k.startswith("NOBILL_"):
        os.environ.pop(_k)


def temp_home() -> Path:
    """A fresh, empty HOME for one test (restored by the caller via env_restore)."""
    d = Path(tempfile.mkdtemp(prefix="nobill-home-"))
    atexit.register(shutil.rmtree, str(d), True)
    return d


def copy_fixture(name: str) -> Path:
    dst = Path(tempfile.mkdtemp(prefix=f"nobill-fx-{name}-")) / name
    atexit.register(shutil.rmtree, str(dst.parent), True)
    shutil.copytree(FIXTURES / name, dst)
    return dst


def tree_digest(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        rel = str(p.relative_to(root))
        h.update(rel.encode())
        if p.is_file():
            h.update(p.read_bytes())
            h.update(str(p.stat().st_mtime_ns).encode())
    return h.hexdigest()


def run_cli(args: list[str], env: dict | None = None) -> subprocess.CompletedProcess:
    e = {k: v for k, v in os.environ.items()}
    if env:
        e.update(env)
    return subprocess.run([sys.executable, "-B", str(SCRIPTS / "audit.py"), *args], capture_output=True,
                          text=True, env=e, timeout=120)


def scan(project: Path, out: Path | None = None, extra: list[str] | None = None, env: dict | None = None) -> tuple[dict, subprocess.CompletedProcess]:
    out = out or Path(tempfile.mkdtemp(prefix="nobill-out-"))
    atexit.register(shutil.rmtree, str(out), True)
    cp = run_cli(["scan", str(project), "--out", str(out), *(extra or [])], env=env)
    if cp.returncode != 0:
        raise AssertionError(f"scan failed ({cp.returncode}): {cp.stderr}")
    return json.loads((out / "findings.json").read_text()), cp


def by_rule(doc: dict, rule: str, severity: str | None = None) -> list[dict]:
    return [f for f in doc["findings"] if f["rule"] == rule and (severity is None or f["severity"] == severity)]


class FakeCloudflare:
    """A local stand-in for api.cloudflare.com: routes map 'METHOD /path' to (status, json body)."""

    def __init__(self, routes: dict[str, tuple[int, object]]):
        self.routes = routes
        self.requests: list[dict] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def _serve(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                path = self.path.split("?", 1)[0]
                key = f"{self.command} {path}"
                fake.requests.append({"method": self.command, "path": self.path, "ua": self.headers.get("User-Agent"),
                                      "auth": self.headers.get("Authorization"), "body": body.decode(errors="replace")})
                route = fake.routes.get(key, (404, {"success": False, "errors": [{"code": 7003, "message": "No route"}]}))
                if callable(route):  # a paginated endpoint answers by query string
                    route = route(self.path)
                status, payload = route[0], route[1]
                # Bytes let regression fixtures exercise literal JSON constants and oversized numbers.
                data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                for hk, hv in (route[2] if len(route) > 2 else {}).items():
                    self.send_header(hk, hv)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = _serve
            do_POST = _serve
            do_PUT = _serve
            do_DELETE = _serve

            def log_message(self, *a):  # keep test output clean
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def ok(result, **extra) -> tuple[int, dict]:
    return 200, {"success": True, "errors": [], "messages": [], "result": result, **extra}


def denied() -> tuple[int, dict]:
    return 403, {"success": False, "errors": [{"code": 10000, "message": "Authentication error"}], "result": None}


def unauthorized() -> tuple[int, dict]:
    return 401, {"success": False, "errors": [{"code": 10001, "message": "Unable to authenticate request"}], "result": None}
