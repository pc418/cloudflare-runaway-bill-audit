"""Read-only Cloudflare API client.

Read-only is enforced here, before any network I/O:
  * GET to any path, or
  * POST to /graphql with a JSON body {query, variables?, operationName?} whose
    document, lexed per the GraphQL spec (comments and strings skipped), contains
    only query operations and fragments.
Everything else raises ReadOnlyViolation. Redirects are not followed (so the
Authorization header can never be forwarded to another host), every request
carries a non-default User-Agent (Cloudflare's edge blocks python-urllib with
error 1010), and no error message ever contains the token.
"""

from __future__ import annotations

import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from ...findings import TOOL_NAME, TOOL_VERSION
from .auth import MALFORMED, Secret, header_safe
from .values import is_int, shown

API_BASE = "https://api.cloudflare.com/client/v4"
USER_AGENT = f"{TOOL_NAME}/{TOOL_VERSION} (read-only bill-risk audit)"
_LOCAL_BASE = re.compile(r"^http://(?:127\.0\.0\.1|localhost|\[::1\]):\d+(?:/.*)?$")


class ReadOnlyViolation(Exception):
    pass


@dataclass
class ApiResult:
    status: int                      # HTTP status; 0 = no response
    result: Any = None
    result_info: dict = field(default_factory=dict)
    errors: list[dict] = field(default_factory=list)
    reason: str = ""                 # short, token-free description when not ok
    success: bool = False            # REST: envelope "success": true; GraphQL: a "data" key and no errors

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300 and not self.errors and self.success

    def error_text(self) -> str:
        if self.errors:
            return "; ".join(f"{e.get('code', '')} {e.get('message', '')}".strip() for e in self.errors[:3])
        return self.reason


_GQL_PUNCT = set("!$&():=@[]{}|")
_GQL_NAME = re.compile(r"[_A-Za-z][_0-9A-Za-z]*")
_GQL_NUMBER = re.compile(r"-?[0-9][0-9.eE+-]*")


def _graphql_tokens(doc: str) -> list[str]:
    """Lex a GraphQL document per the spec: names and punctuators are kept; whitespace,
    commas, comments and string contents are dropped (strings become one '"' token).
    Anything the lexer cannot read (an unterminated string, a stray character) raises
    ReadOnlyViolation: an undecidable document is refused, not sent."""
    toks: list[str] = []
    i, n = 0, len(doc)
    while i < n:
        c = doc[i]
        if c in " \t\r\n,\ufeff":
            i += 1
        elif c == "#":
            while i < n and doc[i] not in "\r\n":
                i += 1
        elif doc.startswith('"""', i):
            j = i + 3
            while True:
                k = doc.find('"""', j)
                if k < 0:
                    raise ReadOnlyViolation("GraphQL document has an unterminated block string")
                if doc[k - 1] == "\\":  # \""" is an escaped triple quote inside the block
                    j = k + 3
                    continue
                break
            toks.append('"')
            i = k + 3
        elif c == '"':
            j = i + 1
            while j < n and doc[j] != '"':
                if doc[j] in "\r\n":
                    break
                j += 2 if doc[j] == "\\" else 1
            if j >= n or doc[j] != '"':
                raise ReadOnlyViolation("GraphQL document has an unterminated string")
            toks.append('"')
            i = j + 1
        elif doc.startswith("...", i):
            toks.append("...")
            i += 3
        elif c in _GQL_PUNCT:
            toks.append(c)
            i += 1
        else:
            m = _GQL_NAME.match(doc, i) or _GQL_NUMBER.match(doc, i)
            if not m:
                raise ReadOnlyViolation(f"GraphQL document has an unexpected character at offset {i}")
            toks.append(m.group(0))
            i = m.end()
    return toks


def _graphql_definitions(doc: str) -> list[str]:
    """The keyword that opens each top-level definition ('{' for the query shorthand)."""
    toks = _graphql_tokens(doc)
    kinds: list[str] = []
    i, n = 0, len(toks)
    while i < n:
        kinds.append(toks[i])
        if toks[i] not in ("{", "query", "fragment"):
            return kinds  # the caller refuses it; no need to read further
        paren = 0
        while i < n and not (toks[i] == "{" and paren == 0):  # header: name, variables, directives
            paren += {"(": 1, "[": 1, ")": -1, "]": -1}.get(toks[i], 0)
            i += 1
        depth = 0
        while i < n:  # the selection set, balanced
            depth += {"{": 1, "}": -1}.get(toks[i], 0)
            i += 1
            if depth == 0:
                break
        if depth != 0:
            raise ReadOnlyViolation("GraphQL document has an unbalanced selection set")
    return kinds


def assert_read_only(method: str, path: str, body: Any) -> None:
    m = method.upper()
    if m == "GET":
        if body is not None:
            raise ReadOnlyViolation("GET requests carry no body")
        return
    if m != "POST":
        raise ReadOnlyViolation(f"{m} is not allowed: the client is read-only (GET, or POST of a GraphQL query)")
    if path.split("?", 1)[0].rstrip("/") != "/graphql":
        raise ReadOnlyViolation(f"POST is only allowed to /graphql, not {path}")
    if not isinstance(body, dict) or not isinstance(body.get("query"), str):
        raise ReadOnlyViolation("POST /graphql needs a JSON body with a 'query' string")
    extra = set(body) - {"query", "variables", "operationName"}
    if extra:
        raise ReadOnlyViolation(f"unexpected GraphQL body keys: {sorted(extra)}")
    kinds = _graphql_definitions(body["query"])
    if not kinds or any(k not in ("{", "query", "fragment") for k in kinds):
        raise ReadOnlyViolation("GraphQL document may only contain query operations and fragments "
                                "(mutation/subscription or unknown definitions are refused)")
    if not any(k in ("{", "query") for k in kinds):
        raise ReadOnlyViolation("GraphQL document has no query operation")


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-standard JSON constant {name}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


class Client:
    def __init__(self, token: Secret, base: str = API_BASE, timeout: float = 20.0):
        if base != API_BASE and not _LOCAL_BASE.match(base):
            raise ValueError("API base must be the Cloudflare API or a local test server")
        if not header_safe(token.reveal()):
            raise ValueError("credential " + MALFORMED) from None
        self._token = token
        self.base = base.rstrip("/")
        self.timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect)

    def _scrub(self, text: str) -> str:
        tok = self._token.reveal()
        return text.replace(tok, "[REDACTED]") if tok else text

    def request(self, method: str, path: str, params: dict | None = None, body: Any = None) -> ApiResult:
        assert_read_only(method, path, body)
        url = self.base + path
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        data = None
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json",
                   "Authorization": "Bearer " + self._token.reveal()}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        status = 0
        raw = b""
        try:
            req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
            with self._opener.open(req, timeout=self.timeout) as resp:
                status = resp.status
                raw = resp.read(8_000_000)
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                raw = exc.read(1_000_000)
            except Exception:  # noqa: BLE001 - body is optional
                raw = b""
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            return ApiResult(0, reason=self._scrub(f"network error: {type(reason).__name__}"))
        except Exception as exc:  # noqa: BLE001 - any other transport failure (urllib puts headers in some messages)
            # Only the exception's type name is kept; its text and chain may carry the Authorization header.
            return ApiResult(0, reason=f"transport error: {type(exc).__name__}")
        res = ApiResult(status)
        try:
            # NaN / Infinity / -Infinity are not JSON; Python accepts them by default, and they compare
            # false with every bound, so a body carrying one is malformed, not data
            payload = json.loads(raw.decode("utf-8") or "null", parse_constant=_reject_constant)
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            # Diagnostics still pass through token scrubbing. Never propagate decoder failures,
            # including Python's integer-string size limit or deeply nested response bodies.
            detail = self._scrub(str(exc))[:160]
            excerpt = self._scrub(raw.decode('utf-8', errors='replace'))[:240]
            reason = f"response was not JSON ({type(exc).__name__}): {detail}; body {excerpt}"
            return ApiResult(0 if 200 <= status < 300 else status, reason=reason)
        graphql = path.split("?", 1)[0].rstrip("/") == "/graphql"
        if isinstance(payload, dict):
            res.result = payload.get("data") if graphql else payload.get("result")
            res.success = ("data" in payload) if graphql else payload.get("success") is True
            # Pagination metadata is consumed by get_all only; a single-object read never reads it,
            # so it is validated there (null / wrong-typed metadata cannot certify a list complete).
            res.result_info = payload.get("result_info", {})
            errs = payload.get("errors")
            if isinstance(errs, list):
                res.errors = [{"code": e.get("code", ""), "message": self._scrub(str(e.get("message", "")))[:300]}
                              if isinstance(e, dict) else {"code": "", "message": self._scrub(str(e))[:300]}
                              for e in errs]
            elif errs is not None:  # null means no error entries were supplied; a non-list is a broken envelope
                res.success = False
                res.errors = [{"code": "", "message": self._scrub(f"malformed API envelope: 'errors' is not a list ({shown(errs)})")}]
        elif not (200 <= status < 300):
            res.reason = f"HTTP {status}"
        if 300 <= status < 400:
            res.reason = f"HTTP {status} redirect not followed"
        if not (200 <= status < 300) and not res.reason:
            res.reason = f"HTTP {status}"
        if 200 <= status < 300 and payload is None:
            res.reason = "response was not JSON"
            res.status = 0
        elif 200 <= status < 300 and not res.success and not res.errors and not res.reason:
            res.reason = ("GraphQL response has no data" if graphql else self._scrub(
                f"API response did not report success (envelope success is not true: "
                f"{shown(payload.get('success') if isinstance(payload, dict) else payload)})"))
        return res

    def get(self, path: str, params: dict | None = None) -> ApiResult:
        return self.request("GET", path, params=params)

    def _page_problem(self, info: Any) -> str | None:
        """Why pagination metadata cannot establish whether a list is complete, or None."""
        if not isinstance(info, dict):
            return self._scrub(f"result_info is not an object ({shown(info)})")
        for key in ("page", "total_pages", "per_page", "total_count"):
            if key in info and not (is_int(info[key]) and info[key] >= (1 if key in ("page", "per_page") else 0)):
                return self._scrub(f"result_info.{key} is not a finite integer in range ({shown(info[key])})")
        if "cursor" in info and info["cursor"] is not None and not isinstance(info["cursor"], str):
            return self._scrub(f"result_info.cursor is not a string ({shown(info['cursor'])})")
        return None

    def get_all(self, path: str, params: dict | None = None, max_pages: int = 20, key: str | None = None) -> ApiResult:
        """GET with page/cursor pagination; the first non-ok page is returned as-is. `key` names the
        list inside an object result (e.g. R2's {"buckets": [...]}); without it only a list result pages."""
        params = dict(params or {})
        first = self.get(path, params)

        def items_of(res: ApiResult) -> list | None:
            if key is None:
                return res.result if isinstance(res.result, list) else None
            return res.result.get(key) if isinstance(res.result, dict) and isinstance(res.result.get(key), list) else None

        if not first.ok or items_of(first) is None:
            return first
        items = list(items_of(first))
        info = first.result_info
        pages = 1
        seen = set()
        while True:
            problem = self._page_problem(info)
            if problem:
                return ApiResult(0, reason=problem)
            if info.get("cursor"):
                params["cursor"] = info["cursor"]
            elif isinstance(info.get("total_pages"), int) and info.get("page", pages) < info["total_pages"]:
                params["page"] = info.get("page", pages) + 1
            elif (isinstance(info.get("total_count"), int) and isinstance(info.get("per_page"), int)
                  and info.get("page", pages) * info["per_page"] < info["total_count"]):
                params["page"] = info.get("page", pages) + 1
            else:
                break
            marker = (params.get("cursor"), params.get("page"))
            if marker in seen or pages >= max_pages:
                return ApiResult(0, reason=self._scrub(f"pagination incomplete or repeated ({shown(info)})"))
            seen.add(marker)
            nxt = self.get(path, params)
            if not nxt.ok or items_of(nxt) is None:
                if nxt.ok:
                    nxt.status, nxt.reason = 0, self._scrub(f"pagination result is not a list ({shown(nxt.result)})")
                return nxt
            items.extend(items_of(nxt))
            info = nxt.result_info
            pages += 1
        if key is None:
            first.result = items
        else:
            first.result = dict(first.result, **{key: items})
        return first

    def graphql(self, query: str, variables: dict | None = None) -> ApiResult:
        body: dict[str, Any] = {"query": query}
        if variables is not None:
            body["variables"] = variables
        return self.request("POST", "/graphql", body=body)
