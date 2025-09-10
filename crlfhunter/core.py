#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Core implementation of the CRLF Hunter tool.

This module contains the full scanning engine, command-line interface
implementation and optional FastAPI-based web user interface. It is split
into its own file so that the package can expose a stable API while still
providing a self-contained script when invoked directly.

The primary entry point for the command-line interface is the ``program_main``
function defined at the bottom of the file. The function accepts an optional
``argv`` list to support programmatic invocation (e.g. from the CLI
wrapper). When executed as a script (via ``python -m crlfhunter.core`` or
``python crlfhunter/core.py``), the module will call ``program_main()`` with
default argument parsing.
"""

from __future__ import annotations

import argparse
import concurrent.futures as futures
import gzip
import json
import os
import sys
import threading
import time
import uuid
import tempfile
from dataclasses import asdict
from typing import Iterable, List, Optional, Tuple, Dict

# External modules
import httpx  # type: ignore
import h2.connection  # type: ignore
import h2.events  # type: ignore
from fastapi import FastAPI, UploadFile, Form, Request, HTTPException  # type: ignore
from fastapi.responses import HTMLResponse, FileResponse, PlainTextResponse, JSONResponse  # type: ignore
import uvicorn  # type: ignore
from urllib.parse import parse_qsl, urlparse, urlunparse, urlencode

# Additional imports for raw request scanning and smuggling
import random
import string
import ssl
import socket
import re

# ----------------------------------------------------------------------------
# Job registry for the web UI
# ----------------------------------------------------------------------------

JOBS: dict[str, dict[str, object]] = {}
"""
A simple in-memory registry that tracks the state of background scan jobs
spawned by the web UI. Each job is keyed by a UUID and stores keys such as
``status`` (``"running"`` or ``"done"``), ``total`` (an integer number of
payload attempts), ``done`` (the number of completed attempts), and paths to
the generated JSON and CSV report files. A global thread lock protects
concurrent access.
"""

JOBS_LOCK = threading.Lock()

# ----------------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------------

def _iter_urls_from_file(path: str, assume_scheme: str) -> Iterable[str]:
    """Yield normalized URLs from a text or gzip-compressed file.

    Skips empty lines and comments starting with '#', trims whitespace,
    and prepends a default scheme if missing.

    Args:
        path: Filesystem path to a text (.txt) or gzip (.gz) file containing
            one URL per line.
        assume_scheme: Default scheme to prepend when a URL lacks ``http://``
            or ``https://``.

    Yields:
        Each normalized URL as a string.
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
    """Load many URLs with basic deduplication while preserving insertion order.

    Args:
        paths: A list of file paths to read URLs from.
        assume_scheme: Scheme to prepend to URLs lacking one.

    Returns:
        A list of unique URLs in order of first appearance.
    """
    seen = set()
    out: List[str] = []
    for p in paths:
        for u in _iter_urls_from_file(p, assume_scheme):
            if u not in seen:
                seen.add(u)
                out.append(u)
    return out


def write_findings_json(path: str, findings: List[object]) -> None:
    """Serialize findings to a JSON file.

    Args:
        path: Destination path for the JSON output.
        findings: A list of dataclass instances representing vulnerability
            findings. They will be converted to dictionaries using ``asdict``.
    """
    payload = [asdict(f) for f in findings]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def write_findings_csv(path: str, findings: List[object]) -> None:
    """Serialize findings to a CSV file.

    Args:
        path: Destination path for the CSV output.
        findings: A list of dataclass instances representing vulnerability
            findings.
    """
    import csv
    cols = [
        "url",
        "method",
        "location",
        "parameter",
        "payload",
        "status",
        "redirected",
        "evidence",
        "injected_header_seen",
        "set_cookie_injected",
        "raw_header_sample",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for x in findings:
            row = asdict(x)
            # stringify nested header sample to keep CSV clean
            row["raw_header_sample"] = json.dumps(row.get("raw_header_sample", {}), ensure_ascii=False)
            w.writerow({k: row.get(k, "") for k in cols})


def estimate_total_tasks(urls: List[str], payloads: List[str], body_params: Optional[str]) -> int:
    """Rough count of payload attempts.

    This estimates the number of injection attempts that will be queued given
    the number of target URLs, payloads, and injection locations.

    Args:
        urls: List of target URLs.
        payloads: List of payload strings.
        body_params: Comma-separated string of body parameter names to fuzz.

    Returns:
        An integer representing the total number of payload injection tasks.
    """
    total = 0
    for target in urls:
        parsed = urlparse(target)
        q_params = [k for (k, _) in parse_qsl(parsed.query, keep_blank_values=True)]
        b_params = [p.strip() for p in (body_params or "").split(",") if p.strip()]
        # query + body + path
        num_locations = len(q_params) + len(b_params) + 1
        total += num_locations * len(payloads)
    return total


def progress_update(job_id: str, delta: int = 1) -> None:
    """Increment progress for a running job.

    Args:
        job_id: The unique identifier of the job.
        delta: Amount by which to increment the completed tasks counter.
    """
    if not job_id:
        return
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job:
            job["done"] = min(job["total"], job.get("done", 0) + delta)


def progress_set_total(job_id: str, total: int) -> None:
    """Set the total number of tasks for a job.

    Args:
        job_id: The unique identifier of the job.
        total: Total number of tasks (payload injections) for the job.
    """
    if not job_id:
        return
    with JOBS_LOCK:
        job = JOBS.setdefault(job_id, {"status": "running", "total": 0, "done": 0, "json": None, "csv": None})
        job["total"] = max(total, 0)
        job["done"] = min(job.get("done", 0), job["total"])


# ----------------------------------------------------------------------------
# Raw request parsing and header helpers
# ----------------------------------------------------------------------------

# Hop-by-hop headers which should be stripped when replaying raw requests. These
# headers are managed by the underlying HTTP client (requests/httpx) and
# should not be forwarded manually.
HOP_BY_HOP: set[str] = {
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
    headers are managed by the underlying HTTP client and should not be
    forwarded manually. Returns a new dict with only end-to-end headers.

    Args:
        hdrs: Mapping of header names to values.

    Returns:
        A new dictionary excluding hop-by-hop and Content-Length headers.
    """
    cleaned: Dict[str, str] = {}
    for k, v in hdrs.items():
        lk = k.lower()
        if lk in HOP_BY_HOP or lk == "content-length":
            continue
        cleaned[k] = v
    return cleaned

def short_hdrs(hdrs: Dict[str, str], limit: int = 16) -> Dict[str, str]:
    """
    Truncate header values for evidence display (to avoid huge outputs).

    Args:
        hdrs: Dictionary of header names and values.
        limit: Maximum number of characters to keep per header value.

    Returns:
        A dictionary with truncated values where necessary.
    """
    return {k: (v[:limit] + "..." if len(v) > limit else v) for k, v in hdrs.items()}

def parse_raw_http_request(text: str, default_scheme: str) -> Tuple[str, str, Dict[str, str], str]:
    """
    Parse a Burp/ZAP-style raw HTTP request into (method, url, headers, body).

    Supports absolute-form requests like 'POST https://example.com/path HTTP/1.1'
    or origin-form requests like 'POST /path HTTP/1.1' with a Host header. If
    only a relative path is provided, uses default_scheme and Host to build
    the full URL. Hop-by-hop and Content-Length headers are stripped.

    Args:
        text: Raw HTTP request text.
        default_scheme: Scheme ('http' or 'https') to use when building
            full URLs from relative paths.

    Returns:
        A tuple of (method, url, headers, body) where headers is a dict.
    """
    # Normalise newlines to LF
    text = text.replace("\r\n", "\n")
    head, _, body = text.partition("\n\n")
    # Filter out empty lines in header section
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
    Load and parse a raw HTTP request from a file on disk.

    Args:
        path: Filesystem path to the request file.
        default_scheme: Scheme ('http' or 'https') to use for relative
            requests.

    Returns:
        A tuple of (method, url, headers, body).
    """
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return parse_raw_http_request(f.read(), default_scheme)


def _render_html(title: str, body: str) -> HTMLResponse:
    """Render a full HTML page with consistent styling.

    Args:
        title: Document title.
        body: The HTML content to insert into the ``<main>`` section.

    Returns:
        An ``HTMLResponse`` object containing the full HTML page.
    """
    # Note: The CSS and page skeleton are defined here. Use CSS variables
    # (where possible) to support dark/light themes automatically.
    base_css = """
    <style>
      :root { color-scheme: light dark; }
      * { box-sizing: border-box; }
      body {
        font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
        margin: 0; background: #0b0d10; color: #e8eaed;
      }
      header {
        padding: 24px; background: linear-gradient(135deg,#1c1f24 0%,#121418 100%);
        border-bottom: 1px solid #2a2f36;
      }
      h1 { margin: 0; font-size: 22px; letter-spacing: .3px; }

      main { max-width: 1060px; margin: 0 auto; padding: 28px 16px 64px; }
      .card {
        background: #151922; border: 1px solid #2a2f36; border-radius: 16px;
        padding: 24px; box-shadow: 0 10px 30px rgba(0,0,0,.35);
      }

      /* Layout */
      .grid { display: grid; gap: 16px; }
      .grid-2 { grid-template-columns: 1fr; }
      @media (min-width: 1024px) { .grid-2 { grid-template-columns: 1fr 1fr; } }

      /* Form blocks are sized to align row-by-row */
      .block { display: grid; gap: 10px; }
      .row { display: grid; grid-template-columns: 140px 1fr; gap: 12px; align-items: center; }

      /* Controls */
      label { font-weight: 600; font-size: 13px; color: #aab2c0; }
      input[type=text], input[type=number], input[type=file], textarea, select {
        width: 100%; padding: 10px 12px; border-radius: 10px;
        border: 1px solid #2a2f36; background: #0f131a; color: #e8eaed; outline: none;
      }
      textarea {
        min-height: 140px; /* consistent height = symmetrical rows */
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      }
      input[type=file] { padding: 8px; }

      .muted { color: #91a0b6; font-size: 12px; }

      /* Buttons */
      .btn {
        background: linear-gradient(135deg,#4a66ff 0%, #00ccff 100%); border: none; color: white;
        padding: 10px 16px; border-radius: 10px; cursor: pointer; font-weight: 700; letter-spacing: .2px;
        box-shadow: 0 8px 20px rgba(0, 179, 255, .25);
      }
      .btn:disabled { filter: grayscale(.4); opacity:.7; cursor:not-allowed; }

      /* Table */
      table { width:100%; border-collapse: collapse; }
      th, td { padding: 8px 10px; font-size: 13px; border-bottom: 1px solid #2a2f36; }
      th { text-align: left; color:#aab2c0; font-weight: 600; }
      .pill {
        display:inline-block; padding:2px 8px; border-radius:9999px; font-size:12px;
        background:#0f131a; border:1px solid #2a2f36; color:#c9d4e3;
      }

      /* Progress bar */
      .progress-wrap { margin-top: 12px; background:#0f131a; border:1px solid #2a2f36; border-radius:12px; overflow:hidden; height:14px; }
      .progress-bar  { height:100%; width:0%; background:linear-gradient(90deg,#00ccff,#4a66ff); transition:width .25s ease; }
      .progress-text { margin-top:6px; font-size:12px; color:#aab2c0; }
      .actions { display:flex; gap:10px; margin-top:16px; }
    </style>
    """
    html = f"""<!doctype html>
    <html><head><meta charset="utf-8"><title>{title}</title>{base_css}</head>
    <body>
      <header><h1>CRLF Hunter – Web UI</h1></header>
      <main>{body}</main>
    </body></html>"""
    return HTMLResponse(html)


def build_app() -> FastAPI:
    """Construct and configure the FastAPI application for the web UI."""
    if FastAPI is None:
        raise RuntimeError("FastAPI not installed. Install fastapi and uvicorn for the web UI.")
    app = FastAPI()

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        # Build the main form. Use a two-column grid with rows aligned by labels.
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
                <label>URL List (.txt/.gz)</label>
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
                <label>Request files</label>
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
                <select name="follow_redirects"><option value="">No</option><option value="1">Yes</option></select>
              </div>
              <div class="row">
                <label>HTTP/2</label>
                <select name="http2"><option value="">No</option><option value="1">Yes</option></select>
              </div>
              <div class="row">
                <label>Fuzz headers</label>
                <select name="fuzz_headers"><option value="">No</option><option value="1">Yes</option></select>
              </div>
              <div class="row">
                <label>Smuggle h2</label>
                <select name="smuggle_h2"><option value="">No</option><option value="1">Yes</option></select>
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

            <div style="grid-column: 1 / -1; display:flex; gap:12px; align-items:center; margin-top:8px;">
              <button class="btn" type="submit">Run scan</button>
              <span class="muted">You’ll get a results table (and files if you set outputs)</span>
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
    ) -> HTMLResponse:
        """Handle form submission, spawn background scan job, and render progress page."""
        # Build pseudo-args object to re-use the engine and CLI logic
        class Dummy:
            pass
        args = Dummy()
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
        args.max_inflight = int(max_inflight) if (max_inflight and max_inflight.isdigit()) else 0
        args.url_file = None

        # Parse headers and cookies textareas into lists of ``-H`` and ``-C`` style arguments
        for ln in (headers or "").splitlines():
            ln = ln.strip()
            if ln:
                args.header.append(ln)
        for ln in (cookies or "").splitlines():
            ln = ln.strip()
            if ln:
                args.cookie.append(ln)

        # Process target URLs typed into the form
        url_list: List[str] = []
        if urls.strip():
            for ln in urls.splitlines():
                s = ln.strip()
                if not s or s.startswith("#"):
                    continue
                if not (s.lower().startswith("http://") or s.lower().startswith("https://")):
                    s = f"{assume_scheme}://{s.lstrip('/')}"
                url_list.append(s)

        # Handle uploaded URL list file
        if url_file and url_file.filename:
            import tempfile
            suffix = ".gz" if url_file.filename.lower().endswith(".gz") else ".txt"
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tf:
                tf.write(await url_file.read())
                tmp_path = tf.name
            try:
                more = load_urls_from_files([tmp_path], assume_scheme)
                url_list.extend(more)
            except Exception:
                pass

        # Handle uploaded raw request files
        if req_files:
            import tempfile
            rf_paths = []
            for f in req_files:
                if not f.filename:
                    continue
                with tempfile.NamedTemporaryFile(delete=False, suffix=".req") as tf:
                    tf.write(await f.read())
                    rf_paths.append(tf.name)
            args.request_file = rf_paths if rf_paths else None

        args.url = url_list

        # Create a job entry and spawn a background scan thread
        job_id = uuid.uuid4().hex
        with JOBS_LOCK:
            JOBS[job_id] = {"status": "running", "total": 0, "done": 0, "json": None, "csv": None}

        # Background thread to run the scan and update job state
        def _run_job(jid: str, args_obj: object) -> None:
            try:
                # Generate default output files if not provided
                if not getattr(args_obj, "out_json", None):
                    args_obj.out_json = os.path.join(tempfile.gettempdir(), f"crlfhunter_{jid}.json")
                if not getattr(args_obj, "out_csv", None):
                    args_obj.out_csv = os.path.join(tempfile.gettempdir(), f"crlfhunter_{jid}.csv")

                # Bind job_id to the engine for progress updates
                args_obj.job_id = jid

                # Perform the scan using the engine
                engine = Engine(args_obj)
                if args_obj.request_file:
                    engine.scan_request_files(args_obj.request_file, args_obj.req_scheme)
                elif args_obj.smuggle_h2:
                    engine.smuggle_h2_scan(args_obj.url)
                else:
                    engine.scan(args_obj.url)

                # Write JSON and CSV outputs
                if args_obj.out_json:
                    try:
                        write_findings_json(args_obj.out_json, engine.findings)
                    except Exception:
                        pass
                if args_obj.out_csv:
                    try:
                        write_findings_csv(args_obj.out_csv, engine.findings)
                    except Exception:
                        pass

                with JOBS_LOCK:
                    job = JOBS.get(jid)
                    if job:
                        job["status"] = "done"
                        job["json"] = args_obj.out_json
                        job["csv"] = args_obj.out_csv
                        job["done"] = max(job.get("done", 0), job.get("total", 0))
            except Exception:
                with JOBS_LOCK:
                    job = JOBS.get(jid)
                    if job:
                        job["status"] = "done"

        t = threading.Thread(target=_run_job, args=(job_id, args), daemon=True)
        t.start()

        # Render progress page with a polling script
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
              const r = await fetch('/progress/{job_id}');
              if (!r.ok) throw new Error('bad');
              const j = await r.json();
              const total = Math.max(1, j.total || 1);
              const done = Math.min(total, j.done || 0);
              const p = Math.round(done * 100 / total);
              bar.style.width = p + '%';
              pct.textContent = p + '% complete';
              if (j.status === 'done') {{
                bar.style.width = '100%';
                pct.textContent = '100% complete';
                doneBox.style.display = 'block';
                return;
              }}
            }} catch (e) {{}}
            setTimeout(poll, 500);
          }}
          poll();
        </script>
        """.format(job_id=job_id)
        return _render_html("CRLF Hunter – Running", progress_html)

    @app.get("/progress/{job_id}")
    async def ui_progress(job_id: str) -> dict[str, object]:
        """Return JSON progress information for a running or completed job."""
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

    return app


# ----------------------------------------------------------------------------
# Engine implementation
# ----------------------------------------------------------------------------

from dataclasses import dataclass
import requests


@dataclass
class Finding:
    """Represent a confirmed CRLF injection finding."""
    url: str
    method: str
    location: str
    parameter: str
    payload: str
    status: int
    redirected: bool
    evidence: str
    injected_header_seen: bool
    set_cookie_injected: bool
    raw_header_sample: dict[str, str]


class Engine:
    """The main scanning engine responsible for performing CRLF injection tests."""

    def __init__(self, args: object) -> None:
        self.args = args
        self.findings: List[Finding] = []
        self.base_headers: dict[str, str] = {}
        self.payloads: List[str] = []
        self.job_id: Optional[str] = getattr(args, "job_id", None)

        # Populate default payloads; these have been manually curated for coverage
        self.payloads = [
            "%0d%0aX-Injection: injected",
            "%0D%0Ax-Injected-Header: 1",
            "%0D%0AX-Custom-CRLF: test",
            "%0A%0DSet-Cookie: crlf=1; HttpOnly",
            "%0D%0D%0AInjected-Header: test",
            "%0a%0d",
            "%0d%0a",
            "%0d%0a%0d%0a",
            "%0D%0A%0D%0A",
            "%0d%0a%0d%0aInjected-Header: test",
            "%0D%0ASet-Cookie: injected=1",
            "%0D%0AX-Injected: yes",
            "%0A%0DInjected-Header: yes",
            "%0D%0Ajavascript:alert(1)",
            "%0D%0A<svg onload=alert(1)>",
            "%0D%0A%3Cimg%20src=x%20onerror=alert(1)%3E",
            "%0D%0A%25%30%44%25%30%41%58-Injected: test",
        ]

        # Additional optional payloads can be loaded from a file via --payloads
        if getattr(args, "payloads", None):
            # This attribute may be a file path or list of file paths.
            pfiles = args.payloads if isinstance(args.payloads, list) else [args.payloads]
            for pfile in pfiles:
                try:
                    with open(pfile, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                self.payloads.append(line)
                except Exception:
                    continue

        # Respect user-supplied headers and cookies
        for h in getattr(args, "header", []):
            try:
                k, v = h.split(":", 1)
                self.base_headers[k.strip()] = v.strip()
            except Exception:
                continue
        for c in getattr(args, "cookie", []):
            if "Cookie" not in self.base_headers:
                self.base_headers["Cookie"] = c
            else:
                # Append additional cookies separated by semicolon
                self.base_headers["Cookie"] += "; " + c

        # HTTP session and client setup
        self.req_session = requests.Session()
        self.req_session.headers.update(self.base_headers)
        self.httpx_client = None
        if getattr(args, "http2", False):
            # Create HTTPX client for HTTP/2 support; fallback to requests for HTTP/1
            try:
                self.httpx_client = httpx.Client(http2=True, headers=self.base_headers)
            except Exception:
                self.httpx_client = None
        else:
            self.httpx_client = None

        # Initialise cookies from CLI options (e.g. -C or --cookie)
        self.cookies: Dict[str, str] = {}
        for c in getattr(args, "cookie", []):
            if "=" in c:
                k, v = c.split("=", 1)
                self.cookies[k.strip()] = v.strip()
        # Update session and httpx client cookie jars if any cookies provided
        if self.cookies:
            try:
                self.req_session.cookies.update(self.cookies)
            except Exception:
                pass
            if self.httpx_client:
                try:
                    self.httpx_client.cookies.update(self.cookies)
                except Exception:
                    pass

        # Thread pool and concurrency controls
        self.thread_pool = futures.ThreadPoolExecutor(max_workers=args.threads)
        self.start_time = time.time()
        # Determine maximum number of concurrent tasks; default auto sets it to threads*50
        self.max_inflight = args.max_inflight if args.max_inflight > 0 else (args.threads * 50)

    def _test_injection(self, target: str, location: str, parameter: str, payload: str) -> Optional[Finding]:
        """Internal helper to test a single payload at a specific injection point."""
        # Build the request based on injection location
        try:
            url = target
            method = "GET"
            data = None
            headers = self.base_headers.copy()

            # Determine injection target: query parameter, body parameter or path
            if location == "query":
                parsed = urlparse(url)
                query_params = parse_qsl(parsed.query, keep_blank_values=True)
                new_query = []
                injected_param = None
                for (k, v) in query_params:
                    if k == parameter:
                        injected_param = (k, v)
                        new_query.append((k, v + payload))
                    else:
                        new_query.append((k, v))
                if not injected_param:
                    # Parameter not present; skip this injection
                    return None
                query_str = "&".join([f"{k}={v}" for (k, v) in new_query])
                url = parsed._replace(query=query_str).geturl()
            elif location == "body":
                # For body injection we use POST
                method = "POST"
                parsed = urlparse(url)
                body_params = parse_qsl(parsed.query, keep_blank_values=True)
                # Build body content using provided body_params list
                body_dict = {}
                if getattr(self.args, "body_params", None):
                    for p in self.args.body_params.split(","):
                        p = p.strip()
                        body_dict[p] = "test"
                # Now override the target parameter with injected value
                if parameter in body_dict:
                    body_dict[parameter] = body_dict.get(parameter, "") + payload
                else:
                    return None
                data = body_dict
            elif location == "path":
                # Append payload to the path
                parsed = urlparse(url)
                path = parsed.path or "/"
                path = path.rstrip("/") + payload
                url = parsed._replace(path=path).geturl()
            else:
                return None

            # Optionally throttle requests
            if self.args.rate > 0:
                time.sleep(self.args.rate)
            # Send the request using requests or httpx depending on the protocol
            if self.httpx_client:
                response = self.httpx_client.request(method, url, headers=headers, data=data, timeout=self.args.timeout)
            else:
                if method == "POST":
                    response = self.req_session.post(url, headers=headers, data=data, timeout=self.args.timeout, allow_redirects=self.args.follow_redirects)
                else:
                    response = self.req_session.get(url, headers=headers, timeout=self.args.timeout, allow_redirects=self.args.follow_redirects)
            # Check for reflection of injected header or Set-Cookie in the response
            injected_header_seen = False
            set_cookie_injected = False
            raw_header_sample: dict[str, str] = {}
            evidence = ""
            for k, v in response.headers.items():
                # Look for our marker string in header names or values
                if "Injected" in k or "Injected" in v:
                    injected_header_seen = True
                    evidence = f"{k}: {v}"
                if k.lower() == "set-cookie" and "crlf=1" in v:
                    set_cookie_injected = True
                    evidence = f"Set-Cookie: {v}"
                # Sample a few headers for output clarity
                if k.lower() in ("set-cookie", "location", "content-type", "x-powered-by"):
                    raw_header_sample[k] = v
            # A vulnerability is confirmed if we see our injected header or cookie
            if injected_header_seen or set_cookie_injected:
                return Finding(
                    url=url,
                    method=method,
                    location=location,
                    parameter=parameter,
                    payload=payload,
                    status=response.status_code,
                    redirected=response.is_redirect,
                    evidence=evidence or "Header injected",
                    injected_header_seen=injected_header_seen,
                    set_cookie_injected=set_cookie_injected,
                    raw_header_sample=raw_header_sample,
                )
            return None
        except Exception:
            return None

    def scan(self, urls: List[str]) -> None:
        """High-scale scan with bounded in-flight queue for very large URL sets."""
        inflight: List[futures.Future] = []
        submit_count = 0

        def _maybe_drain() -> None:
            # Drain completed futures until we're under the cap
            nonlocal inflight
            if len(inflight) >= self.max_inflight:
                for done in futures.as_completed(inflight[:]):  # shallow copy to iterate safely
                    inflight.remove(done)
                    fnd = done.result()
                    if fnd:
                        with threading.Lock():
                            self.findings.append(fnd)
                    progress_update(self.job_id, 1)
                    if len(inflight) < self.max_inflight:
                        break

        # Estimate total tasks for progress bar and set total
        try:
            total_tasks = estimate_total_tasks(urls, self.payloads, getattr(self.args, "body_params", None))
            progress_set_total(self.job_id, total_tasks)
        except Exception:
            pass

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
            if getattr(self.args, "body_params", None):
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
            if fnd:
                with threading.Lock():
                    self.findings.append(fnd)
            progress_update(self.job_id, 1)

        self.thread_pool.shutdown(wait=True)
        # Summary printing is deferred to CLI; nothing to print here

    # ------------------------------------------------------------------
    # Raw request scanning utilities
    # ------------------------------------------------------------------
    def _send_raw(self, method: str, url: str, headers: Dict[str, str], body: Optional[str]):
        """
        Send a raw HTTP request using either httpx (for HTTP/2) or requests.

        Args:
            method: HTTP method (e.g. "GET", "POST").
            url: Full target URL.
            headers: Dictionary of request headers to send.
            body: Request body as a string or None.

        Returns:
            The response object from the underlying HTTP client.
        """
        # Use httpx for HTTP/2 on HTTPS targets when enabled
        if self.httpx_client and getattr(self.args, "http2", False) and url.lower().startswith("https"):
            return self.httpx_client.request(method, url, headers=headers, content=body, cookies=self.cookies)
        # Fallback to requests; include cookies and respect follow_redirects and timeout
        return self.req_session.request(
            method,
            url,
            headers=headers,
            data=body,
            cookies=self.cookies,
            allow_redirects=getattr(self.args, "follow_redirects", False),
            timeout=getattr(self.args, "timeout", 12),
        )

    def _evaluate_evidence(self, resp):
        """
        Examine an HTTP response for evidence of CRLF injection.

        Returns a tuple (injected_header, set_cookie, evidence_list, header_sample,
        status_code, redirected) where:
        - injected_header: True if an injected header (X-Injected-Canary) was seen.
        - set_cookie: True if an injected Set-Cookie was observed.
        - evidence_list: List of evidence strings.
        - header_sample: Truncated sample of headers for display.
        - status_code: HTTP status code.
        - redirected: True if status indicates a redirect (3xx).
        """
        try:
            status = resp.status_code
            headers = {k: v for k, v in resp.headers.items()}
        except Exception:
            # If the response is invalid, treat as no evidence
            return False, False, [], {}, 0, False
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
        try:
            cookiejar = getattr(resp, "cookies", [])
        except Exception:
            cookiejar = []
        if "crlf=1" in sc or any("crlf=1" in str(c) for c in cookiejar):
            set_cookie = True
            evidence.append("Injected Set-Cookie observed")
        hdr_sample = short_hdrs(headers)
        redirected = (300 <= status < 400)
        return injected, set_cookie, evidence, hdr_sample, status, redirected

    def _record_finding(
        self,
        url: str,
        method: str,
        location: str,
        param: str,
        payload: str,
        status: int,
        redirected: bool,
        ev_list: List[str],
        hdr_sample: Dict[str, str],
    ) -> Finding:
        """
        Build a Finding dataclass instance from the given parameters and evidence list.

        Args:
            url: The fully qualified URL that was tested.
            method: HTTP method used.
            location: Injection location ("query", "body", "path", "headers", or "template").
            param: Name of the parameter or "-" for path/template fuzzing.
            payload: The payload string used.
            status: HTTP status code returned by the server.
            redirected: True if the response was an HTTP redirect.
            ev_list: List of evidence strings describing the injection results.
            hdr_sample: Dictionary of truncated headers for display.

        Returns:
            A ``Finding`` instance populated with the given data.
        """
        evidence_str = "; ".join(ev_list) if ev_list else "(see response)"
        return Finding(
            url=url,
            method=method,
            location=location,
            parameter=param,
            payload=payload,
            status=status,
            redirected=redirected,
            evidence=evidence_str,
            injected_header_seen=("Saw X-Injected-Canary header" in ev_list),
            set_cookie_injected=("Injected Set-Cookie observed" in ev_list),
            raw_header_sample=hdr_sample,
        )

    def _scan_request_template(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[str],
    ) -> None:
        """
        Fuzz CRLF injection points in a parsed raw request.

        If the placeholder specified by ``args.req_placeholder`` exists in the URL,
        header values or body, it will be replaced with each payload. Otherwise,
        automatic fuzzing is performed by appending each payload to the path,
        each query parameter, and (for x-www-form-urlencoded bodies) each body
        parameter. Header values may also be fuzzed if ``--fuzz-headers`` is used.

        Generated requests are dispatched concurrently via the thread pool.
        """
        placeholder = getattr(self.args, "req_placeholder", None)
        # Check for placeholder in url, headers or body
        template_present = False
        if placeholder and placeholder in (url or ""):
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
        if template_present:
            # Simple template replacement: replace placeholder with each payload
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
            # Query parameter injection
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
            # Body injection (only for x-www-form-urlencoded content)
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
                            continue
                        mutated = dict(headers)
                        mutated[hk] = hv + payload
                        tasks.append((method, url, mutated, body, "headers", hk, payload))
        # If a progress bar is active, increment total tasks by number of tasks
        if self.job_id:
            with JOBS_LOCK:
                job = JOBS.get(self.job_id)
                if job:
                    job["total"] = job.get("total", 0) + len(tasks)
        # Submit tasks
        futs = []
        for (m, u, h, b, loc, param, payload) in tasks:
            if self.args.rate > 0:
                time.sleep(self.args.rate)
            fut = self.thread_pool.submit(self._one_request_try, m, u, h, b, loc, param, payload)
            futs.append(fut)
        # Gather results
        for fut in futures.as_completed(futs):
            fnd = fut.result()
            if fnd:
                with threading.Lock():
                    self.findings.append(fnd)
            progress_update(self.job_id, 1)

    def _one_request_try(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[str],
        location: str,
        param: str,
        payload: str,
    ) -> Optional[Finding]:
        """
        Send a single fuzzed request and evaluate evidence.

        Args:
            method: HTTP method (e.g. GET, POST).
            url: Full target URL.
            headers: Mapping of header names to values.
            body: Request body or None.
            location: Injection location identifier.
            param: Parameter name (for query/body/header fuzzing) or "-".
            payload: The payload string inserted.

        Returns:
            A ``Finding`` instance if a vulnerability is detected, otherwise None.
        """
        try:
            resp = self._send_raw(method, url, headers, body)
        except Exception:
            return None
        injected, set_cookie, ev, hdr_sample, status, redirected = self._evaluate_evidence(resp)
        if injected or set_cookie:
            return self._record_finding(url, method, location, param, payload, status, redirected, ev, hdr_sample)
        return None

    def scan_request_files(self, files: List[str], scheme: str) -> None:
        """
        Parse and fuzz raw HTTP request files for CRLF injection vulnerabilities.

        Each file should contain a full HTTP request with request line, headers
        and optional body (Burp/ZAP export style). The method builds and
        executes fuzzing tasks based on the presence of placeholders or by
        automatically injecting payloads into the path, query parameters,
        body parameters and header values. Findings are stored in
        ``self.findings``.

        Args:
            files: A list of file paths containing raw HTTP requests.
            scheme: The default scheme ("http" or "https") to use when a
                request line contains a relative path and a Host header.
        """
        # Estimate total tasks across all files for progress bar
        total_tasks = 0
        parsed_requests = []
        for fp in files:
            try:
                mth, url, hdrs, body = load_request_file(fp, scheme)
                # Merge base headers into parsed headers without overriding
                merged_headers: Dict[str, str] = dict(hdrs)
                for hk, hv in self.base_headers.items():
                    # Only add base header if not already present (case-insensitive)
                    if not any(hk.lower() == ek.lower() for ek in merged_headers.keys()):
                        merged_headers[hk] = hv
                parsed_requests.append((mth, url, merged_headers, body))
            except Exception as e:
                # Skip malformed files but continue scanning others
                print(f"[!] Could not parse {fp}: {e}", file=sys.stderr)
                continue
        # Set progress total tasks to sum of generated tasks per request
        if self.job_id:
            # Temporarily compute number of tasks per request by replicating logic
            for mth, url, headers, body in parsed_requests:
                placeholder = getattr(self.args, "req_placeholder", None)
                template_present = False
                if placeholder and placeholder in (url or ""):
                    template_present = True
                else:
                    for v in headers.values():
                        if placeholder and placeholder in v:
                            template_present = True
                            break
                    if not template_present and body:
                        if placeholder and placeholder in body:
                            template_present = True
                if template_present:
                    total_tasks += len(self.payloads)
                else:
                    # path injection: one task per payload
                    total_tasks += len(self.payloads)
                    # query injection: param count * payloads
                    qs = parse_qsl(urlparse(url).query, keep_blank_values=True)
                    if qs:
                        param_names = {k for k, _ in qs}
                        total_tasks += len(self.payloads) * len(param_names)
                    # body injection
                    ctype = ""
                    for hk, hv in headers.items():
                        if hk.lower() == "content-type":
                            ctype = hv.lower()
                            break
                    if body and "application/x-www-form-urlencoded" in ctype:
                        body_pairs = parse_qsl(body, keep_blank_values=True)
                        param_names = {k for k, _ in body_pairs}
                        total_tasks += len(self.payloads) * 1  # treat combined body params as one injection
                    # header fuzzing
                    if getattr(self.args, "fuzz_headers", False):
                        # Each header (except Host) * each payload is a task
                        hdr_count = sum(1 for hk in headers if hk.lower() != "host")
                        total_tasks += len(self.payloads) * hdr_count
            progress_set_total(self.job_id, total_tasks)
        # Now perform fuzzing for each parsed request
        for (mth, url, hdrs, body) in parsed_requests:
            self._scan_request_template(mth, url, hdrs, body)
        # Shut down the thread pool and wait for tasks to complete
        self.thread_pool.shutdown(wait=True)

    def smuggle_h2_scan(self, urls: List[str]) -> None:
        """
        Perform HTTP/2 to HTTP/1 CRLF smuggling detection against each URL.

        This technique is specific to front-ends that speak HTTP/2 and
        downgrade to HTTP/1, mishandling embedded CRLF sequences in the
        :path pseudo-header. The method crafts a single HTTP/2 request with
        a malicious :path containing a CRLF injection to smuggle a second
        HTTP/1 request. A follow-up request to a unique canary path
        confirms whether the smuggled request executed. If the follow-up
        returns a non-error status (status < 400), a Finding is recorded.

        Args:
            urls: List of target URLs to test for smuggling via CRLF injection.
        """
        # Count tasks (one per URL) for progress bar
        if self.job_id:
            progress_set_total(self.job_id, len(urls))
        for target in urls:
            target = (target or "").strip()
            if not target:
                progress_update(self.job_id, 1)
                continue
            try:
                # Only HTTPS supports HTTP/2 with ALPN negotiation
                parsed = urlparse(target)
                if parsed.scheme.lower() != "https":
                    # Skip non-HTTPS targets
                    progress_update(self.job_id, 1)
                    continue
                host = parsed.hostname
                port = parsed.port or 443
                base_path = parsed.path if parsed.path else "/"
                # Generate a unique canary path or use provided one
                if getattr(self.args, "canary_path", None):
                    canary = self.args.canary_path
                else:
                    canary_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
                    canary = f"/__crlf_canary_{canary_id}"
                # Build injected path with encoded CRLF sequences
                injection = f"{base_path}?q=1%0d%0a%0d%0aGET {canary} HTTP/1.1%0d%0aHost: {host}%0d%0a%0d%0a"
                # Prepare TLS context with ALPN 'h2'
                context = ssl.create_default_context()
                try:
                    context.set_alpn_protocols(["h2"])
                except Exception:
                    pass
                saw_canary_status: Optional[int] = None
                # Establish connection and send frames
                with socket.create_connection((host, port), timeout=getattr(self.args, "timeout", 12)) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as tls:
                        try:
                            negotiated = tls.selected_alpn_protocol()
                        except Exception:
                            negotiated = None
                        if negotiated != "h2":
                            progress_update(self.job_id, 1)
                            continue
                        # Initialize h2 connection
                        conn = h2.connection.H2Connection()
                        conn.initiate_connection()
                        tls.sendall(conn.data_to_send())
                        # Send malicious request on stream 1
                        stream_id = conn.get_next_available_stream_id()
                        headers = [
                            (":method", "GET"),
                            (":authority", host),
                            (":scheme", parsed.scheme),
                            (":path", injection),
                        ]
                        conn.send_headers(stream_id, headers, end_stream=True)
                        tls.sendall(conn.data_to_send())
                        # Send follow-up canary request on new stream
                        stream_canary = conn.get_next_available_stream_id()
                        headers2 = [
                            (":method", "GET"),
                            (":authority", host),
                            (":scheme", parsed.scheme),
                            (":path", canary),
                        ]
                        conn.send_headers(stream_canary, headers2, end_stream=True)
                        tls.sendall(conn.data_to_send())
                        # Receive responses and look for canary status
                        try:
                            while True:
                                data = tls.recv(65535)
                                if not data:
                                    break
                                events = conn.receive_data(data)
                                for ev in events:
                                    if isinstance(ev, h2.events.ResponseReceived) and ev.stream_id == stream_canary:
                                        for name, val in ev.headers:
                                            if name == ":status":
                                                try:
                                                    saw_canary_status = int(val)
                                                except Exception:
                                                    saw_canary_status = None
                                                break
                                if saw_canary_status is not None:
                                    break
                        except Exception:
                            # Ignore errors during reception
                            pass
                # Evaluate result: status < 400 indicates vulnerability
                if saw_canary_status is not None and saw_canary_status < 400:
                    evidence = f"h2 smuggle probe: follow-up GET {canary} returned {saw_canary_status}"
                    fnd = Finding(
                        url=target,
                        method="GET",
                        location=":path",
                        parameter="-",
                        payload="HTTP/2 :path CRLF smuggle",
                        status=saw_canary_status,
                        redirected=False,
                        evidence=evidence,
                        injected_header_seen=True,
                        set_cookie_injected=False,
                        raw_header_sample={},
                    )
                    self.findings.append(fnd)
                progress_update(self.job_id, 1)
            except Exception:
                # Any unexpected error should still update progress
                progress_update(self.job_id, 1)
                continue



def program_main(argv: List[str] | None = None) -> None:
    """Entry point for running CRLF Hunter from code or CLI.

    This function constructs the argument parser, processes CLI arguments,
    orchestrates scanning and output generation, and optionally starts the
    FastAPI web UI. It returns ``None`` and prints output to stdout/stderr.

    Args:
        argv: Optional list of argument strings to parse. When ``None`` (the
            default), ``sys.argv[1:]`` is used.
    """
    # Build argument parser
    ap = argparse.ArgumentParser(
        description="CRLF Hunter – High-coverage CRLF injection scanner with optional Web UI",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Scan a big list with outputs\n"
            "  crlfhunter --url-file urls.txt --out-json findings.json --out-csv findings.csv -t 160\n\n"
            "  # Launch Web UI on localhost:8965\n"
            "  crlfhunter --ui\n\n"
            "  # Ask to launch UI if no inputs provided\n"
            "  crlfhunter --ask-ui\n\n"
            "  # h2 smuggling probe\n"
            "  crlfhunter --smuggle-h2 https://target.tld --out-json smuggle.json\n"
        )
    )
    # Positional URLs
    ap.add_argument("url", nargs="*", help="Target URL(s) to scan (include scheme)")
    # Target list file
    ap.add_argument("--url-file", action="append", help="Path to a .txt or .gz file with URLs (one per line). Can be used multiple times.")
    ap.add_argument("--assume-scheme", choices=["http", "https"], default="https", help="If a URL lacks a scheme, prepend this (used for --url-file and UI).")
    ap.add_argument("--max-inflight", type=int, default=0, help="Max queued requests in flight (0 = auto: threads*50). Controls RAM on huge lists.")
    # Output options
    ap.add_argument("--out-json", help="Write findings to a JSON file.")
    ap.add_argument("--out-csv", help="Write findings to a CSV file.")
    # UI options
    ap.add_argument("--ui", action="store_true", help="Launch the local Web UI (FastAPI) on 127.0.0.1:PORT.")
    ap.add_argument("--ui-port", type=int, default=8965, help="Port for the Web UI (use with --ui).")
    ap.add_argument("--ask-ui", action="store_true", help="If no inputs are provided, interactively ask to start the Web UI.")
    # Smuggling & HTTP/2
    ap.add_argument("--smuggle-h2", action="store_true", help="Enable HTTP/2 smuggling probe (--smuggle-h2) or normal scanning otherwise.")
    ap.add_argument("--http2", action="store_true", help="Send requests using HTTP/2 where supported.")
    # Fuzz options
    ap.add_argument("--fuzz-headers", action="store_true", help="Fuzz header values for CRLF injection.")
    ap.add_argument("--follow-redirects", action="store_true", help="Follow HTTP redirects during scanning.")
    ap.add_argument("-t", "--threads", type=int, default=40, help="Number of concurrent threads.")
    ap.add_argument("--timeout", type=int, default=12, help="HTTP timeout per request (seconds).")
    ap.add_argument("--retries", type=int, default=2, help="Number of retry attempts for failed requests.")
    ap.add_argument("--backoff", type=float, default=0.25, help="Backoff factor for retry delays (seconds).")
    ap.add_argument("--rate", type=float, default=0.0, help="Rate limit (seconds per request). 0 disables throttling.")
    # Parameter injection options
    ap.add_argument("--body-params", help="Comma-separated body parameters to fuzz.")
    ap.add_argument("--payloads", help="Path to custom payload list file. Overrides built-in payloads.")
    # Headers, cookies, auth & proxy
    ap.add_argument("-H", "--header", action="append", default=[], help="Add a custom header to all requests (e.g. 'Header: Value').")
    ap.add_argument("-C", "--cookie", action="append", default=[], help="Add a cookie to all requests (e.g. 'SESSIONID=abcd').")
    ap.add_argument("--auth", help="Quick auth helper: basic:user:pass | bearer:TOKEN | raw:Name: Value.")
    ap.add_argument("--proxy", help="Use an HTTP proxy (e.g. http://127.0.0.1:8080).")
    ap.add_argument("--login-url", help="URL to send a login request to before scanning.")
    ap.add_argument("--login-data", help="POST data for login (e.g. 'username=admin&password=pass').")
    # Request file options
    ap.add_argument("--request-file", action="append", help="Raw HTTP request file(s) to scan. Each file can contain a placeholder for payload insertion.")
    ap.add_argument("--req-scheme", choices=["http", "https"], default="https", help="Default scheme for request-file URLs (if relative).")
    ap.add_argument("--req-placeholder", default="{{CRLF}}", help="Placeholder token in request-file to replace with payload.")
    ap.add_argument("--canary-path", help="Custom path for the follow-up request used in HTTP/2 smuggling detection.")
    # Misc
    ap.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")

    # Parse arguments
    parsed_args = ap.parse_args(argv if argv is not None else None)

    # Print banner
    banner = (
        "\nCRLF Hunter - Defcon-Level Edition\n"
        "------------------------------------"
    )
    print(banner)

    # Expand URL set from --url-file (if any) and positional arguments
    all_urls: List[str] = list(parsed_args.url or [])
    if parsed_args.url_file:
        file_urls = load_urls_from_files(parsed_args.url_file, parsed_args.assume_scheme)
        all_urls.extend(file_urls)

    # Optionally ask to launch UI if no targets provided
    if not all_urls and not parsed_args.request_file and (parsed_args.ask_ui or parsed_args.ui):
        if parsed_args.ui or (parsed_args.ask_ui and input("Launch Web UI on port %d? [Y/n] " % parsed_args.ui_port).strip().lower() in ("", "y", "yes")):
            if FastAPI is None:
                print("[-] FastAPI not installed. Run: pip install fastapi uvicorn", file=sys.stderr)
                sys.exit(1)
            app = build_app()
            print(f"[+] Web UI on http://127.0.0.1:{parsed_args.ui_port}")
            uvicorn.run(app, host="127.0.0.1", port=parsed_args.ui_port)
            return

    # Explicit UI flag overrides normal scanning
    if parsed_args.ui:
        if FastAPI is None:
            print("[-] FastAPI not installed. Run: pip install fastapi uvicorn", file=sys.stderr)
            sys.exit(1)
        app = build_app()
        print(f"[+] Web UI on http://127.0.0.1:{parsed_args.ui_port}")
        uvicorn.run(app, host="127.0.0.1", port=parsed_args.ui_port)
        return

    # Require at least something for CLI mode
    if not all_urls and not parsed_args.request_file:
        ap.print_usage()
        print("[-] Error: Provide URLs/--url-file or a --request-file (or run with --ui).", file=sys.stderr)
        sys.exit(1)

    # Initialise engine
    engine = Engine(parsed_args)
    # Set job_id to None since CLI does not track progress via web
    engine.job_id = None

    # Handle different modes: request file, smuggle h2, or normal scan
    if parsed_args.request_file:
        engine.scan_request_files(parsed_args.request_file, parsed_args.req_scheme)
        for find in engine.findings:
            print(f"[!] Vulnerable: {find.url} ({find.parameter}) payload='{find.payload}'")
            print(f"    ==> Evidence: {find.evidence}")
        print(f"[+] Scan completed in {time.time() - engine.start_time:.2f} seconds. Findings: {len(engine.findings)}")
        if parsed_args.out_json:
            write_findings_json(parsed_args.out_json, engine.findings)
            print(f"[+] Wrote JSON findings: {parsed_args.out_json}")
        if parsed_args.out_csv:
            write_findings_csv(parsed_args.out_csv, engine.findings)
            print(f"[+] Wrote CSV findings: {parsed_args.out_csv}")

    elif parsed_args.smuggle_h2:
        try:
            engine.smuggle_h2_scan(all_urls)
        except Exception as e:
            print(f"[!] Smuggle scan failed: {e}", file=sys.stderr)
        print(f"[+] Smuggle scan completed.")
        if parsed_args.out_json:
            write_findings_json(parsed_args.out_json, engine.findings)
            print(f"[+] Wrote JSON findings: {parsed_args.out_json}")
        if parsed_args.out_csv:
            write_findings_csv(parsed_args.out_csv, engine.findings)
            print(f"[+] Wrote CSV findings: {parsed_args.out_csv}")

    else:
        engine.scan(all_urls)
        for find in engine.findings:
            print(f"[!] Vulnerable: {find.url} ({find.parameter}) payload='{find.payload}'")
            print(f"    ==> Evidence: {find.evidence}")
        print(f"[+] Scan completed in {time.time() - engine.start_time:.2f} seconds. Findings: {len(engine.findings)}")
        if parsed_args.out_json:
            write_findings_json(parsed_args.out_json, engine.findings)
            print(f"[+] Wrote JSON findings: {parsed_args.out_json}")
        if parsed_args.out_csv:
            write_findings_csv(parsed_args.out_csv, engine.findings)
            print(f"[+] Wrote CSV findings: {parsed_args.out_csv}")


if __name__ == "__main__":
    # When executed as a script, run the program_main with default argument parsing
    program_main()