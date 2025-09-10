# CRLF Hunter

A fast and flexible **CRLF injection scanner** that can handle thousands of URLs with ease.
Includes **Web UI, supports HTTP/2 → HTTP/1 smuggling checks,
and generates clean CSV/JSON reports** you can actually use.

> **Author**: DeathReaper  
> **License**: MIT  
> **Disclaimer**: This tool is made for ethical security testing only. Do
> **not** use it for illegal activity. The author is **not responsible** for
> misuse or any resulting damage.

---

## What it does

CRLF Hunter is a comprehensive tool for discovering HTTP header injection
vulnerabilities via CRLF sequences. It can fuzz web applications via URL
parameters, form bodies, path segments, header fields, and even **raw
HTTP requests**. It also detects **HTTP/2 → HTTP/1 request smuggling** via
malicious ``:path`` headers.

Key capabilities include:

* **CRLF injection fuzzing** across **query parameters**, **form bodies**, and
  **URL paths**. The built‑in payload list covers common encodings
  (percent‑encoding, double encoding, Unicode) and CRLF variations.
* **Raw request scanning**: supply Burp/ZAP‑style request files with
  placeholders (default `{{CRLF}}`) or let the tool automatically fuzz
  paths, query params, bodies and header values when no placeholder is
  present. Supports multiple request files and header fuzzing with
  `--fuzz-headers`.
* **Huge URL lists**: stream-friendly, bounded in‑flight queue so it stays
  fast **and** memory‑safe with tens of thousands of targets. Use
  `--url-file` to read `.txt` or `.gz` lists directly.
* **HTTP/2 smuggling detection**: enable with `--smuggle-h2` to check for
  CRLF smuggling across HTTP/2→HTTP/1 downgrades (works with HTTPS hosts).
* **JSON/CSV outputs** for reporting and triage. Use `--out-json` and
  `--out-csv` to write findings to disk.
* **Optional Web UI** (FastAPI) with a tidy two‑column form, a **live
  progress bar** and **Download JSON/CSV** buttons when finished. Toggle the UI with
  `--ui` or `--ask-ui`.
* **Header fuzzing** (optional) and CDN/WAF bypass headers built in.
* **HTTP/2 mode** (via `httpx`) and `--http2` flag to send requests over
  HTTP/2 where supported.
* **Authentication support**: simple login flow and quick helpers for
  Basic/Bearer auth tokens (`--auth`), custom headers (`-H`), cookies
  (`-C`), and proxies (`--proxy`).
* **Rate limiting**, retries/backoff, thread pool control, and memory
  safety via `--max-inflight`.

---

## Install

```
git clone https://github.com/Ghufran2/CRLF-Hunter.git
cd CRLF-Hunter/
sudo apt install -y python3-venv
(if you're on 3.13 and this fails, try: sudo apt install -y python3.13-venv)

python3 -m venv .venv
source .venv/bin/activate
pip install -U pip setuptools wheel
pip install .
pip install python-multipart (Needed for the UI)

# or for editable development:
pip install -e .
```

After installation you can run the tool anywhere using the `crlfhunter`
command.

---

## Quick start (CLI)

```
# Scan a single URL
crlfhunter https://example.com/?q=test

# Scan a list from file (txt or .gz)
crlfhunter --url-file urls.txt --out-json findings.json --out-csv findings.csv -t 160

# Fuzz raw request files (Burp/ZAP export)
crlfhunter --request-file attack.req --req-placeholder {{CRLF}} --fuzz-headers --out-json raw.json

# HTTP/2 smuggling probe
crlfhunter --smuggle-h2 https://target.tld --out-json smuggle.json
```

### Useful flags

- `--url-file <file>`: txt/gz list (one URL per line). You can specify
  multiple files.
- `--assume-scheme https|http`: prepended to scheme‑less entries in lists.
- `--out-json`, `--out-csv`: write reports.
- `--threads`, `--timeout`, `--retries`, `--backoff`, `--rate`: performance
  controls.
- `--max-inflight N`: cap queued tasks to keep memory flat on huge lists.
- `--http2`, `--fuzz-headers`, `--follow-redirects`, `--proxy <url>`.
- `--body-params`: comma-separated names for POST body fuzzing.
- `--login-url` + `--login-data`: perform a login request before scanning.
- `--ask-ui`: prompt to launch the UI when you run without targets.
- `--ui` / `--ui-port`: run the FastAPI interface (default port 8965).

Run `crlfhunter --help` for a complete list of options with defaults and
examples.

---

## Web UI

CRLF Hunter exposes a simple web interface for local use. The UI
supports everything available in the CLI, including raw request fuzzing and
smuggling tests.

```
# Default localhost:8965
crlfhunter --ui

# Custom port
crlfhunter --ui --ui-port 7777

# Prompt to open the UI when no targets are provided
crlfhunter --ask-ui
```

Features of the UI:

* Two-column layout for entering target URLs or uploading URL lists and
  request files.
* Upload `.txt` or `.gz` lists and specify default schemes.
* Upload raw request files (Burp/ZAP) to scan them directly—placeholder
  replacement and automatic fuzzing are both supported, including header
  fuzzing when enabled.
* Fields for headers, cookies, body parameters, authentication, rate
  control, smuggle test toggle, and more.
* **Live progress bar** with percentage while your scan runs.
* **Download JSON** / **Download CSV** buttons when the scan finishes.

---

## Output

When you specify `--out-json` and/or `--out-csv`, the tool writes
reports containing all confirmed findings:

- **JSON**: a list of objects with fields such as URL, method, location,
  parameter, payload, HTTP status, evidence and header sample.
- **CSV**: one finding per row; header samples are JSON-encoded into a
  single cell.

Example summary output:

```
[!] Vulnerable: https://example.com/profile?user=evil (parameter: user) payload='%0D%0ASet-Cookie:crlf=1'
    ==> Evidence: Set-Cookie header injected successfully
[+] Scan completed in 12.34 seconds. Findings: 1
[+] Wrote JSON findings: findings.json
[+] Wrote CSV findings: findings.csv
```

---

## Notes on safety

This tool is intended for **authorized** security testing only. Always
obtain explicit permission before scanning targets. Misuse may be
illegal and subject to penalties. The authors provide no warranty.

---

## License & Attribution

This project is distributed under the MIT License (see `LICENSE`).

Developed by **DeathReaper**. Please attribute appropriately if you
fork or publish derivative works.
