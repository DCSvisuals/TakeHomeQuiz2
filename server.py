#!/usr/bin/env python3
"""Local website for the CST8808 Quiz 2 iptables parser.

The page stays on this computer. Edge, Chrome, Safari, and Firefox can open it.
parse_iptables.py does the parsing. This file only serves the page and the report.
"""

import json
import socketserver
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from parse_iptables import DEFAULT_LOG, analyze

HOST = "127.0.0.1"
DEFAULT_PORT = 8808
MAX_BODY = 2 * 1024 * 1024
HERE = Path(__file__).resolve().parent
LOG_SUFFIXES = {".log", ".txt"}
CSP = (
    "default-src 'none'; "
    "style-src 'unsafe-inline'; "
    "script-src 'unsafe-inline'; "
    "connect-src 'self'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)


def clean_name(name):
    if not isinstance(name, str) or not name.strip():
        return "uploaded.log"
    base = Path(name.replace("\\", "/")).name.strip()
    if not base or base in {".", ".."}:
        return "uploaded.log"
    return base[:120]


def log_files():
    """Names of .log and .txt files that sit directly in the program folder."""
    root = HERE.resolve()
    found = []
    for path in root.iterdir():
        if not path.is_file() or path.suffix.lower() not in LOG_SUFFIXES:
            continue
        resolved = path.resolve()
        if resolved.parent != root:
            continue
        found.append(path.name)
    found.sort(key=lambda item: (item != DEFAULT_LOG.name, item.lower()))
    return found


def read_named_log(name):
    if not isinstance(name, str) or not name.strip():
        return 400, {"error": "Choose a log from the list."}
    cleaned = Path(name.replace("\\", "/")).name
    if cleaned not in log_files():
        return 404, {"error": "That log is not in the program folder. Upload it from this page."}
    path = (HERE / cleaned).resolve()
    root = HERE.resolve()
    if path.parent != root or not path.is_file():
        return 404, {"error": "That log is not in the program folder."}
    try:
        if path.stat().st_size > MAX_BODY:
            return 413, {"error": "That file is too large. Keep the log under 2 MB."}
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return 500, {"error": f"Could not read {cleaned}: {exc}"}
    return 200, analyze(text, cleaned)


def report_for_default_log():
    if DEFAULT_LOG.name in log_files():
        return read_named_log(DEFAULT_LOG.name)
    return 404, {
        "error": "iptables.log was not found in the program folder. Upload a log from the page.",
    }


def report_for_upload(raw):
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return 400, {"error": "The upload was not valid JSON."}
    if not isinstance(payload, dict):
        return 400, {"error": "The upload was not a log file."}
    text = payload.get("text")
    if not isinstance(text, str):
        return 400, {"error": "The upload did not include log text."}
    if not text.strip():
        return 400, {"error": "The file is empty."}
    return 200, analyze(text, clean_name(payload.get("name")))


class QuizServer(ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self):
        # HTTPServer looks up the hostname for 127.0.0.1. On this Mac that
        # reverse lookup can stall, so the local name is set directly.
        socketserver.TCPServer.server_bind(self)
        _host, port = self.server_address[:2]
        self.server_name = "localhost"
        self.server_port = port


class QuizHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return
        if path == "/api/logs":
            self._send_json(200, {"logs": [{"name": name} for name in log_files()]})
            return
        if path == "/api/report":
            chosen = query.get("name", [None])[0]
            if chosen:
                status, payload = read_named_log(chosen)
            else:
                status, payload = report_for_default_log()
            self._send_json(status, payload)
            return
        if path in {"/", "/index.html"}:
            self._send_page()
            return
        self._send_html(
            404,
            "<!DOCTYPE html><html lang='en'><meta charset='utf-8'><title>Not found</title>"
            "<p>That page is not part of the quiz tool. <a href='/'>Back to the parser.</a></p>",
        )

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path != "/api/report":
            self._send_json(404, {"error": "That address is not part of the quiz tool."})
            return
        content_type = self.headers.get("Content-Type", "")
        if not content_type.startswith("application/json"):
            self._send_json(415, {"error": "Open the log from the page."})
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._send_json(411, {"error": "The upload did not include a length."})
            return
        if length < 0 or length > MAX_BODY:
            self.close_connection = True
            self._send_json(413, {"error": "That file is too large. Keep the log under 2 MB."})
            return
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        status, payload = report_for_upload(raw)
        self._send_json(status, payload)

    def _send_page(self):
        page = HERE / "index.html"
        if not page.is_file():
            self._send_html(500, "<p>index.html is missing from the program folder.</p>")
            return
        data = page.read_bytes()
        self._send_bytes(200, data, "text/html; charset=utf-8")

    def _send_json(self, status, payload):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send_bytes(status, data, "application/json; charset=utf-8")

    def _send_html(self, status, html):
        self._send_bytes(status, html.encode("utf-8"), "text/html; charset=utf-8")

    def _send_bytes(self, status, data, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def parse_args(argv):
    """Return (port, open_browser). A bare number chooses the port."""
    open_browser = False
    port = DEFAULT_PORT
    for arg in argv:
        if arg == "--open":
            open_browser = True
            continue
        if arg.isdigit() and 1 <= int(arg) <= 65535:
            port = int(arg)
            continue
        raise SystemExit(
            "Usage: python3 server.py [port] [--open]\n"
            f"Example: python3 server.py {DEFAULT_PORT} --open"
        )
    return port, open_browser


def main(argv):
    try:
        port, open_browser = parse_args(argv[1:])
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return 1
    try:
        httpd = QuizServer((HOST, port), QuizHandler)
    except OSError as exc:
        print(f"Could not listen on http://{HOST}:{port}")
        print("The usual cause is that the website is already open in another window.")
        print("Close that window, or pick another port:")
        print(f"python3 server.py {port + 1} --open")
        print(exc)
        return 1
    url = f"http://{HOST}:{port}"
    print(f"CST8808 Quiz 2 iptables parser: {url}", flush=True)
    print("Leave this window open. Closing it stops the website.", flush=True)
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
