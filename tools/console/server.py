#!/usr/bin/env python3
"""Helmet Duck Console: a local, read-only web view of the live site.

Binds to 127.0.0.1 only, answers GET only, refuses any other Host header, and
serves three static files plus two JSON routes:

  /api/ping                       identity: name, version, running revision
  /api/snapshot?days=7&refresh=1  the evidence (cached 55 seconds per window)

It never deploys, never changes AWS, never writes to the site. Its only writes are
the log mirror and a few cache files under .console-cache/, which is ignored by git.

    python3 tools/console/server.py [--port 4318] [--no-open]

The launcher, helmet-duck-console-start.command, runs it as a background job and
proves its identity and revision before reusing or stopping it.
"""
import json
import os
import pathlib
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import analytics  # noqa: E402
from version import CONSOLE_NAME, CONSOLE_VERSION  # noqa: E402

WEB = HERE / "web"
FILES = {"/": "index.html", "/index.html": "index.html", "/app.js": "app.js", "/styles.css": "styles.css"}
MIME = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8"}
CACHE_S = 55
REVISION = os.environ.get("HELMET_DUCK_CONSOLE_REVISION", "development")[:64]

_cache = {}
_lock = threading.Lock()


def snapshot(days, force=False):
    with _lock:
        hit = _cache.get(days)
        if hit and not force and time.time() - hit[0] < CACHE_S:
            return hit[1]
    value = analytics.build_snapshot(days)
    with _lock:
        _cache[days] = (time.time(), value)
    return value


class Handler(BaseHTTPRequestHandler):
    server_version = "HelmetDuckConsole/" + CONSOLE_VERSION

    def log_message(self, fmt, *args):  # quiet; the launcher keeps a log of its own
        pass

    def _send(self, status, ctype, body):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status, obj):
        self._send(status, "application/json; charset=utf-8", json.dumps(obj).encode())

    def do_GET(self):
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        if host not in ("127.0.0.1", "localhost"):
            return self._json(403, {"error": "local console: invalid Host"})
        url = urlsplit(self.path)
        if url.path == "/api/ping":
            return self._json(200, {"ok": True, "name": CONSOLE_NAME, "version": CONSOLE_VERSION, "revision": REVISION})
        if url.path == "/api/snapshot":
            q = parse_qs(url.query)
            try:
                days = min(30, max(1, int(q.get("days", ["7"])[0])))
            except ValueError:
                days = 7
            try:
                body = dict(snapshot(days, q.get("refresh", ["0"])[0] == "1"), console={"name": CONSOLE_NAME, "version": CONSOLE_VERSION, "revision": REVISION})
                return self._json(200, body)
            except Exception as exc:  # noqa: BLE001  the page shows the words instead of dying
                return self._json(500, {"error": str(exc)[:240]})
        name = FILES.get(url.path)
        if not name:
            return self._send(404, "text/plain; charset=utf-8", b"Not found")
        path = WEB / name
        return self._send(200, MIME.get(path.suffix, "application/octet-stream"), path.read_bytes())

    def do_POST(self):
        self._json(405, {"error": "read-only console: GET only"})

    do_PUT = do_DELETE = do_PATCH = do_POST


def main():
    args = sys.argv[1:]
    port = 4318
    if "--port" in args:
        port = max(1024, min(65535, int(args[args.index("--port") + 1])))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = "http://127.0.0.1:%d" % port
    print("\n%s\n%s\n\nRead-only, local to this Mac, Ctrl+C to stop\n" % (CONSOLE_NAME, url), flush=True)
    if "--no-open" not in args and sys.platform == "darwin":
        subprocess.Popen(["open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except OSError as exc:
        print("helmet-duck-console-start: %s" % exc, file=sys.stderr)
        sys.exit(1)
