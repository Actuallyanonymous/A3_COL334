#!/usr/bin/env python3
"""HTTP/1.1 server. Files come from a directory, bytes go out over our TCP.

    sudo ./server/run-server [-p PORT] [-d DOCROOT] [--log LOGFILE]

Defaults are port 8080 and docroot ./www. One connection at a time,
forever, until the process is killed. A client that misbehaves closes
that connection and the server keeps listening.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time

from tcp_conn import TCPEndpoint, TCPError, TCPTimeout

# METHOD SP TARGET SP HTTP/x.y
# Token characters are the ones RFC 9110 allows in a method.
_REQUEST_RE = re.compile(
    r"^([!#$%&'*+\-.0-9A-Z^_`a-z|~]+) ([^ ]+) (HTTP/[0-9]+\.[0-9]+)$"
)

_CONTENT_TYPES = {
    ".html": "text/html",
    ".htm": "text/html",
    ".txt": "text/plain",
    ".css": "text/css",
    ".js": "application/javascript",
    ".json": "application/json",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".pdf": "application/pdf",
}

_REASONS = {
    200: "OK",
    400: "Bad Request",
    403: "Forbidden",
    404: "Not Found",
    501: "Not Implemented",
}


def content_type(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    return _CONTENT_TYPES.get(ext, "application/octet-stream")


def _error_page(code: int) -> bytes:
    reason = _REASONS[code]
    page = (
        f"<html><head><title>{code} {reason}</title></head>"
        f"<body><h1>{code} {reason}</h1></body></html>\n"
    )
    return page.encode("ascii")


def _wire(code: int, body: bytes, ctype: str, send_body: bool) -> bytes:
    """Headers every response carries. HEAD gets the same headers and no body."""
    reason = _REASONS[code]
    head = (
        f"HTTP/1.1 {code} {reason}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Content-Type: {ctype}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("ascii")
    if send_body:
        return head + body
    return head


def _map_path(docroot: str, target: str) -> tuple[int, bytes, str]:
    """Table 4, steps 3–5. Steps 1 and 2 already rejected the request line.

    The query string is not part of the filename. A path that ends in /
    or names a directory serves index.html inside it. Percent-decoding
    is not required, so "%2e%2e" is an ordinary name, not "..".
    """
    path = target.split("?", 1)[0]
    # A ".." segment is Forbidden even when the file would not exist.
    if ".." in path.split("/"):
        return 403, _error_page(403), "text/html"

    root = os.path.realpath(docroot)
    relative = path.lstrip("/")
    full = os.path.realpath(os.path.join(root, relative))
    if full != root and not full.startswith(root + os.sep):
        return 403, _error_page(403), "text/html"
    if os.path.isdir(full):
        full = os.path.join(full, "index.html")
    if not os.path.isfile(full):
        return 404, _error_page(404), "text/html"
    try:
        with open(full, "rb") as handle:
            data = handle.read()
    except OSError:
        return 403, _error_page(403), "text/html"
    return 200, data, content_type(full)


def response_for(head: bytes, docroot: str) -> bytes:
    """Turn a request head (bytes before the blank line) into a response."""
    text = head.decode("iso-8859-1", errors="replace")
    request_line = text.split("\r\n", 1)[0]
    match = _REQUEST_RE.match(request_line)
    if match is None or not match.group(2).startswith("/"):
        return _wire(400, _error_page(400), "text/html", True)
    method, target, _version = match.group(1), match.group(2), match.group(3)
    if method not in ("GET", "HEAD"):
        return _wire(501, _error_page(501), "text/html", True)
    code, body, ctype = _map_path(docroot, target)
    return _wire(code, body, ctype, send_body=(method == "GET"))


def _read_request_head(conn, deadline: float) -> bytes:
    """Bytes before the header/body separator. Raises if it is not here in time."""
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        if len(buf) > 1024 * 1024:
            raise TCPError("request head too large")
        chunk = conn.recv_some(max_bytes=4096, idle=10.0, hard_deadline=deadline)
        if not chunk:
            raise TCPError("client closed before the request head")
        buf.extend(chunk)
    end = buf.find(b"\r\n\r\n")
    return bytes(buf[:end])


def serve_connection(conn, docroot: str) -> None:
    """One request, one response, then the caller closes (T9).

    An unfinished request head within 10s produces no response at all.
    """
    try:
        head = _read_request_head(conn, time.monotonic() + 10.0)
    except (TCPError, TCPTimeout):
        return
    conn.send_all(response_for(head, docroot))


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="run-server", add_help=True)
    parser.add_argument("-p", dest="port", type=int, default=8080)
    parser.add_argument("-d", dest="docroot", default="./www")
    parser.add_argument("--log", dest="logfile", default=None)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("port must be 1-65535")
    return args


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    log_fh = None
    endpoint = None
    try:
        if args.logfile:
            log_fh = open(args.logfile, "w", encoding="ascii", buffering=1)
        endpoint = TCPEndpoint(log_file=log_fh)
        while True:
            try:
                conn = endpoint.accept(args.port)
            except KeyboardInterrupt:
                break
            try:
                serve_connection(conn, args.docroot)
            except KeyboardInterrupt:
                break
            except Exception:
                # A broken or rude client ends this connection, not the process.
                pass
            finally:
                try:
                    conn.close()
                except TCPError:
                    pass
    except KeyboardInterrupt:
        pass
    finally:
        if endpoint is not None:
            endpoint.close()
        if log_fh is not None:
            log_fh.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
