#!/usr/bin/env python3
"""HTTP/1.1 client. One GET per run, carried by our own TCP.

    sudo ./client/run-client URL [-o OUTFILE] [--log LOGFILE]

The response body goes to OUTFILE, or to stdout when -o is omitted.
The status line goes to stderr. Exit 0 on a complete 2xx, 1 on any
other complete status (the body is still saved, redirects are not
followed), and 2 when the response never arrives in one piece.
"""

from __future__ import annotations

import argparse
import re
import socket
import sys
from dataclasses import dataclass

from tcp_conn import TCPEndpoint, TCPError, TCPReset, TCPTimeout

# http://HOST[:PORT][/PATH]   PATH may contain a query string.
_URL_RE = re.compile(r"^http://([^/@]+)(/.*)?$")


@dataclass
class Url:
    host: str
    port: int
    path: str
    # Host header, exactly the authority as it was written in the URL.
    host_header: str


def parse_url(text: str) -> Url:
    match = _URL_RE.match(text)
    if not match:
        raise ValueError("invalid url")
    authority = match.group(1)
    path = match.group(2) or "/"
    if authority.count(":") > 1:
        raise ValueError("invalid url")
    if ":" in authority:
        host, port_text = authority.rsplit(":", 1)
        if not port_text.isdigit():
            raise ValueError("invalid url")
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise ValueError("invalid url")
    else:
        host = authority
        port = 80
    if not host:
        raise ValueError("invalid url")
    return Url(host, port, path, authority)


def build_request(url: Url) -> bytes:
    """One HTTP/1.1 GET. No Accept-Encoding, so the body is not compressed."""
    return (
        f"GET {url.path} HTTP/1.1\r\n"
        f"Host: {url.host_header}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("ascii")


def resolve_ipv4(host: str, port: int) -> str:
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        raise TCPError("dns failure") from exc
    if not infos:
        raise TCPError("dns failure")
    return infos[0][4][0]


class ByteStream:
    """A byte buffer in front of a TCP connection.

    Headers and body often arrive in the same segment. Bytes past the
    header stay here and are the start of the body.
    """

    def __init__(self, conn, hard_deadline: float | None = None) -> None:
        self.conn = conn
        self.hard_deadline = hard_deadline
        self.buf = bytearray()

    def _pull(self) -> bool:
        chunk = self.conn.recv_some(
            max_bytes=65536,
            idle=30.0,
            hard_deadline=self.hard_deadline,
        )
        if not chunk:
            return False
        self.buf.extend(chunk)
        return True

    def read_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            if not self._pull():
                raise TCPError("incomplete body")
        data = bytes(self.buf[:n])
        del self.buf[:n]
        return data

    def read_line(self) -> bytes:
        while b"\r\n" not in self.buf:
            if len(self.buf) > 1024 * 1024:
                raise TCPError("response header too large")
            if not self._pull():
                raise TCPError("incomplete body")
        end = self.buf.find(b"\r\n")
        line = bytes(self.buf[:end])
        del self.buf[: end + 2]
        return line

    def read_until_eof(self) -> bytes:
        parts = [bytes(self.buf)]
        self.buf.clear()
        while True:
            chunk = self.conn.recv_some(max_bytes=65536, idle=30.0)
            if not chunk:
                break
            parts.append(chunk)
        return b"".join(parts)


def _header_map(lines: list[str]) -> dict[str, list[str]]:
    headers: dict[str, list[str]] = {}
    for line in lines:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.setdefault(name.strip().lower(), []).append(value.strip())
    return headers


def _chunked(headers: dict[str, list[str]]) -> bool:
    for value in headers.get("transfer-encoding", []):
        tokens = [part.strip().lower() for part in value.split(",")]
        if "chunked" in tokens:
            return True
    return False


def _read_chunked(stream: ByteStream) -> bytes:
    """Chunked body. Chunk extensions and trailers are ignored."""
    body = bytearray()
    while True:
        line = stream.read_line()
        token = line.split(b";", 1)[0].strip()
        try:
            size = int(token, 16)
        except ValueError as exc:
            raise TCPError("bad chunk size") from exc
        if size < 0 or size > 16 * 1024 * 1024:
            raise TCPError("bad chunk size")
        if size == 0:
            # Trailers run until a blank line. We do not interpret them.
            while True:
                trailer = stream.read_line()
                if trailer == b"":
                    break
            break
        body.extend(stream.read_exact(size))
        if stream.read_exact(2) != b"\r\n":
            raise TCPError("bad chunk framing")
    return bytes(body)


def read_response(conn) -> tuple[str, int, bytes]:
    """Read one complete HTTP response. Raises TCPError if it is cut off."""
    stream = ByteStream(conn)
    while b"\r\n\r\n" not in stream.buf:
        if len(stream.buf) > 1024 * 1024:
            raise TCPError("response header too large")
        if not stream._pull():
            raise TCPError("incomplete response")
    split = stream.buf.find(b"\r\n\r\n")
    head = bytes(stream.buf[:split]).decode("iso-8859-1")
    del stream.buf[: split + 4]

    lines = head.split("\r\n")
    status_line = lines[0]
    parts = status_line.split(" ")
    if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
        raise TCPError("bad status line")
    code = int(parts[1])
    headers = _header_map(lines[1:])

    if _chunked(headers):
        body = _read_chunked(stream)
    elif "content-length" in headers:
        lengths = headers["content-length"]
        try:
            values = [int(item) for item in lengths]
        except ValueError as exc:
            raise TCPError("bad content-length") from exc
        if any(v < 0 for v in values) or any(v != values[0] for v in values):
            raise TCPError("bad content-length")
        body = stream.read_exact(values[0])
    else:
        # No length and not chunked: the body ends when the server FINs.
        body = stream.read_until_eof()
    return status_line, code, body


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="run-client", add_help=True)
    parser.add_argument("url")
    parser.add_argument("-o", dest="outfile", default=None)
    parser.add_argument("--log", dest="logfile", default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    try:
        url = parse_url(args.url)
    except ValueError:
        print("invalid url", file=sys.stderr)
        return 2

    log_fh = None
    endpoint = None
    try:
        if args.logfile:
            log_fh = open(args.logfile, "w", encoding="ascii", buffering=1)
        ip = resolve_ipv4(url.host, url.port)
        endpoint = TCPEndpoint(log_file=log_fh)
        conn = endpoint.connect(ip, url.port)
        try:
            conn.send_all(build_request(url))
            status_line, code, body = read_response(conn)
        finally:
            # T9. A teardown that hits the 2s cap, or a RST after the
            # body is already complete, does not undo a finished response.
            try:
                conn.close()
            except TCPError:
                pass
    except (TCPError, TCPTimeout, TCPReset, OSError) as exc:
        print(str(exc) or "request failed", file=sys.stderr)
        return 2
    finally:
        if endpoint is not None:
            endpoint.close()
        if log_fh is not None:
            log_fh.close()

    try:
        if args.outfile:
            with open(args.outfile, "wb") as handle:
                handle.write(body)
        else:
            sys.stdout.buffer.write(body)
    except OSError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    print(status_line, file=sys.stderr)
    if 200 <= code <= 299:
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
