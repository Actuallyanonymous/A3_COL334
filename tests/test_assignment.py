#!/usr/bin/env python3
"""Checks that do not need the four VMs.

The TCP tests speak the real stack to itself over a pair of UDP sockets,
so a dropped or reordered datagram is a dropped or reordered IP packet.
Raw sockets are what the programs use on the VMs; this stands in for the
wire without needing root.
"""

from __future__ import annotations

import os
import random
import socket
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from http_client import build_request, parse_url, read_response  # noqa: E402
from http_server import content_type, response_for  # noqa: E402
from tcp_conn import TCPEndpoint  # noqa: E402
from wire import (  # noqa: E402
    ACK,
    OUR_MSS,
    SYN,
    build_packet,
    format_log,
    inet_checksum,
    parse_packet,
)


class WireTests(unittest.TestCase):
    def test_checksum_vector(self):
        # 0x0001 + 0xF203 = 0xF204, one's complement is 0x0DFB.
        self.assertEqual(inet_checksum(b"\x00\x01\xf2\x03"), 0x0DFB)

    def test_syn_roundtrip_and_log_shape(self):
        packet = build_packet(
            "10.10.1.10",
            "10.10.3.10",
            301,
            62425,
            8000,
            1000,
            0,
            SYN,
            b"",
            OUR_MSS,
        )
        parsed = parse_packet(packet)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.ttl, 64)
        self.assertEqual(parsed.ident, 301)
        self.assertNotEqual(parsed.ident, 0)
        self.assertEqual(parsed.seq, 1000)
        self.assertEqual(parsed.ack, 0)
        self.assertEqual(parsed.flags, 0x02)
        self.assertEqual(parsed.win, 65535)
        self.assertEqual(parsed.payload, b"")
        self.assertEqual(parsed.mss, 1460)
        # SYN carries exactly one option, four bytes, so data offset is 6.
        self.assertEqual(packet[20 + 12] >> 4, 6)
        line = format_log("SEND", parsed).rstrip("\n")
        self.assertEqual(
            line,
            "SEND 10.10.1.10:62425 > 10.10.3.10:8000 "
            "ttl=64 id=301 seq=1000 ack=0 flags=0x02 win=65535 len=0 mss=1460",
        )

    def test_data_segment_has_no_options(self):
        packet = build_packet(
            "10.10.1.10",
            "10.10.3.10",
            302,
            62425,
            8000,
            1001,
            5001,
            ACK,
            b"abc",
            None,
        )
        parsed = parse_packet(packet)
        self.assertEqual(parsed.flags, 0x10)
        self.assertEqual(parsed.mss, None)
        self.assertEqual(parsed.payload, b"abc")
        self.assertEqual(packet[20 + 12] >> 4, 5)
        line = format_log("RECV", parsed).rstrip("\n")
        self.assertIn("flags=0x10", line)
        self.assertTrue(line.endswith("mss=-"))

    def test_bad_checksum_is_dropped(self):
        packet = bytearray(
            build_packet(
                "10.0.0.1",
                "10.0.0.2",
                7,
                1,
                2,
                10,
                0,
                SYN,
                b"",
                1460,
            )
        )
        packet[30] ^= 0xFF
        self.assertIsNone(parse_packet(bytes(packet)))

    def test_ignores_unknown_tcp_options_but_keeps_mss(self):
        # A kernel SYN-ACK: MSS, NOP, window scale, timestamp. We only
        # have a builder for a bare MSS, so patch a header by parsing
        # a segment we construct with the public parser's option walk
        # via a hand-built packet checked below through parse_packet.
        # Build a legal packet, then this is covered by parse of options
        # inside a segment whose checksum we recompute in the helper.
        from wire import IPPROTO_TCP

        src = "10.0.0.1"
        dst = "10.0.0.2"
        # MSS (4) + NOP (1) + window scale (3) + timestamp (10) = 18,
        # plus 2 bytes of NOP padding so the header is a multiple of 4.
        options = (
            b"\x02\x04\x05\xb4"  # MSS 1460
            b"\x01"  # NOP
            b"\x03\x03\x07"  # window scale 7
            b"\x08\x0a" + b"\x00\x00\x00\x01" + b"\x00\x00\x00\x00"  # timestamp
            b"\x01\x01"  # NOP pad, so the header stays a multiple of 4 bytes
        )
        self.assertEqual(len(options) % 4, 0)
        data_offset = (20 + len(options)) // 4
        import struct

        offset_flags = (data_offset << 12) | SYN
        tcp = struct.pack("!HHIIHHHH", 9, 80, 5, 0, offset_flags, 65535, 0, 0) + options
        pseudo = struct.pack(
            "!4s4sBBH",
            socket.inet_aton(src),
            socket.inet_aton(dst),
            0,
            IPPROTO_TCP,
            len(tcp),
        )
        csum = inet_checksum(pseudo + tcp)
        tcp = tcp[:16] + struct.pack("!H", csum) + tcp[18:]
        ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(tcp),
            4,
            0,
            64,
            IPPROTO_TCP,
            0,
            socket.inet_aton(src),
            socket.inet_aton(dst),
        )
        ip = ip[:10] + struct.pack("!H", inet_checksum(ip)) + ip[12:]
        parsed = parse_packet(ip + tcp)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.mss, 1460)
        self.assertEqual(parsed.flags, SYN)


class HttpTests(unittest.TestCase):
    def test_url_and_request(self):
        url = parse_url("http://10.10.3.10:8080/a/b?q=1")
        self.assertEqual(url.host, "10.10.3.10")
        self.assertEqual(url.port, 8080)
        self.assertEqual(url.path, "/a/b?q=1")
        self.assertEqual(url.host_header, "10.10.3.10:8080")
        raw = build_request(url)
        self.assertEqual(
            raw,
            b"GET /a/b?q=1 HTTP/1.1\r\n"
            b"Host: 10.10.3.10:8080\r\n"
            b"Connection: close\r\n"
            b"\r\n",
        )
        self.assertNotIn(b"Accept-Encoding", raw)

        plain = parse_url("http://example.com")
        self.assertEqual(plain.port, 80)
        self.assertEqual(plain.path, "/")
        self.assertEqual(plain.host_header, "example.com")
        self.assertEqual(build_request(plain).split(b"\r\n")[1], b"Host: example.com")

        with_port = parse_url("http://example.com:80/x")
        self.assertEqual(with_port.host_header, "example.com:80")
        self.assertEqual(with_port.path, "/x")

        for bad in ("https://x/", "http://", "ftp://x/", "http:///x", "not a url"):
            with self.assertRaises(ValueError):
                parse_url(bad)

    def test_content_type(self):
        self.assertEqual(content_type("a.HTML"), "text/html")
        self.assertEqual(content_type("a.JPEG"), "image/jpeg")
        self.assertEqual(content_type("a.jpg"), "image/jpeg")
        self.assertEqual(content_type("a.bin"), "application/octet-stream")
        self.assertEqual(content_type("a.js"), "application/javascript")

    def test_response_table(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "sub"))
            with open(os.path.join(root, "index.html"), "wb") as handle:
                handle.write(b"<h1>hi</h1>")
            with open(os.path.join(root, "pic.JPG"), "wb") as handle:
                handle.write(b"\xff\xd8\xff")
            with open(os.path.join(root, "sub", "index.html"), "wb") as handle:
                handle.write(b"sub")

            ok = response_for(b"GET / HTTP/1.1", root)
            self.assertTrue(ok.startswith(b"HTTP/1.1 200 OK\r\n"))
            self.assertIn(b"Content-Type: text/html\r\n", ok)
            self.assertIn(b"Connection: close\r\n", ok)
            self.assertTrue(ok.endswith(b"<h1>hi</h1>"))

            # Query string is ignored for the file, kept out of the filename.
            queried = response_for(b"GET /pic.JPG?x=../y HTTP/1.1", root)
            self.assertIn(b"Content-Type: image/jpeg\r\n", queried)
            self.assertTrue(queried.endswith(b"\xff\xd8\xff"))

            head = response_for(b"HEAD / HTTP/1.1", root)
            self.assertIn(b"Content-Length: 11\r\n", head)
            self.assertFalse(head.endswith(b"<h1>hi</h1>"))
            self.assertTrue(head.endswith(b"\r\n\r\n"))

            self.assertIn(b"400 Bad Request", response_for(b"GET noslash HTTP/1.1", root))
            self.assertIn(b"400 Bad Request", response_for(b"NOT A REQUEST", root))
            self.assertIn(b"501 Not Implemented", response_for(b"POST / HTTP/1.1", root))
            self.assertIn(b"403 Forbidden", response_for(b"GET /../etc/passwd HTTP/1.1", root))
            self.assertIn(b"403 Forbidden", response_for(b"GET /sub/../../x HTTP/1.1", root))
            self.assertIn(b"404 Not Found", response_for(b"GET /missing.txt HTTP/1.1", root))
            # Directory with a trailing slash and without both serve index.html.
            self.assertTrue(response_for(b"GET /sub/ HTTP/1.1", root).endswith(b"sub"))
            self.assertTrue(response_for(b"GET /sub HTTP/1.1", root).endswith(b"sub"))

    def test_framing(self):
        class Fake:
            def __init__(self, data):
                self.data = data

            def recv_some(self, max_bytes=65536, idle=30.0, hard_deadline=None):
                if not self.data:
                    return b""
                chunk = self.data[:max_bytes]
                self.data = self.data[max_bytes:]
                return chunk

        status, code, body = read_response(
            Fake(
                b"HTTP/1.0 200 OK\r\n"
                b"Content-Length: 4\r\n"
                b"\r\n"
                b"wiki"
            )
        )
        self.assertEqual(status, "HTTP/1.0 200 OK")
        self.assertEqual(code, 200)
        self.assertEqual(body, b"wiki")

        _status, code, body = read_response(
            Fake(
                b"HTTP/1.1 200 OK\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"\r\n"
                b"4;ext=1\r\n"
                b"Wiki\r\n"
                b"5\r\n"
                b"pedia\r\n"
                b"0\r\n"
                b"Ignored: trailer\r\n"
                b"\r\n"
            )
        )
        self.assertEqual(code, 200)
        self.assertEqual(body, b"Wikipedia")

        _status, code, body = read_response(
            Fake(b"HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\nnope")
        )
        self.assertEqual(code, 404)
        self.assertEqual(body, b"nope")


class _UdpLink:
    """UDP datagrams standing in for IP packets. Optional loss and reorder."""

    def __init__(self, sock, peer, drop_every=0, reorder_every=0):
        self.sock = sock
        self.peer = peer
        self.drop_every = drop_every
        self.reorder_every = reorder_every
        self.sent = 0
        self.held = None

    def send_packet(self, packet, dest_ip):
        self.sent += 1
        if self.drop_every and self.sent % self.drop_every == 0:
            return
        if self.held is not None:
            held, self.held = self.held, None
            self.sock.sendto(held, self.peer)
        if self.reorder_every and self.sent % self.reorder_every == 0:
            self.held = packet
            return
        self.sock.sendto(packet, self.peer)

    def recv_packet(self):
        try:
            data, _addr = self.sock.recvfrom(65535)
            return data
        except (BlockingIOError, InterruptedError):
            return None

    def fileno(self):
        return self.sock.fileno()

    def close(self):
        self.sock.close()


def _pair(drop_every=0, reorder_every=0):
    left = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    right = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    left.bind(("127.0.0.1", 0))
    right.bind(("127.0.0.1", 0))
    for sock in (left, right):
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    return (
        _UdpLink(left, right.getsockname(), drop_every, reorder_every),
        _UdpLink(right, left.getsockname(), drop_every, reorder_every),
    )


class TransferTests(unittest.TestCase):
    def _exchange(self, payload, drop_every=0, reorder_every=0, client_isn=None, server_isn=None):
        client_link, server_link = _pair(drop_every, reorder_every)
        errors = []
        got = {}

        def server():
            try:
                ep = TCPEndpoint(transport=server_link)
                conn = ep.accept(9000, isn=server_isn)
                data = conn.read_exact(len(payload), idle=15.0)
                conn.send_all(b"OK" + data)
                conn.close()
                got["server"] = data
                ep.close()
            except Exception as exc:  # noqa: BLE001 - the test reports it
                errors.append(exc)

        def client():
            try:
                ep = TCPEndpoint(transport=client_link)
                conn = ep.connect(
                    "127.0.0.1",
                    9000,
                    local_port=62000,
                    isn=client_isn,
                )
                conn.send_all(payload)
                reply = conn.read_exact(2 + len(payload), idle=15.0)
                conn.close()
                got["client"] = reply
                ep.close()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=server), threading.Thread(target=client)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=40)
        for thread in threads:
            if thread.is_alive():
                errors.append(RuntimeError("transfer hung"))
        if errors:
            raise errors[0]
        self.assertEqual(got["server"], payload)
        self.assertEqual(got["client"], b"OK" + payload)

    def test_lossless(self):
        self._exchange(b"hello tcp")

    def test_large_and_sequence_wrap(self):
        payload = bytes(random.Random(1).randrange(256) for _ in range(200_000))
        self._exchange(payload, client_isn=0xFFFFFF00, server_isn=0xFFFFF000)

    def test_loss_and_reorder(self):
        payload = bytes(random.Random(2).randrange(256) for _ in range(80_000))
        # Every 7th packet is dropped, every 4th is held back one send
        # so it arrives after the next one.
        self._exchange(payload, drop_every=7, reorder_every=4)


class HttpOverTcpTests(unittest.TestCase):
    def test_get_file(self):
        with tempfile.TemporaryDirectory() as root:
            body = b"xyz" * 1000
            with open(os.path.join(root, "blob.bin"), "wb") as handle:
                handle.write(body)
            client_link, server_link = _pair()
            errors = []
            got = {}

            def server():
                try:
                    ep = TCPEndpoint(transport=server_link)
                    from http_server import serve_connection

                    conn = ep.accept(8080)
                    serve_connection(conn, root)
                    conn.close()
                    ep.close()
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)

            def client():
                try:
                    ep = TCPEndpoint(transport=client_link)
                    conn = ep.connect("127.0.0.1", 8080, local_port=63000)
                    url = parse_url("http://127.0.0.1:8080/blob.bin")
                    conn.send_all(build_request(url))
                    status, code, data = read_response(conn)
                    conn.close()
                    got["status"] = status
                    got["code"] = code
                    got["body"] = data
                    ep.close()
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)

            threads = [threading.Thread(target=server), threading.Thread(target=client)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=20)
            if errors:
                raise errors[0]
            self.assertEqual(got["code"], 200)
            self.assertEqual(got["status"], "HTTP/1.1 200 OK")
            self.assertEqual(got["body"], body)


class ScriptTests(unittest.TestCase):
    def test_addresses_are_the_ones_in_the_table(self):
        root = os.path.join(os.path.dirname(__file__), "..", "netcfg")
        text = {}
        for name in ("client.sh", "r1.sh", "r2.sh", "server.sh"):
            with open(os.path.join(root, name), encoding="utf-8") as handle:
                text[name] = handle.read()
        self.assertIn("10.10.1.10/24", text["client.sh"])
        self.assertIn("10.10.4.2/30", text["client.sh"])
        self.assertIn("10.10.1.1/24", text["r1.sh"])
        self.assertIn("10.10.2.1/24", text["r1.sh"])
        self.assertIn("10.10.0.0/16", text["r1.sh"])
        self.assertIn("10.10.2.2/24", text["r2.sh"])
        self.assertIn("10.10.3.1/24", text["r2.sh"])
        self.assertIn("10.10.4.1/30", text["r2.sh"])
        self.assertIn("10.10.1.10/32", text["r2.sh"])
        self.assertIn("10.10.3.10/24", text["server.sh"])
        # r1 and the server stay strict; client and r2 are loose.
        self.assertIn("rp_filter=1", text["r1.sh"])
        self.assertIn("rp_filter=1", text["server.sh"])
        self.assertIn("rp_filter=2", text["client.sh"])
        self.assertIn("rp_filter=2", text["r2.sh"])
        self.assertNotIn("default", text["r2.sh"].split("No default route")[-1].split("echo")[0])


if __name__ == "__main__":
    unittest.main()
