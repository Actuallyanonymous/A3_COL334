"""IPv4 and TCP header construction.

Part B forbids letting the kernel write the IP header, so every packet
we send is built here and every packet we accept is parsed here.
Checksums are the standard Internet checksum (one's complement of the
one's complement sum of the 16-bit words).
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

# Byte 13 of the TCP header. The log prints this byte as two hex digits.
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10

# T3: the only option we ever send, and the largest payload we will send.
OUR_MSS = 1460
# T11: the window field is fixed. No window scaling, so this is bytes.
RECV_WINDOW = 65535
IP_TTL = 64
IPPROTO_TCP = 6


@dataclass
class Packet:
    """One TCP segment plus the IPv4 fields the log line needs."""

    src_ip: str
    dst_ip: str
    ttl: int
    ident: int
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    win: int
    payload: bytes
    mss: int | None


def inet_checksum(data: bytes) -> int:
    """Internet checksum of `data`. An odd trailing byte is padded with 0."""
    if len(data) & 1:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    # Fold the carry back in until the sum fits in 16 bits.
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _checksum_ok(data: bytes, checksum_at: int) -> bool:
    """True when recomputing with the checksum field zeroed matches it."""
    if checksum_at < 0 or checksum_at + 2 > len(data):
        return False
    expect = (data[checksum_at] << 8) | data[checksum_at + 1]
    zeroed = data[:checksum_at] + b"\x00\x00" + data[checksum_at + 2 :]
    return inet_checksum(zeroed) == expect


def build_packet(
    src_ip: str,
    dst_ip: str,
    ident: int,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes,
    mss: int | None,
    ttl: int = IP_TTL,
    win: int = RECV_WINDOW,
) -> bytes:
    """Build one IPv4 datagram carrying one TCP segment.

    `mss` is sent only when it is not None. Callers pass 1460 for SYN
    and SYN-ACK and None for everything else, so those segments carry
    exactly one option (T3) and data segments carry none.
    """
    if mss is not None:
        # Kind 2, length 4, value. Four bytes, so the TCP header is 24
        # bytes and the data offset is 6.
        options = struct.pack("!BBH", 2, 4, mss)
        data_offset = 6
    else:
        options = b""
        data_offset = 5

    # Top 4 bits are the data offset in 32-bit words. The low 8 bits
    # are byte 13 (the flags the log prints). NS and the reserved bits
    # stay 0.
    offset_flags = (data_offset << 12) | (flags & 0xFF)
    tcp_len = 20 + len(options) + len(payload)
    tcp_header = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        offset_flags,
        win & 0xFFFF,
        0,  # checksum, filled below
        0,  # urgent pointer
    ) + options

    # TCP checksum covers a pseudo-header the receiver rebuilds from
    # the IP header, plus the TCP header and payload.
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        IPPROTO_TCP,
        tcp_len,
    )
    tcp_checksum = inet_checksum(pseudo + tcp_header + payload)
    tcp_header = tcp_header[:16] + struct.pack("!H", tcp_checksum) + tcp_header[18:]

    total = 20 + tcp_len
    # Don't Fragment. Fragmentation is out of scope, and 1460 bytes of
    # payload already fills a 1500-byte Ethernet frame exactly.
    flags_frag = 0x4000
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # version 4, IHL 5 (no IP options)
        0,  # TOS
        total,
        ident & 0xFFFF,
        flags_frag,
        ttl & 0xFF,
        IPPROTO_TCP,
        0,  # checksum, filled below
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    ip_checksum = inet_checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack("!H", ip_checksum) + ip_header[12:]
    return ip_header + tcp_header + payload


def _parse_mss(options: bytes) -> int | None:
    """Return the MSS option if present. Every other option is skipped (T4)."""
    mss = None
    i = 0
    while i < len(options):
        kind = options[i]
        if kind == 0:  # end of options
            break
        if kind == 1:  # NOP, no length byte
            i += 1
            continue
        if i + 1 >= len(options):
            break
        length = options[i + 1]
        if length < 2 or i + length > len(options):
            break
        if kind == 2 and length == 4:
            mss = struct.unpack("!H", options[i + 2 : i + 4])[0]
        i += length
    return mss


def parse_packet(buf: bytes) -> Packet | None:
    """Parse one IPv4 TCP datagram.

    Returns None when the packet is truncated, fragmented, not TCP,
    or either checksum fails. Callers drop that silently (T4).
    The slice uses the IP total-length field so trailer padding that
    raw sockets sometimes append is not fed into the TCP checksum.
    """
    if len(buf) < 20:
        return None
    version_ihl = buf[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4 or ihl < 20 or len(buf) < ihl:
        return None
    if not _checksum_ok(buf[:ihl], 10):
        return None

    total, ident, flags_frag, ttl, proto = struct.unpack("!HHHBB", buf[2:10])
    if total < ihl or total > len(buf):
        return None
    # More Fragments or a non-zero offset: we do not reassemble.
    if flags_frag & 0x3FFF:
        return None
    if proto != IPPROTO_TCP:
        return None

    src_ip = socket.inet_ntoa(buf[12:16])
    dst_ip = socket.inet_ntoa(buf[16:20])
    segment = buf[ihl:total]
    if len(segment) < 20:
        return None

    data_offset = (segment[12] >> 4) * 4
    if data_offset < 20 or data_offset > len(segment):
        return None

    src_port, dst_port, seq, ack = struct.unpack("!HHII", segment[:12])
    flags = segment[13]
    win = struct.unpack("!H", segment[14:16])[0]
    payload = segment[data_offset:]

    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        IPPROTO_TCP,
        len(segment),
    )
    if not _checksum_ok(pseudo + segment, 12 + 16):
        return None

    mss = _parse_mss(segment[20:data_offset])
    return Packet(
        src_ip=src_ip,
        dst_ip=dst_ip,
        ttl=ttl,
        ident=ident,
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        ack=ack,
        flags=flags,
        win=win,
        payload=payload,
        mss=mss,
    )


def format_log(direction: str, pkt: Packet) -> str:
    """One log line, exactly the shape in Table 3. The caller flushes it."""
    mss = "-" if pkt.mss is None else str(pkt.mss)
    return (
        f"{direction} {pkt.src_ip}:{pkt.src_port} > {pkt.dst_ip}:{pkt.dst_port} "
        f"ttl={pkt.ttl} id={pkt.ident} seq={pkt.seq} ack={pkt.ack} "
        f"flags=0x{pkt.flags:02x} win={pkt.win} len={len(pkt.payload)} mss={mss}\n"
    )
