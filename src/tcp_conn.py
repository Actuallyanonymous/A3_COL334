"""One TCP connection on top of a raw IPv4 socket.

What this implements (T1–T14), and what it deliberately skips
(window scaling, SACK, timestamps, TIME_WAIT — section 2.7):

  * Handshake. A SYN or SYN-ACK that is not answered is retransmitted
    within 1s. We keep trying for 7s, which is past the required 6s.
  * Reliability. Bytes are delivered once, in order. Out-of-order data
    inside the 65535-byte window is kept. A lost segment is resent
    after an RTO of at most 1s, and also after three duplicate ACKs.
    If the oldest unacked byte makes no progress for 10s, we give up.
  * Congestion control in the Reno style: slow start, then additive
    increase, and a cut on loss. The initial window is 10 segments so
    a flow of ours is not starved by a kernel TCP flow (curl) that
    also starts at 10.
  * Teardown. We ACK the peer's FIN. After we send ours we retransmit
    it until it is ACKed and we wait for theirs, but never longer than 2s.

The kernel's own TCP stack is still running. A SYN to a port with no
kernel listener makes the kernel emit a RST, which would kill this
connection (T8). The launchers install an iptables rule that drops
those RSTs. This module only does the TCP.
"""

from __future__ import annotations

import os
import random
import select
import socket
import time
from dataclasses import dataclass, field

from wire import (
    ACK,
    FIN,
    OUR_MSS,
    PSH,
    RECV_WINDOW,
    RST,
    SYN,
    Packet,
    build_packet,
    format_log,
    parse_packet,
)

# Handshake must last at least 6s (T7). 7s leaves a little slack so a
# peer that answers at t=6 is still accepted.
HANDSHAKE_TIMEOUT = 7.0
# T9: give up on teardown after at most 2s. Stay under the cap so a
# slow scheduling tick cannot push us past it.
TEARDOWN_TIMEOUT = 1.9
# T10: give up when nothing new is acknowledged for 10s.
STALL_TIMEOUT = 10.0
# T7 / T10: every retransmission happens within 1s. The floor keeps a
# tiny measured RTT from causing a spurious retransmit. The initial
# value is under 1s so timer slack still satisfies "at most 1s".
MAX_RTO = 1.0
MIN_RTO = 0.2
INITIAL_RTO = 0.9

MASK = 0xFFFFFFFF
_rng = random.SystemRandom()


def debug(msg: str) -> None:
    if os.environ.get("TCP_DEBUG") == "1":
        print(msg, flush=True)


class TCPError(Exception):
    pass


class TCPTimeout(TCPError):
    pass


class TCPReset(TCPError):
    pass


def seq_lt(a: int, b: int) -> bool:
    """True when `a` is before `b` in the 32-bit sequence space (RFC 1982)."""
    return ((a - b) & MASK) > 0x80000000


def seq_leq(a: int, b: int) -> bool:
    return a == (b & MASK) or seq_lt(a, b)


def seq_diff(a: int, b: int) -> int:
    """How far `a` is ahead of `b`, in [0, 2^32)."""
    return (a - b) & MASK


def random_isn() -> int:
    return _rng.randrange(0, 2**32)


def random_client_port() -> int:
    # T13. Above Ubuntu's default ephemeral range (32768–60999), which
    # is also why the client's iptables rule does not catch curl.
    return _rng.randrange(61000, 65536)


def route_source_ip(dest_ip: str) -> str:
    """Local address the kernel would use to reach `dest_ip`.

    A connected UDP socket does not transmit anything; connect() here
    only asks the routing table. connect() on a TCP socket is forbidden,
    a UDP socket is not.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((dest_ip, 9))
        ip = sock.getsockname()[0]
    finally:
        sock.close()
    if not ip or ip == "0.0.0.0":
        raise TCPError(f"no route to {dest_ip}")
    return ip


class IPID:
    """IPv4 identification. T1 requires it to be non-zero."""

    def __init__(self) -> None:
        self._n = _rng.randrange(1, 65536)

    def next(self) -> int:
        cur = self._n
        self._n = 1 if self._n == 65535 else self._n + 1
        return cur


class Logger:
    def __init__(self, fh) -> None:
        self._fh = fh

    def send(self, pkt: Packet) -> None:
        self._write("SEND", pkt)

    def recv(self, pkt: Packet) -> None:
        self._write("RECV", pkt)

    def _write(self, direction: str, pkt: Packet) -> None:
        if self._fh is None:
            return
        self._fh.write(format_log(direction, pkt))
        self._fh.flush()


class RawTransport:
    """AF_INET/SOCK_RAW/IPPROTO_TCP with IP_HDRINCL.

    The kernel delivers each TCP segment with its IPv4 header still
    attached, and it does not add a header to what we send.
    """

    def __init__(self) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except PermissionError as exc:
            raise TCPError("raw sockets need root (run with sudo)") from exc
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.setblocking(False)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        except OSError:
            pass
        self.sock = sock
        self.dest_addr = None  # raw send uses the packet's own destination

    def send_packet(self, packet: bytes, dest_ip: str) -> None:
        addr = self.dest_addr if self.dest_addr is not None else (dest_ip, 0)
        self.sock.sendto(packet, addr)

    def recv_packet(self) -> bytes | None:
        try:
            data, _addr = self.sock.recvfrom(65535)
            return data
        except (BlockingIOError, InterruptedError):
            return None

    def fileno(self) -> int:
        return self.sock.fileno()

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class Reassembly:
    """Out-of-order payload, stored as offsets from the current rcv_nxt.

    The advertised window is 65535 and never shrinks, so an offset past
    that is outside the window and is not stored (T12: keep the ones
    that are inside, do not deliver them until the hole in front is
    filled).
    """

    def __init__(self) -> None:
        self.buf: dict[int, int] = {}

    def add(self, rcv_nxt: int, seq: int, data: bytes) -> None:
        off = seq_diff(seq, rcv_nxt)
        for i, byte in enumerate(data):
            pos = off + i
            if pos >= RECV_WINDOW:
                break
            self.buf[pos] = byte

    def pop_contiguous(self) -> bytes:
        n = 0
        while n in self.buf:
            n += 1
        if n == 0:
            return b""
        out = bytes(self.buf[i] for i in range(n))
        if n == len(self.buf):
            self.buf.clear()
        else:
            self.buf = {k - n: v for k, v in self.buf.items() if k >= n}
        return out


@dataclass
class OutSeg:
    """One segment we have sent and not yet fully acknowledged."""

    seq: int
    payload: bytes
    syn: bool
    fin: bool
    first_sent: float
    last_sent: float
    retransmitted: bool = False

    @property
    def span(self) -> int:
        # SYN and FIN each consume one sequence number, payload the rest.
        return len(self.payload) + int(self.syn) + int(self.fin)


@dataclass
class TCPConnection:
    """State for exactly one connection. The endpoint drives the socket."""

    transport: object
    logger: Logger
    ipids: IPID
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    isn: int = field(default_factory=random_isn)

    def __post_init__(self) -> None:
        self.snd_una = self.isn
        self.snd_nxt = self.isn
        self.rcv_nxt = 0
        self.irs = 0

        self.got_peer_syn = False
        self.syn_sent = False
        self.syn_acked = False
        self.established = False

        self.peer_win = 0
        self.send_mss = OUR_MSS
        # Reno. Set again once we know the peer's MSS.
        self.cwnd = 10 * OUR_MSS
        self.ssthresh = 64 * 1024
        self._ack_credit = 0
        self._loss_cut = False

        self.srtt: float | None = None
        self.rto = INITIAL_RTO
        self.rto_cur = INITIAL_RTO

        self.inflight: list[OutSeg] = []
        self.outbuf = bytearray()
        self.app_buf = bytearray()
        self.reasm = Reassembly()

        self.fin_queued = False
        self.fin_sent = False
        self.fin_seq = 0
        self.peer_fin_seq: int | None = None
        self.fin_consumed = False

        self.dup_acks = 0
        self.did_fast = False
        self.aborted = False
        self.abort_reason = ""
        self.user_closed = False
        self.packets_in = 0
        self.last_progress = time.monotonic()
        self.need_ack = False

    # ---------------------------------------------------------------- sends

    def _send(self, seq: int, flags: int, payload: bytes, seg: OutSeg | None) -> None:
        mss = OUR_MSS if flags & SYN else None
        ack_num = self.rcv_nxt if flags & ACK else 0
        packet = build_packet(
            self.local_ip,
            self.remote_ip,
            self.ipids.next(),
            self.local_port,
            self.remote_port,
            seq,
            ack_num,
            flags,
            payload,
            mss,
        )
        parsed = parse_packet(packet)
        if parsed is None:
            # We just built it. A failure here is a bug, not a bad peer.
            raise TCPError("outgoing segment failed its own checksum")
        self.logger.send(parsed)
        self.transport.send_packet(packet, self.remote_ip)
        if seg is not None:
            now = time.monotonic()
            seg.last_sent = now
            if seg.first_sent == 0:
                seg.first_sent = now

    def _flags_for(self, seg: OutSeg) -> int:
        if seg.syn and not self.got_peer_syn:
            return SYN
        if seg.syn:
            return SYN | ACK
        flags = ACK
        if seg.payload:
            flags |= PSH
        if seg.fin:
            flags |= FIN
        return flags

    def _transmit_new(self) -> None:
        """Send queued data, then the FIN, within cwnd and the peer window."""
        if not self.established:
            return
        before = self._in_flight()
        while self.outbuf and self._send_room() > 0:
            n = min(self.send_mss, self._send_room(), len(self.outbuf))
            payload = bytes(self.outbuf[:n])
            del self.outbuf[:n]
            seg = OutSeg(self.snd_nxt, payload, False, False, 0.0, 0.0)
            self.inflight.append(seg)
            self._send(self.snd_nxt, ACK | PSH, payload, seg)
            self.snd_nxt = (self.snd_nxt + n) & MASK
        if (
            self.fin_queued
            and not self.fin_sent
            and not self.outbuf
            and self._send_room() > 0
        ):
            seg = OutSeg(self.snd_nxt, b"", False, True, 0.0, 0.0)
            self.inflight.append(seg)
            self._send(self.snd_nxt, ACK | FIN, b"", seg)
            self.fin_seq = self.snd_nxt
            self.snd_nxt = (self.snd_nxt + 1) & MASK
            self.fin_sent = True
        # Starting a flight arms the "nothing acknowledged for 10s" timer.
        if before == 0 and self._in_flight() > 0:
            self.last_progress = time.monotonic()

    def _resend(self, seg: OutSeg) -> None:
        self._send(seg.seq, self._flags_for(seg), seg.payload, seg)
        seg.retransmitted = True

    def _send_pure_ack(self) -> None:
        # Pure ACKs are not tracked: if one is lost the peer retransmits
        # and we ACK again.
        self._send(self.snd_nxt, ACK, b"", None)

    def _send_room(self) -> int:
        """Bytes of new data we may put in flight right now."""
        limit = min(self.cwnd, self.peer_win)
        room = limit - self._in_flight()
        return room if room > 0 else 0

    def _in_flight(self) -> int:
        return seq_diff(self.snd_nxt, self.snd_una)

    # -------------------------------------------------------------- receive

    def _tuple_ok(self, pkt: Packet) -> bool:
        return (
            pkt.src_ip == self.remote_ip
            and pkt.dst_ip == self.local_ip
            and pkt.src_port == self.remote_port
            and pkt.dst_port == self.local_port
        )

    def _ingest(self) -> None:
        while True:
            raw = self.transport.recv_packet()
            if raw is None:
                return
            pkt = parse_packet(raw)
            if pkt is None:
                debug("drop: bad checksum or not a complete TCP/IPv4 segment")
                continue
            if not self._tuple_ok(pkt):
                continue
            # Belongs to this connection and both checksums passed (T4, T5).
            self.logger.recv(pkt)
            self.packets_in += 1
            self._on_packet(pkt)
            if self.aborted:
                return

    def _on_packet(self, pkt: Packet) -> None:
        if pkt.flags & RST:
            self.aborted = True
            # A RST before the handshake finishes is a refused connection.
            self.abort_reason = "connection reset" if self.established else "connection refused"
            return

        if pkt.flags & ACK:
            self._on_ack(pkt.ack, pkt.win, bool(pkt.payload))

        data_seq = pkt.seq
        if pkt.flags & SYN:
            self._on_syn(pkt)
            data_seq = (pkt.seq + 1) & MASK

        if pkt.payload and self.got_peer_syn:
            self._on_data(data_seq, pkt.payload)

        if (pkt.flags & FIN) and self.got_peer_syn:
            fin_seq = (data_seq + len(pkt.payload)) & MASK
            self._on_fin(fin_seq)

        if self.got_peer_syn and self.syn_acked and not self.established:
            self._become_established()

        if self.need_ack and self.got_peer_syn:
            self._send_pure_ack()
            self.need_ack = False

    def _on_syn(self, pkt: Packet) -> None:
        if self.got_peer_syn:
            # Retransmitted SYN or SYN-ACK. ACK it again; do not move
            # rcv_nxt a second time (the SYN byte was already counted).
            if pkt.seq == self.irs:
                self.need_ack = True
                if not self.established and self.syn_sent:
                    self._resend_handshake()
            return
        # Client: the peer's first segment must be a SYN-ACK of our ISN.
        if self.syn_sent and not (pkt.flags & ACK):
            return
        if self.syn_sent and pkt.ack != ((self.isn + 1) & MASK):
            return
        self.irs = pkt.seq
        self.rcv_nxt = (pkt.seq + 1) & MASK
        self.got_peer_syn = True
        peer_mss = pkt.mss if pkt.mss else 536
        # T3: never send more than 1460, and never more than they asked.
        self.send_mss = min(OUR_MSS, peer_mss) if peer_mss > 0 else min(OUR_MSS, 536)
        self.need_ack = True

    def _resend_handshake(self) -> None:
        """A duplicate SYN while we are in SYN-RECEIVED: repeat SYN-ACK."""
        for seg in self.inflight:
            if seg.syn:
                self._resend(seg)
                return

    def _on_data(self, seq: int, payload: bytes) -> None:
        # T11: every data segment gets a cumulative ACK, including a
        # duplicate and one that is still missing a hole in front of it.
        self.need_ack = True
        if seq_lt(seq, self.rcv_nxt):
            skip = seq_diff(self.rcv_nxt, seq)
            if skip >= len(payload):
                return
            payload = payload[skip:]
            seq = self.rcv_nxt
        if seq_diff(seq, self.rcv_nxt) >= RECV_WINDOW:
            return
        room = RECV_WINDOW - seq_diff(seq, self.rcv_nxt)
        payload = payload[:room]
        if not payload:
            return
        self.reasm.add(self.rcv_nxt, seq, payload)
        self._drain()

    def _on_fin(self, fin_seq: int) -> None:
        if self.peer_fin_seq is None:
            self.peer_fin_seq = fin_seq
        self.need_ack = True
        self._drain()

    def _drain(self) -> None:
        """Move the in-order prefix into the application buffer, then the FIN."""
        while True:
            data = self.reasm.pop_contiguous()
            if not data:
                break
            self.app_buf.extend(data)
            self.rcv_nxt = (self.rcv_nxt + len(data)) & MASK
        if (
            self.peer_fin_seq is not None
            and not self.fin_consumed
            and self.rcv_nxt == self.peer_fin_seq
            and 0 not in self.reasm.buf
        ):
            self.fin_consumed = True
            self.rcv_nxt = (self.rcv_nxt + 1) & MASK
            self.need_ack = True

    def _on_ack(self, ack: int, win: int, has_payload: bool) -> None:
        # An ACK behind snd_una is an old packet. An ACK past snd_nxt
        # acknowledges data we never sent.
        if seq_lt(ack, self.snd_una):
            return
        if seq_lt(self.snd_nxt, ack):
            return
        self.peer_win = win
        if ack == self.snd_una:
            if not has_payload and self._in_flight() > 0 and self.established:
                self.dup_acks += 1
                if self.dup_acks == 3:
                    self._fast_retransmit()
            return

        acked = seq_diff(ack, self.snd_una)
        self.snd_una = ack
        self.dup_acks = 0
        self.did_fast = False
        self._loss_cut = False
        self.last_progress = time.monotonic()
        self.rto_cur = self.rto
        self._retire_acked()
        if ((self.isn + 1) & MASK) == self.snd_una or seq_leq((self.isn + 1) & MASK, self.snd_una):
            self.syn_acked = True
        if self.established:
            self._grow_cwnd(acked)

    def _retire_acked(self) -> None:
        now = time.monotonic()
        while self.inflight:
            seg = self.inflight[0]
            end = (seg.seq + seg.span) & MASK
            if seq_leq(end, self.snd_una):
                if not seg.retransmitted:
                    self._sample_rtt(now - seg.first_sent)
                self.inflight.pop(0)
                continue
            if seq_lt(seg.seq, self.snd_una):
                self._trim(seg, self.snd_una)
            break

    def _trim(self, seg: OutSeg, new_seq: int) -> None:
        """Drop the prefix of `seg` that `new_seq` has already acknowledged."""
        cut = seq_diff(new_seq, seg.seq)
        if seg.syn:
            seg.syn = False
            cut -= 1
        pay = min(cut, len(seg.payload))
        if pay:
            seg.payload = seg.payload[pay:]
            cut -= pay
        if cut and seg.fin:
            seg.fin = False
        seg.seq = new_seq

    def _sample_rtt(self, sample: float) -> None:
        # Karn's algorithm: the caller skips retransmitted segments,
        # whose ACK might have been for the original or the copy.
        if sample < 0:
            return
        if self.srtt is None:
            self.srtt = sample
        else:
            self.srtt = 0.875 * self.srtt + 0.125 * sample
        self.rto = min(MAX_RTO, max(MIN_RTO, self.srtt * 2))
        self.rto_cur = self.rto

    # ---------------------------------------------------- congestion (T14)

    def _become_established(self) -> None:
        self.established = True
        # 10 segments matches the initial window kernel TCP uses, so we
        # do not start the race already a factor of ten behind curl.
        self.cwnd = 10 * self.send_mss
        self.ssthresh = 64 * 1024
        self.last_progress = time.monotonic()

    def _grow_cwnd(self, acked_bytes: int) -> None:
        """Reno, counted in bytes so one-ACK-per-packet and delayed ACKs
        grow the window at the same rate. That is what lets a flow of
        ours share a bottleneck with curl instead of outrunning it.

        Slow start (cwnd < ssthresh): +1 MSS per MSS newly acknowledged,
        which doubles the window every round trip.
        Congestion avoidance: +1 MSS per round trip.
        """
        self._ack_credit += acked_bytes
        while self._ack_credit >= self.send_mss:
            self._ack_credit -= self.send_mss
            if self.cwnd < self.ssthresh:
                self.cwnd += self.send_mss
            else:
                self.cwnd += max(1, (self.send_mss * self.send_mss) // self.cwnd)
        if self.cwnd > 4 * 1024 * 1024:
            self.cwnd = 4 * 1024 * 1024

    def _cut_cwnd(self) -> None:
        if self._loss_cut:
            return
        self._loss_cut = True
        self.ssthresh = max(self.cwnd // 2, 2 * self.send_mss)
        self.cwnd = self.ssthresh

    def _fast_retransmit(self) -> None:
        if self.did_fast or not self.inflight:
            return
        self.did_fast = True
        self._cut_cwnd()
        self._resend(self.inflight[0])
        # Don't immediately RTO the segment we just resent.
        self.rto_cur = self.rto

    def _on_rto(self) -> None:
        # A timeout means the pipe is not just congested, it went quiet.
        # Collapse back to one segment and slow-start again.
        self.ssthresh = max(self.cwnd // 2, 2 * self.send_mss)
        self.cwnd = self.send_mss
        self._loss_cut = True
        self.did_fast = True
        self.dup_acks = 0
        self.rto_cur = min(MAX_RTO, max(self.rto_cur * 2, self.rto))

    # --------------------------------------------------------------- timers

    def _retransmit(self, now: float) -> None:
        if not self.inflight:
            return
        seg = self.inflight[0]
        if now - seg.last_sent < self.rto_cur:
            return
        self._resend(seg)
        if self.established:
            self._on_rto()
        else:
            # Handshake retransmits stay at or under 1s, without touching cwnd.
            self.rto_cur = min(MAX_RTO, self.rto_cur)

    def _check_stall(self, now: float) -> None:
        if not self.established or self.aborted:
            return
        pending = (
            self._in_flight() > 0
            or bool(self.outbuf)
            or (self.fin_queued and not self._our_fin_acked())
        )
        if pending and now - self.last_progress >= STALL_TIMEOUT:
            self.aborted = True
            self.abort_reason = "nothing acknowledged for 10s"

    def _secs_until_timer(self, now: float, deadline: float | None) -> float | None:
        when: float | None = deadline
        if self.inflight:
            due = self.inflight[0].last_sent + self.rto_cur
            when = due if when is None else min(when, due)
        if when is None:
            return None
        return max(0.0, when - now)

    def _drive(self, until, deadline: float | None) -> None:
        while True:
            self._ingest()
            if self.aborted:
                raise TCPReset(self.abort_reason or "connection reset")
            if until():
                return
            now = time.monotonic()
            if deadline is not None and now >= deadline:
                raise TCPTimeout("timeout")
            self._check_stall(now)
            if self.aborted:
                raise TCPReset(self.abort_reason or "connection reset")
            self._retransmit(now)
            self._transmit_new()
            if until():
                return
            now = time.monotonic()
            if deadline is not None and now >= deadline:
                raise TCPTimeout("timeout")
            timeout = self._secs_until_timer(now, deadline)
            while True:
                try:
                    readable, _, _ = select.select([self.transport.fileno()], [], [], timeout)
                    break
                except InterruptedError:
                    continue
            if not readable:
                continue

    # ----------------------------------------------------------------- API

    def start_active(self) -> None:
        """Client: send the opening SYN."""
        seg = OutSeg(self.isn, b"", True, False, 0.0, 0.0)
        self.inflight.append(seg)
        self.syn_sent = True
        self._send(self.isn, SYN, b"", seg)
        self.snd_nxt = (self.isn + 1) & MASK

    def start_passive(self, syn: Packet) -> None:
        """Server: `syn` is the peer's SYN. Send SYN-ACK."""
        self._on_syn(syn)
        self.need_ack = False  # the SYN-ACK carries the acknowledgement
        seg = OutSeg(self.isn, b"", True, False, 0.0, 0.0)
        self.inflight.append(seg)
        self.syn_sent = True
        self._send(self.isn, SYN | ACK, b"", seg)
        self.snd_nxt = (self.isn + 1) & MASK

    def wait_established(self, timeout: float = HANDSHAKE_TIMEOUT) -> None:
        self._drive(lambda: self.established, time.monotonic() + timeout)

    def send_all(self, data: bytes) -> None:
        """Queue `data` and wait until the peer has acknowledged all of it."""
        if self.aborted:
            raise TCPReset(self.abort_reason or "connection reset")
        if not self.established:
            raise TCPError("send before the handshake finished")
        if not data:
            return
        if self._in_flight() == 0 and not self.outbuf:
            self.last_progress = time.monotonic()
        self.outbuf.extend(data)
        self._drive(lambda: not self.outbuf and self._in_flight() == 0, None)

    def recv_some(
        self,
        max_bytes: int = 65536,
        idle: float = 30.0,
        hard_deadline: float | None = None,
    ) -> bytes:
        """Return in-order bytes, or b'' when the peer's FIN has been consumed.

        `idle` is how long we will wait between packets. `hard_deadline`
        is an absolute monotonic time that is never extended (the
        server's 10s budget for a request head).
        """
        while not self.app_buf and not self.fin_consumed:
            now = time.monotonic()
            if hard_deadline is not None and now >= hard_deadline:
                raise TCPTimeout("timeout")
            deadline = now + idle
            if hard_deadline is not None:
                deadline = min(deadline, hard_deadline)
            seen = self.packets_in
            self._drive(
                lambda: bool(self.app_buf) or self.fin_consumed or self.packets_in != seen,
                deadline,
            )
        if not self.app_buf:
            return b""
        n = min(len(self.app_buf), max_bytes)
        data = bytes(self.app_buf[:n])
        del self.app_buf[:n]
        return data

    def read_exact(self, n: int, idle: float = 30.0) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.recv_some(max_bytes=n - len(buf), idle=idle)
            if not chunk:
                raise TCPError("connection closed before all the data arrived")
            buf.extend(chunk)
        return bytes(buf)

    def _our_fin_acked(self) -> bool:
        if not self.fin_sent:
            return False
        # The FIN occupies fin_seq. It is acknowledged when snd_una is
        # strictly past it.
        return not seq_lt(self.snd_una, (self.fin_seq + 1) & MASK)

    def _teardown_done(self) -> bool:
        return self.fin_sent and self._our_fin_acked() and self.fin_consumed

    def close(self) -> None:
        """Active or passive close (T9). Returns even if the peer never FINs."""
        if self.user_closed:
            return
        self.user_closed = True
        if self.aborted or not self.syn_sent:
            return
        try:
            if self.established:
                # Finish data first. The 10s stall lives inside _drive;
                # this deadline is only a backstop.
                self._drive(
                    lambda: not self.outbuf and self._in_flight() == 0,
                    time.monotonic() + 60.0,
                )
            self.fin_queued = True
            self.last_progress = time.monotonic()
            self._drive(self._teardown_done, time.monotonic() + TEARDOWN_TIMEOUT)
        except TCPError as exc:
            debug(f"teardown ended: {exc}")


class TCPEndpoint:
    """Owns the raw socket. One connection at a time (section 2.7)."""

    def __init__(self, transport=None, log_file=None) -> None:
        self.transport = transport if transport is not None else RawTransport()
        self.logger = Logger(log_file)
        self.ipids = IPID()

    def connect(
        self,
        dest_ip: str,
        dest_port: int,
        local_port: int | None = None,
        isn: int | None = None,
    ) -> TCPConnection:
        local_ip = route_source_ip(dest_ip)
        local_port = local_port if local_port is not None else random_client_port()
        conn = TCPConnection(
            self.transport,
            self.logger,
            self.ipids,
            local_ip,
            local_port,
            dest_ip,
            dest_port,
            isn if isn is not None else random_isn(),
        )
        conn.start_active()
        try:
            conn.wait_established(HANDSHAKE_TIMEOUT)
        except TCPError:
            conn.user_closed = True
            raise
        return conn

    def accept(self, port: int, isn: int | None = None) -> TCPConnection:
        """Block until a handshake completes. A failed handshake is ignored."""
        while True:
            syn = self._wait_syn(port)
            conn = TCPConnection(
                self.transport,
                self.logger,
                self.ipids,
                syn.dst_ip,  # reply from the address the SYN was sent to
                port,
                syn.src_ip,
                syn.src_port,
                isn if isn is not None else random_isn(),
            )
            self.logger.recv(syn)
            try:
                conn.start_passive(syn)
                conn.wait_established(HANDSHAKE_TIMEOUT)
                return conn
            except TCPError as exc:
                debug(f"handshake gave up: {exc}")
                conn.user_closed = True
                continue

    def _wait_syn(self, port: int) -> Packet:
        while True:
            while True:
                try:
                    readable, _, _ = select.select([self.transport.fileno()], [], [], None)
                    break
                except InterruptedError:
                    continue
            if not readable:
                continue
            while True:
                raw = self.transport.recv_packet()
                if raw is None:
                    break
                pkt = parse_packet(raw)
                if pkt is None:
                    continue
                if pkt.dst_port != port:
                    continue
                if pkt.flags & RST:
                    continue
                # A SYN that already carries ACK is a SYN-ACK, not a new connection.
                if (pkt.flags & SYN) and not (pkt.flags & ACK):
                    return pkt

    def close(self) -> None:
        self.transport.close()
