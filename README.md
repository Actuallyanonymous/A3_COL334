# Assignment 3

Team: 2024CS50081, Daanveer (2024CS50125)

Language: Python 3 (standard library only). Developed to run on Ubuntu 22.04 / Python 3.10. There is no compiler. `make` only byte-compiles the sources so a missing import fails before you boot the VMs.

```bash
make
python3 tests/test_assignment.py
```

The programs themselves are started with the launchers, from any working directory:

```bash
sudo ./client/run-client URL [-o OUTFILE] [--log LOGFILE]
sudo ./server/run-server [-p PORT] [-d DOCROOT] [--log LOGFILE]
```

`server` defaults are `-p 8080` and `-d ./www`.

## Layout

```
netcfg/client.sh     host:  LAN A 10.10.1.10/24, Link D 10.10.4.2/30
netcfg/r1.sh         router: LAN A 10.10.1.1/24,  LAN B 10.10.2.1/24
netcfg/r2.sh         router: LAN B 10.10.2.2/24,  LAN C 10.10.3.1/24, Link D 10.10.4.1/30
netcfg/server.sh     host:  LAN C 10.10.3.10/24
client/run-client
server/run-server
src/                 TCP stack, HTTP client, HTTP server
www/                 tiny docroot so the server has something to serve
```

Each netcfg script is run once, as root, with the interface names for that VM:

```bash
sudo ./netcfg/client.sh IF_A IF_D
sudo ./netcfg/r1.sh     IF_A IF_B
sudo ./netcfg/r2.sh     IF_B IF_C IF_D
sudo ./netcfg/server.sh IF_C
```

Find the names with `ip -br link`. Pass only the internal NICs. Do not pass the NAT adapter.

Before the first run, the assignment wants `rp_filter=1` on every interface (Ubuntu's default is 2). The scripts then keep r1 and the server strict, and move the client and r2 to loose mode. Setting the starting point:

```bash
sudo sysctl -w net.ipv4.conf.all.rp_filter=1
sudo sysctl -w net.ipv4.conf.default.rp_filter=1
for name in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 1 | sudo tee "$name" >/dev/null; done
```

`iptables` has to be installed (the launchers use it). Do that while the NAT adapter still has a route out, then you can leave NAT attached or not; the scripts never configure it.

```bash
sudo apt install iptables
```

Copy this tree onto each VM (shared folder, or `git clone` while NAT works). The internal networks have no DHCP and no path to the public internet.

## The network

```
client ---- LAN A ---- r1 ---- LAN B ---- r2 ---- LAN C ---- server
   \                                  /
    \------------ Link D ------------/
```

Two directions are required to take different paths:

- client to server: `client -> r1 -> r2 -> server` (LAN A, LAN B, LAN C)
- server to client: `server -> r2 -> client` over Link D, skipping r1

r1 and r2 forward. The client and the server must not.

### Why r2 has two routes into LAN A

A single route for all of 10.10.1.0/24 cannot do both jobs. If it points at r1, server-to-client traffic goes back through r1 and misses Link D. If it points across Link D at the client, the client would have to forward packets onward to r1, and hosts are not allowed to forward.

So r2 has a host route for the client only, and a network route for everyone else:

```
10.10.1.10/32  via 10.10.4.2   dev IF_D     # the client, over Link D
10.10.1.0/24   via 10.10.2.1   dev IF_B     # r1 and the rest of LAN A
```

Longest prefix wins. The next hop on Link D is 10.10.4.2 (the address the client actually owns on that link). The IP packet is still addressed to 10.10.1.10. Linux delivers that to the client anyway: a host accepts a packet for any of its own addresses on any interface. r2 has no default route.

### Why r1 has one /16

r1 is attached to LAN A and LAN B. Everything else it must reach (LAN C and Link D) is one prefix, `10.10.0.0/16`, via r2 at 10.10.2.2. The connected /24s are longer, so they still win for A and B. That is the single extra route A5 asks for.

The client reaches LAN B and LAN C via r1 (`10.10.1.1`), which is what forces client-to-server through r1. The server reaches LAN A and LAN B via r2 (`10.10.3.1`); r2's host route bends only the client onto Link D.

### Why reverse-path filtering is not the same on every machine

Strict mode (1) drops a packet whose source would not be routed back out the interface it arrived on. That is correct on r1 and on the server, and the assignment says it must stay strict there:

- On r1, the client is reached out of LAN A and r2's networks are reached out of LAN B, which is also where those packets arrive.
- The server has one interface. Everything arrives on it and everything leaves on it.

It is wrong on the client and on r2, because the two directions use different links:

- A packet from the client (source 10.10.1.10) arrives at r2 on LAN B, but r2's route back to 10.10.1.10 points out Link D. Strict mode would drop every client-to-server packet.
- The reply (source 10.10.3.10) arrives at the client on Link D, but the client's route to 10.10.3.0/24 points out LAN A. Strict mode would drop the reply.

Those two machines use loose mode (2): the source must be reachable via some interface, not specifically the one the packet arrived on. The kernel's effective value is `max(conf/all, conf/<interface>)`, so the scripts set both. They also turn ICMP redirects off, so the kernel cannot "fix" the asymmetric paths.

Check, after the scripts:

```bash
ip -br addr
ip route
ip route get 10.10.3.10     # on the client: via 10.10.1.1
ip route get 10.10.1.10     # on the server: via 10.10.3.1
ip route get 10.10.1.10     # on r2: via 10.10.4.2
ip route get 10.10.1.1      # on r2: via 10.10.2.1
ip route get 10.10.3.10     # on r1: via 10.10.2.2
sysctl net.ipv4.conf.all.rp_filter
sysctl net.ipv4.ip_forward
```

`traceroute -n` from the client to the server should show r1, then r2, then the server. The interesting address is r2's. The ICMP Time Exceeded is sourced from the address on the interface facing the original sender. r2's route back to the client leaves via Link D, so that hop is expected to be **10.10.4.1**, not 10.10.2.2. The reverse traceroute (server to client) is only two hops, 10.10.3.1 then 10.10.1.10, because the return path never visits r1. Confirm both on the VMs and use whatever address actually appears; the reason is the route back to the machine that sent the probe.

## TCP and HTTP

`src/wire.py` builds and parses the IPv4 and TCP headers, including both checksums. The socket is `AF_INET` / `SOCK_RAW` / `IPPROTO_TCP` with `IP_HDRINCL`, so the kernel does not supply an IP header.

`src/tcp_conn.py` is one connection:

- SYN and SYN-ACK carry a single option, MSS 1460. Anything else we receive is ignored except the peer's MSS. Data segments are at most `min(1460, peer MSS)`.
- Handshake retransmits within 1s and keeps trying for 7s. A RST aborts the connection.
- The receive window is fixed at 65535. Out-of-order bytes inside that window are kept and delivered once, in order. Every data segment, duplicate or not, gets a cumulative ACK.
- Sending is limited by both the congestion window and the peer's advertised window. Loss cuts the window (Reno: slow start, then additive increase, timeout back to one segment, plus a fast retransmit on three duplicate ACKs). Nothing acknowledged for 10s gives up. The retransmission timer never exceeds 1s.
- Close ACKs the peer's FIN, retransmits ours until it is ACKed, and waits for theirs, but no longer than 2s. There is no TIME_WAIT.

The kernel's own TCP still sees these packets and would RST them, because it has no socket for the port. The launchers drop those RSTs: the client rule covers source ports 61000–65535 (above Ubuntu's default ephemeral range, so curl and wget are left alone), and the server rule covers the listen port only. The rules stay installed after the process exits; delete one with `iptables -D` if it gets in the way.

`src/http_client.py` does one HTTP/1.1 GET with `Connection: close` and no `Accept-Encoding`. It understands Content-Length, chunked transfer (extensions and trailers ignored), and a body that ends when the server FINs. The status line goes to stderr, the body to `-o` or stdout. Exit 0 is a complete 2xx, exit 1 is any other complete status (body still saved, redirects not followed), exit 2 is anything that did not finish.

`src/http_server.py` serves one request per connection and stays up. The response is chosen in the order in the assignment: bad request line, method other than GET or HEAD, a `..` path segment, missing file, otherwise 200. A directory (or a path ending in `/`) maps to `index.html`. HEAD sends the same headers as GET and no body. An unfinished request head in 10 seconds is closed with no response.

## What still has to be done on the VMs

The routing scripts and the programs are in this tree. Screenshots for `report.pdf` have to be taken on the four VMs; they cannot be produced from this machine. For the report:

1. Network-adapter settings of all four VMs, plus `ip -br addr` and `ip route` on each.
2. `traceroute -n` client to server and server to client, with the path explanation above (and why r2's hop address is the one you see).
3. `sysctl net.ipv4.conf.all.rp_filter` (and the per-interface values) on each machine, with the reason above. r1 and the server must be 1. The client and r2 are 2.
4. From the client, download an HTML page and a file of at least 100KB from a normal server on the server VM, for example `python3 -m http.server 8000` in some directory there. Record both exit codes. `md5sum` of each file must match `curl` fetching the same URL.
5. `curl`, `wget`, and `./client/run-client` all fetching one file from `./server/run-server`. All three checksums match the original.
6. One `tcpdump -nn` or Wireshark capture of a complete connection, plus a short description of retransmission (oldest unacked segment, at most 1s, give up after 10s with no progress), the out-of-order buffer (held until the gap in front is filled, then delivered once), and congestion control (slow start, additive increase, halve on loss).

A binary for item 4:

```bash
dd if=/dev/urandom of=www/big.bin bs=1024 count=200
```

Set `TCP_DEBUG=1` in the environment if a handshake fails and you want the drop/timeout lines on stderr. `--log` writes the Table 3 packet log.
