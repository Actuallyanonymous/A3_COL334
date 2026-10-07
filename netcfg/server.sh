#!/bin/bash
# server.sh IF_C
#
# Host on LAN C (10.10.3.10/24). One interface, so every off-link
# packet goes to r2 (10.10.3.1). r2 then sends packets for the client
# (10.10.1.10) out Link D, which is requirement A3:
#
#   server -> r2 -> client   over Link D
#
# Strict reverse-path filtering stays on (A7). It works with one
# interface: a packet from the client arrives on LAN C (r2 forwarded
# it) and the route back to 10.10.1.10 is also LAN C, toward r2.
#
# This host must not forward (A4).

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: server.sh IF_C" >&2
    exit 1
fi

IF_C="$1"

sysctl_path() {
    printf '%s' "${1//.//}"
}

ip link set dev "$IF_C" up
ip addr replace 10.10.3.10/24 dev "$IF_C"

# A4: the server is a host.
sysctl -qw net.ipv4.ip_forward=0

# A7: stay strict. max(all, interface) is what the kernel actually uses.
sysctl -qw net.ipv4.conf.all.rp_filter=1
sysctl -qw net.ipv4.conf.default.rp_filter=1
sysctl -qw "net.ipv4.conf.$(sysctl_path "$IF_C").rp_filter=1"

sysctl -qw net.ipv4.conf.all.accept_redirects=0
sysctl -qw net.ipv4.conf.all.send_redirects=0
sysctl -qw "net.ipv4.conf.$(sysctl_path "$IF_C").accept_redirects=0"

# A1: LAN A and LAN B. LAN C is connected. Both go through r2, and
# r2's /32 for 10.10.1.10 bends only the client onto Link D.
ip route replace 10.10.1.0/24 via 10.10.3.1 dev "$IF_C"
ip route replace 10.10.2.0/24 via 10.10.3.1 dev "$IF_C"

echo "server ready: $IF_C=10.10.3.10/24  rp_filter=strict"
