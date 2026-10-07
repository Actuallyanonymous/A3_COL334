#!/bin/bash
# r2.sh IF_B IF_C IF_D
#
# Router on LAN B (10.10.2.2/24), LAN C (10.10.3.1/24) and
# Link D (10.10.4.1/30). No default route (A6).
#
# Two different routes into LAN A, on purpose:
#
#   10.10.1.10/32  via 10.10.4.2   Link D     the client host only
#   10.10.1.0/24   via 10.10.2.1   LAN B      everyone else on LAN A
#
# Longest prefix wins, so a packet for the client (10.10.1.10) goes
# out Link D, and a packet for r1 (10.10.1.1) still goes via r1.
# That is how server -> client travels server -> r2 -> client over
# Link D (A3) without turning the client into a router (A4).
#
# The next hop is 10.10.4.2, not "dev IF_D" alone. The client's
# address on Link D is 10.10.4.2; it will not answer ARP for
# 10.10.1.10 on that link. The IP destination stays 10.10.1.10 and
# the layer-2 destination is the MAC of 10.10.4.2.
#
# Forward packets from the client arrive on LAN B with source
# 10.10.1.10, but the route back to 10.10.1.10 points out Link D.
# Strict reverse-path filtering would drop the entire client -> server
# direction. Loose mode (2) is required on this router. A7 only forces
# strict mode on r1 and the server.

set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo "usage: r2.sh IF_B IF_C IF_D" >&2
    exit 1
fi

IF_B="$1"
IF_C="$2"
IF_D="$3"

sysctl_path() {
    printf '%s' "${1//.//}"
}

ip link set dev "$IF_B" up
ip link set dev "$IF_C" up
ip link set dev "$IF_D" up

ip addr replace 10.10.2.2/24 dev "$IF_B"
ip addr replace 10.10.3.1/24 dev "$IF_C"
ip addr replace 10.10.4.1/30 dev "$IF_D"

# A4: r2 is a router.
sysctl -qw net.ipv4.ip_forward=1

sysctl -qw net.ipv4.conf.all.rp_filter=2
sysctl -qw net.ipv4.conf.default.rp_filter=2
sysctl -qw "net.ipv4.conf.$(sysctl_path "$IF_B").rp_filter=2"
sysctl -qw "net.ipv4.conf.$(sysctl_path "$IF_C").rp_filter=2"
sysctl -qw "net.ipv4.conf.$(sysctl_path "$IF_D").rp_filter=2"

sysctl -qw net.ipv4.conf.all.send_redirects=0
sysctl -qw net.ipv4.conf.all.accept_redirects=0
sysctl -qw "net.ipv4.conf.$(sysctl_path "$IF_B").send_redirects=0"
sysctl -qw "net.ipv4.conf.$(sysctl_path "$IF_C").send_redirects=0"
sysctl -qw "net.ipv4.conf.$(sysctl_path "$IF_D").send_redirects=0"

# Rest of LAN A (including r1's 10.10.1.1) via r1. No default route.
ip route replace 10.10.1.0/24 via 10.10.2.1 dev "$IF_B"
# The client itself, and only the client, over Link D.
ip route replace 10.10.1.10/32 via 10.10.4.2 dev "$IF_D"

echo "r2 ready: $IF_B=10.10.2.2/24  $IF_C=10.10.3.1/24  $IF_D=10.10.4.1/30  rp_filter=loose"
