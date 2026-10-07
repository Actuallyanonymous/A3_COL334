#!/bin/bash
# r1.sh IF_A IF_B
#
# Router between LAN A (10.10.1.1/24) and LAN B (10.10.2.1/24).
#
# A5: every network r1 is NOT attached to (LAN C 10.10.3.0/24 and
# Link D 10.10.4.0/30) is reached by ONE static route, and there are
# no other static routes. 10.10.0.0/16 covers both. The connected
# /24s are longer prefixes, so they still win for LAN A and LAN B:
#
#   10.10.1.0/24   dev IF_A          (connected, more specific)
#   10.10.2.0/24   dev IF_B          (connected, more specific)
#   10.10.0.0/16   via 10.10.2.2     (the single extra route)
#
# Client -> server therefore arrives on LAN A and leaves toward r2
# on LAN B (A2). Return traffic does not come back through r1 (A3).
#
# Strict reverse-path filtering stays on (A7). It still passes here:
#   - client sources arrive on LAN A, and the route back is LAN A
#   - r2's networks arrive on LAN B, and the /16 route back is LAN B

set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: r1.sh IF_A IF_B" >&2
    exit 1
fi

IF_A="$1"
IF_B="$2"

sysctl_path() {
    printf '%s' "${1//.//}"
}

ip link set dev "$IF_A" up
ip link set dev "$IF_B" up

ip addr replace 10.10.1.1/24 dev "$IF_A"
ip addr replace 10.10.2.1/24 dev "$IF_B"

# A4: r1 is a router.
sysctl -qw net.ipv4.ip_forward=1

# A7: stay strict. Set `all` as well as the interfaces because the
# kernel uses max(all, interface).
sysctl -qw net.ipv4.conf.all.rp_filter=1
sysctl -qw net.ipv4.conf.default.rp_filter=1
sysctl -qw "net.ipv4.conf.$(sysctl_path "$IF_A").rp_filter=1"
sysctl -qw "net.ipv4.conf.$(sysctl_path "$IF_B").rp_filter=1"

# Forwarding turns ICMP redirects on. A redirect would try to "fix"
# the asymmetric path the assignment requires, so turn them off.
sysctl -qw net.ipv4.conf.all.send_redirects=0
sysctl -qw net.ipv4.conf.all.accept_redirects=0
sysctl -qw "net.ipv4.conf.$(sysctl_path "$IF_A").send_redirects=0"
sysctl -qw "net.ipv4.conf.$(sysctl_path "$IF_B").send_redirects=0"

# A5: one route for every network we are not attached to.
ip route replace 10.10.0.0/16 via 10.10.2.2 dev "$IF_B"

echo "r1 ready: $IF_A=10.10.1.1/24  $IF_B=10.10.2.1/24  rp_filter=strict"
