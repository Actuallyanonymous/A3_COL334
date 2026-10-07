#!/bin/bash
# client.sh IF_A IF_D
#
# Host on LAN A (10.10.1.10/24) and Link D (10.10.4.2/30).
#
# Forward path to the server (requirement A2):
#   client -> r1 -> r2 -> server
# so LAN B and LAN C are reached via r1's LAN A address, 10.10.1.1.
# Link D is directly connected and is NOT used for that direction.
#
# Return traffic from the server comes back in on Link D (A3), while the
# route to the server still points out LAN A. That is asymmetric, so strict
# reverse-path filtering would drop the replies. Loose mode (2) accepts a
# source that is reachable via any interface. r1 and the server stay strict;
# this host is allowed to relax it (A7).
#
# This host must not forward (A4).

set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: client.sh IF_A IF_D" >&2
    exit 1
fi

IF_A="$1"
IF_D="$2"

# sysctl treats "." as a separator, so an interface like "eth0.10"
# is written "eth0/10" in the sysctl path.
sysctl_path() {
    printf '%s' "${1//.//}"
}

ip link set dev "$IF_A" up
ip link set dev "$IF_D" up

# `replace` is the same as `add` on a fresh boot and lets us re-run
# the script while debugging without deleting the address first.
ip addr replace 10.10.1.10/24 dev "$IF_A"
ip addr replace 10.10.4.2/30 dev "$IF_D"

# A4: the client is a host.
sysctl -qw net.ipv4.ip_forward=0

# Effective rp_filter is max(conf/all, conf/<if>). Set both, or a
# pre-existing `all=2` (Ubuntu's default) would win over a per-if 1,
# and a pre-existing per-if 1 would not become loose unless `all` is 2.
sysctl -qw net.ipv4.conf.all.rp_filter=2
sysctl -qw net.ipv4.conf.default.rp_filter=2
sysctl -qw "net.ipv4.conf.$(sysctl_path "$IF_A").rp_filter=2"
sysctl -qw "net.ipv4.conf.$(sysctl_path "$IF_D").rp_filter=2"

# Don't let an ICMP redirect pull server-bound traffic onto Link D.
sysctl -qw net.ipv4.conf.all.accept_redirects=0
sysctl -qw net.ipv4.conf.all.send_redirects=0
sysctl -qw "net.ipv4.conf.$(sysctl_path "$IF_A").accept_redirects=0"
sysctl -qw "net.ipv4.conf.$(sysctl_path "$IF_D").accept_redirects=0"

# A1: every address on LAN B and LAN C. A2: those packets go to r1.
ip route replace 10.10.2.0/24 via 10.10.1.1 dev "$IF_A"
ip route replace 10.10.3.0/24 via 10.10.1.1 dev "$IF_A"

echo "client ready: $IF_A=10.10.1.10/24  $IF_D=10.10.4.2/30  rp_filter=loose"
