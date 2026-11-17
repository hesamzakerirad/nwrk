---
title: Platform support
description: What nw can inspect on Linux, macOS and Windows, and every known limitation.
weight: 9
---

nw runs on Linux, macOS and Windows, on `amd64` and `arm64`. The measurements (`nw test`, `nw diagnose`) behave the same everywhere. Inspecting the local network (`nw network`, and the local checks of `nw doctor`) reads the operating system, and a few things are not available everywhere. This page lists every limitation we know of.

nw prefers native operating system interfaces to parsing the output of other programs, so it does not depend on tools like `ip`, `route` or `ipconfig` being installed.

## What is read, and how

| Information | Linux | macOS | Windows |
|---|---|---|---|
| Interfaces and addresses | Go standard library (system call) | same | same |
| Routing table | `/proc/net/route` and `/proc/net/ipv6_route` | routing socket (`sysctl`) | not available, see below |
| DNS servers | `/etc/resolv.conf` | `/etc/resolv.conf` | adapter settings (IP Helper API) |
| DNS search domains | `/etc/resolv.conf` | `/etc/resolv.conf` | not shown |
| Proxy: environment | yes | yes | yes |
| Proxy: system settings | not applicable | not read, see below | per-user Internet Settings (registry) |
| Default route exists | operating system route lookup, no packet sent | same | same |

## Limitations

**Windows: the routing table is not available.** `nw network routes` reports that it is not supported, and `nw network show` says the default route is unavailable. `nw doctor` still checks that a default route exists, through the operating system's route lookup, which works on every platform.

**Windows: DNS search domains are not shown.** Only the servers are read.

**macOS: system proxy settings are not read.** They live in the SystemConfiguration framework, which nw does not link. Only the proxy environment variables are shown. nw itself ignores proxies either way.

**macOS and Linux: the DNS servers shown are those in `/etc/resolv.conf`.** That file does not always reflect what applications use:

- On Linux with `systemd-resolved`, it usually lists the local stub (`127.0.0.53`), not the upstream servers.
- On macOS, per-domain and per-interface resolvers, managed by the system, are not all visible in the file.
- A system that resolves names through another mechanism may be reported as having no DNS server. That is a warning in `nw doctor`, and its caveat says so.

**The system resolver measurement uses the operating system's own lookup**, so it behaves like your applications: it honors the hosts file and search domains. That API does not report DNS response codes, so for the system resolver a missing name and an empty answer both appear as `dns.no_answer`. A resolver you name with `--resolver` is queried directly and reports exact response codes.

**Virtual interfaces count.** VPN, container and virtual-machine interfaces that are up with an address are counted as able to reach beyond this machine. A VPN client can also change the routing table.

**IPv6 may legitimately be missing.** A network without IPv6 is normal. It is reported as informational, never as a fault of the destination.

**Containers and sandboxes.** In a container or sandbox the interfaces, routes and resolvers that nw sees are the container's. A sandbox that forbids reading `/proc` or route lookups makes the local checks inconclusive rather than failed.

**Other systems.** nw is built for Linux, macOS and Windows only. On other systems the routing table is reported as not supported.

## Path probes

| | Linux | macOS | Windows |
|---|---|---|---|
| `path ping`, ICMP | Unprivileged datagram ICMP socket when your group is allowed by `net.ipv4.ping_group_range`; otherwise a raw socket (root or `CAP_NET_RAW`) | Unprivileged datagram ICMP socket | Raw socket, needs an administrator |
| `path ping`, TCP | works | works | works |
| `path trace`, ICMP (lists routers) | Needs root or `CAP_NET_RAW` | Needs root | Not available |
| `path trace`, TCP | Works; shows how many hops away the destination answers, cannot see routers | same | same |
| `path mtu`: segment size | Read from the connection | Read from the connection | Not reported |

**ICMP needs privileges on some systems.** When the system refuses, `ping` and `trace` with the default `--method auto` use TCP and print why. Asking for `--method icmp` explicitly fails with exit status 2 and says what would allow it.

**TCP trace cannot list routers.** An unprivileged TCP socket never sees the ICMP Time Exceeded messages that routers send. The result is the TTL at which the destination first answers, which is an upper bound on the hop count.

**A hop with no reply proves nothing.** Routers commonly filter or rate-limit ICMP while forwarding traffic normally.

**`path mtu` is a hint, not a discovery.** Finding the exact path MTU needs Don't-Fragment probes and ICMP feedback, which nw does not do. The command reports the MTU of the interface a connection uses and the maximum segment size it negotiated. Tunnels and VPNs show up as a lower segment size, but so does a device that clamps it.

**The ICMP trace has only been written against the documented behavior.** It needs privileges to exercise, and it has not yet been run on every platform; please report anything that looks wrong.

## DNS over TLS and HTTPS

A host name in a `tls://` or `https://` resolver is resolved by the operating system to connect, so that one lookup uses the system resolver and is not measured. Use an IP address to avoid it. The certificate must be valid for the host in the address, including an IP address, when that is what you give.

## Reporting a limitation

If nw misreports your setup, please open a bug report with the output of `nw network show --output json` (check it for anything private first) and your platform. Every confirmed limitation is added to this page.
