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

## Reporting a limitation

If nw misreports your setup, please open a bug report with the output of `nw network show --output json` (check it for anything private first) and your platform. Every confirmed limitation is added to this page.
