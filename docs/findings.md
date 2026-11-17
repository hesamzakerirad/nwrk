---
title: Findings
description: Every diagnostic rule, what it observes, and when it can be wrong.
weight: 7
---

A finding states what was observed, in technical terms. It is produced by a rule from the [measurements](../measurements/) and always points at the measurements that support it. Rules are deterministic: the same measurements give the same findings. Each rule has a version that changes whenever its conditions or wording change.

Every rule below lists **when it can be wrong**. These caveats are printed with each finding. If a finding was wrong for you, please open a "Rule false positive" issue.

## Severity

`error` means nothing at that layer worked. `warning` means part of it failed, or a server error. `info` is context and does not change the exit status. `error` and `warning` make `nw diagnose` exit with status `1`.

## DNS_RESOLUTION_FAILURE

**Layer:** dns. **Fires when** a resolver did not return an address for the name. `error` when no resolver returned one, `warning` when another resolver did.

**Observes:** the resolver and the error code (`dns.nxdomain`, `dns.no_answer`, `dns.timeout`, `dns.servfail`, `dns.refused`, `dns.transport`).

**When it can be wrong:**
- A differing or missing DNS answer is an observation, not proof of manipulation. Split-horizon DNS, CDNs, caches and geography can all explain differences between resolvers.
- The system resolver is queried through the operating system, which does not report response codes. For it, `dns.no_answer` can also mean the name does not exist.
- A short `--timeout` makes a slow resolver look unreachable.

**Typical hypotheses:** the name does not exist; the resolver filters or has a stale cache; the resolver is unreachable; an upstream or DNSSEC failure; the resolver refuses this client.

## NO_USABLE_ADDRESS

**Layer:** dns. **Fires when** the name resolved but nothing can be connected to: every address returned by a resolver is a placeholder such as `0.0.0.0` or `::`, or no route exists to any address. `error`.

**When it can be wrong:**
- A placeholder address is a convention used by many kinds of DNS filters, and also appears in misconfigured zones. The address alone does not say which.
- No route to an address is a property of this network at this moment, not of the destination. An IPv6-only answer on an IPv4-only network is the common case.

**Typical hypotheses:** a DNS filter or policy returned a placeholder; the zone is misconfigured; this network has no route for the address family.

## TCP_CONNECTION_REFUSED

**Layer:** tcp. **Fires when** an address actively refused the connection (`tcp.refused`). `error` if every connection failed, `warning` if some succeeded.

**When it can be wrong:**
- A refusal can come from the destination host, from a firewall in front of it, or from a device on the path that rejects connections. The error does not say which.
- A refusal on one address while others succeed is common during maintenance and with load balancers.

**Typical hypotheses:** nothing listens on the port; a firewall or device on the path rejects the connection.

## TCP_CONNECTION_TIMEOUT

**Layer:** tcp. **Fires when** an address did not answer before the deadline (`tcp.timeout`). `error` if every connection failed, `warning` otherwise.

**When it can be wrong:**
- A timeout means no answer arrived in time. Packet loss, a slow path, a dropped connection attempt and a filtered port all look the same.
- The deadline is set by `--timeout`. A slow but working path can time out when it is short.

**Typical hypotheses:** packets are dropped or filtered on the path or by the destination's firewall; the host is down or overloaded.

## TLS_CERTIFICATE_INVALID

**Layer:** tls. **Fires when** certificate verification failed: `tls.cert_expired`, `tls.cert_untrusted` or `tls.hostname_mismatch`. `error`, or `warning` if another address verified.

**When it can be wrong:**
- Verification uses this machine's trust store and clock. A wrong clock or a missing root certificate here gives the same error as a bad certificate on the server.
- A certificate for a different name can mean the server is misconfigured, or that the connection reached a different server than intended.

**Typical hypotheses:** the certificate expired or the local clock is wrong; the chain is not trusted (self-signed, missing intermediate, or a device on the path presenting its own certificate); the certificate was issued for other names.

## TLS_HANDSHAKE_FAILURE_AFTER_TCP

**Layer:** tls. **Fires when** the TCP connection to an address succeeded but the TLS handshake with the same address did not (`tls.handshake_failure`, `tls.reset`, `tls.timeout`, `tls.error`). `error`, or `warning` if another address completed the handshake.

**When it can be wrong:**
- A failed handshake can come from the server's configuration, this client's configuration, a proxy or other device on the path, or interference with the connection. The error does not distinguish these.
- Certificate problems are reported by `TLS_CERTIFICATE_INVALID`, not here.

**Typical hypotheses:** the server rejected the handshake or failed; a proxy or other device on the path interfered. A reset or silence makes the second more likely than an alert from the server, and both stay low to medium.

## HTTP_ERROR_RESPONSE

**Layer:** http. **Fires when** the final response has a status of 400 or above. `warning` for 5xx and 429; `info` for other 4xx.

**When it can be wrong:**
- A 4xx status usually reflects the requested path or access rules, not the network. That is why it is informational: a 404 on the root path does not make `nw diagnose` exit with `1`.
- CDNs and bot protection can answer a bare command-line client differently from a browser. nw sends no cookies and a minimal User-Agent.
- A response proves some server answered, not that it is the intended origin.

**Typical hypotheses:** the origin or an upstream is failing (5xx); rate limiting (429); access rules (401, 403); the path does not exist (404).

## HTTP_REQUEST_FAILURE

**Layer:** http. **Fires when** the request itself failed at the HTTP level: `http.timeout`, `http.redirect_loop`, `http.protocol_error`, `http.reset`, `http.error`. `error` if every request failed, `warning` otherwise.

**When it can be wrong:**
- A timeout after the connection and TLS succeeded means the server stayed silent. A slow server and a stalled path look the same.
- Failures in DNS, TCP or TLS during the request are reported by the rules of those layers.

**Typical hypotheses:** redirects that lead back to themselves; a server that accepted the connection but did not answer; a port served by something that is not an HTTP server.

## IP_FAMILY_BEHAVIOR_DIFFERENCE

**Layer:** ip_family. **Fires when** the name has both IPv4 and IPv6 addresses and one family works at a layer (TCP, TLS or HTTP) where the other fails. `warning`, or `info` when IPv6 fails only because this network has no IPv6 route.

**When it can be wrong:**
- A name with no AAAA record is not an IPv6 failure, and this rule does not fire for it.
- Many networks have no IPv6 connectivity at all. That case is informational.

**Typical hypotheses:** this network has no IPv6; the IPv6 (or IPv4) path or service is broken or filtered while the other family works.

## UNCLASSIFIED_FAILURE

**Layer:** other. **Fires when** a measurement failed and no other rule explains it, for example a reset during the TCP connection. `warning`. It exists so that a failure is never silent: read the error code and message of the measurements it lists.
