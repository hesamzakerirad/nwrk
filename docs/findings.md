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

## Findings of nw security interference

These look for signs of interference (see [Investigating interference](../interference/)). They run in `nw security interference` and in `nw diagnose --profile deep`. None of them is a verdict, none reaches `high` confidence from a single measurement, and each says what else could explain it.

### DNS_ANSWER_MISMATCH

**Layer:** dns. **Fires when**, for a name, the system resolver and another resolver returned no address in common. `info`; `warning` when something else supports the difference: one answer is a private address, or only one of the two answer sets accepts connections.

**When it can be wrong:**
- A differing DNS answer is an observation, not proof of manipulation. CDNs return different addresses by location and by resolver, split-horizon DNS serves internal views, and caches differ.
- Disjoint answers for a name served by a CDN are the normal case. The finding is stronger only when the addresses also behave differently.

### DNS_PRIVATE_ADDRESS_FOR_PUBLIC_NAME

**Layer:** dns. **Fires when** a resolver returned a private, loopback, link-local or shared-address-space address for a name that is not reserved for local use (`.local`, `.internal`, `.home.arpa`, `.test`, single-label names and similar are exempt). `warning`.

**When it can be wrong:**
- Split-horizon DNS, corporate and home networks, local development setups and VPNs return private addresses for public names on purpose.
- The system resolver honors the hosts file, so an entry there produces exactly this result.
- Captive portals and some filters answer with a private address as well; the address alone does not say which applies.

### DNS_MULTIPLE_DIFFERENT_RESPONSES

**Layer:** dns. **Fires when** a single plain UDP query was answered more than once within 500 ms, with different answers. `warning`.

**When it can be wrong:**
- A resolver normally answers once. Several different replies are consistent with a device on the path answering ahead of the real server, and also with unusual but legitimate setups, such as a load-balanced resolver address or a resolver that retries.
- The probe listens for a fixed short time, and a single probe is one observation.

### TLS_RESET_AFTER_CLIENTHELLO

**Layer:** tls. **Fires when** the TCP connection to an address succeeded and every handshake attempt with the target name (at least two) was then reset or went unanswered. `warning`; confidence is `low`, or `medium` when a control name at the same address got an answer.

**When it can be wrong:**
- A reset or silence after the hello is what a server with a broken or incompatible TLS setup produces, and what a device on the path that interferes with the connection produces. The attempt alone does not distinguish them.
- Without a comparison, such as a control name or a different network, this stays a low-confidence observation.

### TLS_SNI_DEPENDENT_FAILURE

**Layer:** tls. **Fires when**, at one address, handshakes with the target name are reset or unanswered while a handshake with the neutral control name gets an answer. `warning`, `medium` confidence at most.

**When it can be wrong:**
- A server that hosts many names may reject names it does not know, so a control name can be treated differently from the target for ordinary reasons.
- Many networks and servers are not affected by the server name at all; a difference is a prompt to compare, not a conclusion.
- Only one control name and a few attempts are used.

### HTTP_REDIRECT_TO_UNRELATED_HOST

**Layer:** http. **Fires when** a redirect in the chain points to a registered domain other than the target's. `info`; `warning` when the destination is a bare IP address.

**When it can be wrong:**
- Sites redirect to other domains on purpose: sign-in providers, regional or brand domains, CDNs and short-link services.
- A redirect to a bare IP address is unusual for a public site but also common for devices and portals on a local network.

### HTTP_HTTPS_RESPONSE_DIFFERENCE

**Layer:** http. **Fires when** the same target answered differently over http and over https: the requests end on different registered domains (`warning`), or the final status classes differ (`info`).

**When it can be wrong:**
- An http request that is redirected to https on the same host is normal and is not a difference.
- Servers legitimately answer the two schemes differently: an http-only status page, a redirect to a canonical host, or different virtual hosts.
- Only the status and the destination are compared; bodies are never stored.

### INTERFERENCE_INSUFFICIENT_EVIDENCE

**Layer:** other. **Fires when** an interference run could not make some comparisons: no independent resolver answered, no control handshake was made, or http and https were not compared. `info`.

**When it can be wrong:**
- No finding does not mean nothing is wrong. It means the comparisons that ran showed nothing.

## Findings of nw security inspect

Security-oriented observations (see [Investigating interference](../interference/)).

### DNSSEC_VALIDATION_FAILURE

**Layer:** dns. **Fires when** a validating resolver answers SERVFAIL while the same query with validation disabled returns an answer. `warning`.

**When it can be wrong:**
- A name's signatures can be broken or expired because of a mistake at its zone, and also by a change in transit.
- The check says the answer fails validation, not why; resolvers differ in how strictly they validate.

### DNSSEC_STATUS

**Layer:** dns. Whether the answer carries DNSSEC signatures and whether the resolver reports validating them. `info`.

**When it can be wrong:**
- Many names are not signed, and that is not a fault.
- The authenticated-data flag is the resolver's own statement; it is only as trustworthy as the path to the resolver.

### TLS_CERTIFICATE_EXPIRING_SOON

**Layer:** tls. **Fires when** a valid certificate expires within 14 days. `warning`.

**When it can be wrong:**
- Servers that renew automatically may replace the certificate shortly before it expires, so a near expiry can be normal.
- The date is compared with this machine's clock.

### TLS_LEGACY_PROTOCOL_ACCEPTED

**Layer:** tls. **Fires when** a handshake limited to TLS 1.0 and 1.1 succeeded; both are deprecated (RFC 8996). `warning`.

**When it can be wrong:**
- This is a property of the server's configuration, not of your connection: a client that supports TLS 1.2 or later negotiates the newer version.
- Some servers keep old versions on for legacy clients on purpose.

### HTTP_NOT_UPGRADED_TO_HTTPS

**Layer:** http. **Fires when** a request over http gets a final response over http, with no redirect to https, although the site is reachable over https. `info`.

**When it can be wrong:**
- Some sites deliberately serve only a few resources over http, such as certificate revocation or captive-portal checks.

### HTTP_HSTS_MISSING

**Layer:** http. **Fires when** the https response has no `Strict-Transport-Security` header. `info`.

**When it can be wrong:**
- The header is a hardening measure. Its absence is common and is not a fault by itself.
- Only the final response of the chain is looked at, and only the headers nw keeps.

## Findings of nw doctor

These come from `nw doctor` (see [Regions and presets](../regions/)). Findings that place the problem in the local layer decide the `local` verdict. The caveats below are printed with each finding.

### LOCAL_NO_ACTIVE_INTERFACE

**Layer:** local. **Fires when** no network interface is up with an address that can reach beyond this machine. `error`.

**When it can be wrong:**
- Interfaces are read from the operating system. A connection that is still being set up, or an adapter the system does not report, shows up as missing.
- Link-local addresses alone (169.254.x.x, fe80::) cannot reach beyond the local link, so they do not count.

### LOCAL_NO_DEFAULT_ROUTE

**Layer:** local. **Fires when** the operating system has no route to the internet for IPv4 or IPv6. `error`.

**When it can be wrong:**
- The check asks the operating system for a route to a public address and sends no packet. A route that exists but leads nowhere still passes; the reachability checks cover that.
- A VPN client can change the routing table, and a route that appears a moment later passes on the next run.

### LOCAL_NO_RESOLVER_CONFIGURED

**Layer:** local. **Fires when** the operating system has no DNS server configured. `warning`.

**When it can be wrong:**
- nw reads the configuration the platform keeps in files or adapter settings. A system that resolves names through another mechanism may be misreported; see [Platform support](../platform-support/).

### SYSTEM_RESOLVER_FAILING

**Layer:** local. **Fires when** the system resolver could not resolve reference names. `error` when every lookup failed (and then the verdict is `local`), `warning` when only some failed.

**When it can be wrong:**
- A name can fail to resolve for reasons specific to that name, which is why one failing name is only a warning.
- The system resolver is queried through the operating system, which does not report response codes.

**Typical hypotheses:** the resolver configured on this machine is unreachable or failing while others work from the same network (higher confidence when two or more other resolvers answer); name resolution does not work from here at all.

### INTERNATIONAL_UNREACHABLE

**Layer:** reachability. **Fires when** some or all international reference targets did not answer an HTTPS request. `error` when none answered, `warning` when some did.

**When it can be wrong:**
- Reachability is judged from a few reference targets. A single target can be down for its own reasons, which is why one failure among several is only a warning.
- A target that fails here may work elsewhere and the reverse; the result is about this network at this moment.

**Typical hypotheses:** traffic to international destinations is blocked, dropped or stalled beyond this machine while domestic ones work (it cites the working domestic targets); or no target answers at all and the connection is down beyond this machine. Without domestic anchors the failure cannot be placed, and the report says to select a region that has them.

### DOMESTIC_UNREACHABLE

**Layer:** reachability. The same as `INTERNATIONAL_UNREACHABLE`, for the domestic reference targets of a region such as `ir`.

### REFERENCE_RESOLVER_FAILING

**Layer:** dns. **Fires when** a resolver other than the system one did not return an address. `warning` when you chose the resolver, `info` when it came from the region preset.

**When it can be wrong:**
- A resolver can be unreachable from this network, refuse this client, or be down; the error alone does not say which.
- A public resolver that does not answer from here does not mean this machine's own resolver is wrong.

### RESOLVER_ANSWER_DIFFERENCE

**Layer:** dns. **Fires when**, for a name, the system resolver and another resolver returned no address in common. `info`, an observation.

**When it can be wrong:**
- A differing DNS answer is an observation, not proof of manipulation. CDNs return different addresses by location and by resolver, split-horizon DNS serves internal views, and caches differ.
- Disjoint answers for a CDN-hosted name are the normal case, not a fault.

### PROXY_CONFIGURED

**Layer:** local. **Fires when** a proxy is set in the environment or the system settings. `info`.

**When it can be wrong:**
- A proxy setting does not mean the proxy is in use for any given program, and nw measures the direct path without it.

## Findings of nw reach

These come from `nw reach` (see [Developer reachability](../reach/)). `nw reach` also reports `DNS_RESOLUTION_FAILURE` and `UNCLASSIFIED_FAILURE`, described above and below.

### REACH_SERVER_SIDE_RESTRICTION

**Layer:** reachability. **Fires when** an endpoint completed the exchange and the final response has status 403 or 451. `warning`. Confidence in the hypothesis is `low`, or `medium` for 451.

**When it can be wrong:**
- A 403 is also the normal answer to a request that lacks credentials, a path or a header the server expects. nw sends no cookies and a minimal User-Agent.
- CDNs and bot protection answer a command-line client differently from a browser.
- nw does not keep the response body, so it cannot tell a provider error page from an ordinary one.
- One network is one vantage point. The same answer from another network would show whether the refusal depends on the address or the region.

**Typical hypotheses:** the server, a CDN or a hosting provider restricts access from this address or region (access rules, geographic policy or legal compliance, including sanctions).

### REACH_NETWORK_INTERFERENCE

**Layer:** reachability. **Fires when** every request to an endpoint failed with a reset, a timeout or a failed handshake, or the system resolver answered a public name with a private, loopback or link-local address. `warning`. Confidence is `low`, or `medium` when at least two endpoints show the pattern and another endpoint answered.

**When it can be wrong:**
- An overloaded or offline server, a firewall at the server and a broken route produce the same resets and timeouts.
- Split-horizon DNS, corporate networks, tunnels and captive portals return private addresses for public names on purpose.
- nw measures from one network. Without a second vantage point the cause stays open.

**Typical hypotheses:** a device on the path alters, resets or drops the exchange.

### REACH_HTTP3_FAILS_TCP_WORKS

**Layer:** reachability. **Fires when** the server advertises HTTP/3 in its `Alt-Svc` header, the HTTPS request over TCP succeeded, and the HTTP/3 probe over UDP got no response. `info`.

**When it can be wrong:**
- Many networks and firewalls drop UDP port 443 without any intent to restrict a service.
- A server can advertise HTTP/3 for some of its hosts only.

**Typical hypotheses:** UDP port 443 is filtered on this network or on the path to the server.

### REACH_IP_FAMILY_DIFFERENCE

**Layer:** ip_family. **Fires when** an endpoint has IPv4 and IPv6 addresses and the request succeeded over one family and failed over the other. `warning`, or `info` when the failing family has no route.

**When it can be wrong:**
- A name with no AAAA record is not an IPv6 failure, and this rule does not fire for it.
- Many networks have no IPv6 connectivity at all. A missing route is reported as informational.

**Typical hypotheses:** this network has no route for one family; the path or the server treats the two families differently.

## UNCLASSIFIED_FAILURE

**Layer:** other. **Fires when** a measurement failed and no other rule explains it, for example a reset during the TCP connection. `warning`. It applies to `nw diagnose`, `nw doctor` and `nw reach`. It exists so that a failure is never silent: read the error code and message of the measurements it lists.
