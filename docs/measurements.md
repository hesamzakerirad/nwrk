---
title: Measurements
description: What nw test dns, tcp, tls and http measure, and what each error code means.
weight: 4
---

A measurement is one test with one structured result. It records what happened, not what it means: a failed measurement is evidence, and interpreting evidence is the job of later commands. Everything here runs on your machine, and nw sends nothing anywhere except the packets of the tests themselves.

Every measurement has an ID, a type, a status, start and end times, a duration, a target, and either a result or an error. The [report schema](../report-schema/) lists every field.

## Statuses

| Status | Meaning |
|---|---|
| `success` | The measurement completed and the check passed |
| `failure` | The measurement ran and the check did not pass; `error.code` says how |
| `skipped` | A step it depends on failed, so it did not run; `note` says why |
| `inconclusive` | It ran but proves nothing, for example a local check that could not read the system; `note` says why |

## DNS

`nw test dns <host>` asks for the A and AAAA records of a name, both at once.

- The **system resolver** is always measured first, as the baseline. It uses the operating system's own resolver, so it behaves like your applications: it honors the hosts file and search domains. The name servers your system is configured with are listed in `resolver.servers`. The operating system does not report DNS response codes, so for the system baseline an NXDOMAIN and an empty answer are both reported as `dns.no_answer`.
- Each **`--resolver`** is queried directly, over UDP (retrying over TCP when the answer is truncated) or over TCP for `tcp://`. These report the exact response code (`NOERROR`, `NXDOMAIN`, `SERVFAIL`, `REFUSED`), CNAME chains and timings.
- A name with an A record but no AAAA record is a **success**. A missing AAAA is normal and is never counted as an IPv6 failure. The per-type result keeps the evidence.
- Differences between resolvers are observations. Split-horizon DNS, CDNs, caches and geography all produce legitimate differences.

| Error code | Meaning |
|---|---|
| `dns.nxdomain` | The resolver said the name does not exist |
| `dns.no_answer` | The name exists but there were no A or AAAA records (also what the system baseline reports for "not found") |
| `dns.servfail` | The resolver reported a failure while answering |
| `dns.refused` | The resolver refused to answer |
| `dns.timeout` | No response before the deadline |
| `dns.transport` | The resolver could not be reached at all |
| `dns.error` | Another response code |

## TCP

`nw test tcp <host:port>` resolves the host (a name needs DNS; an IP address does not) and connects to each address on the port, IPv4 and IPv6 separately. The connection is closed right after it opens and nothing is sent.

| Error code | Meaning |
|---|---|
| `tcp.refused` | The destination answered that nothing listens on the port |
| `tcp.timeout` | No answer before the deadline (packets dropped or filtered) |
| `tcp.unreachable` | No route to the network or host |
| `tcp.reset` | The connection was reset |
| `tcp.error` | Another operating system error |

## TLS

`nw test tls <host[:port]>` completes a handshake with each address and verifies the certificate chain and the name. Verification is always on, and there is no option to turn it off. The report keeps the certificate details even when verification fails, because they are the evidence: subject, issuer, validity period, names (SANs), and whether the chain verified.

Certificate errors are kept apart from handshake errors, because the causes and next steps differ.

| Error code | Meaning |
|---|---|
| `tls.cert_expired` | The certificate is expired or not yet valid |
| `tls.cert_untrusted` | The chain does not lead to a trusted authority |
| `tls.hostname_mismatch` | The certificate is not valid for the name you asked for |
| `tls.handshake_failure` | The handshake failed for another reason, for example an alert from the server, a server that does not speak TLS, or a closed connection |
| `tls.reset` | The connection was reset during the handshake |
| `tls.timeout` | The handshake did not finish before the deadline |
| `tls.error` | Another failure |

A failed handshake can have many causes: server configuration, client configuration, a proxy, or interference on the path. The report states what was seen and does not guess which.

## HTTP

`nw test http <url>` makes one request, `GET` unless you pass `--method HEAD`, and follows up to `--max-redirects` redirects. The request goes directly: proxy environment variables are ignored, so you measure the path itself.

- Each request in the chain is a **hop** with its own timings: DNS, connect, TLS, first byte and total, in milliseconds. A stage that did not happen, such as TLS on plain HTTP, is left out.
- Up to 1 MiB of the body is read and thrown away, so the total includes the transfer. **Bodies, cookies and authorization headers are never stored.** Only a short list of diagnostic response headers is kept (server, content type and length, cache control, via, alt-svc, strict transport security, retry-after, date).
- A response with any status code is a completed measurement. A `503` is a `success` with `status_code: 503`; whether that is a problem is judged by `nw diagnose`; see [Findings](../findings/).
- Errors from the stages below are reported with their own codes, so an HTTP request that fails in TLS says `tls.cert_expired`, not a generic HTTP error.

| Error code | Meaning |
|---|---|
| `http.timeout` | No complete response before the deadline, after the connection was established |
| `http.redirect_loop` | A URL was requested twice, or there were more redirects than allowed |
| `http.protocol_error` | The server's reply was not valid HTTP, or a redirect went somewhere unsupported |
| `http.reset` | The connection was reset after it was established |
| `http.error` | Another failure |

Plus every `dns.*`, `tcp.*` and `tls.*` code above, when the failure happened in that stage.

## Local checks

`nw doctor` also inspects this machine's own network setup. These measurements have type `local`, scope `local`, and a `params.check` of `interfaces`, `route`, `resolvers` or `proxy`. Their results record counts and kinds, never addresses or interface names, so a report can be shared safely. They read the operating system and send nothing; see [Platform support](../platform-support/) for what each platform can read.

- **interfaces**: is any interface up, not loopback, with an address that is not link-local? Counts of interfaces and the address families in use.
- **route**: does the operating system have a default route for IPv4 and for IPv6? It asks which route it would use and sends no packet.
- **resolvers**: how many DNS servers are configured, by kind (private, global, loopback), and where the configuration was read from.
- **proxy**: whether a proxy is set. It is always a `success`: a proxy is context, not a fault. Credentials are never kept.

A local check that could not read the system is `inconclusive`, with the reason in `note`, rather than a failure.

| Error code | Meaning |
|---|---|
| `local.no_interface` | No interface is up with an address that can reach beyond this machine |
| `local.no_route` | The operating system has no route to the internet for IPv4 or IPv6 |
| `local.no_resolver` | The operating system has no DNS server configured |

## Deadlines

`--timeout` (default 10 seconds) is the deadline of each measurement. Press Ctrl-C to stop a run: nw closes its connections, prints nothing partial, and exits with status 130.
