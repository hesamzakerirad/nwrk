---
title: Investigating interference
description: How nw looks for signs that DNS, TLS or HTTP traffic is being altered, and how to read what it finds.
weight: 11
---

Sometimes a destination fails, or answers differently, because something between you and it treats the traffic differently: a DNS filter, a proxy, a device that resets or answers connections. `nw security interference` looks for **signs** of that. It compares what different parties return and how the same request behaves when one thing changes. It does not conclude that interference happened. A single timeout or mismatch has many ordinary explanations, and every finding says what else could produce it and what was not checked.

```sh
nw security interference example.com --resolver tls://9.9.9.9 --resolver 1.1.1.1
nw diagnose example.com --profile deep      # includes the same probes
```

## What it compares

| Check | How | Finding |
|---|---|---|
| Resolver answers | The system resolver against each `--resolver`; when they return no address in common, nw also connects to both sets of addresses | `DNS_ANSWER_MISMATCH` |
| Private addresses | A public name that resolves to a private, loopback, link-local or shared address | `DNS_PRIVATE_ADDRESS_FOR_PUBLIC_NAME` |
| Several replies | One plain UDP query is sent, and nw keeps listening for 500 ms. A resolver normally answers once | `DNS_MULTIPLE_DIFFERENT_RESPONSES` |
| Server name | At the same address, handshakes with the target name against a neutral control name | `TLS_SNI_DEPENDENT_FAILURE`, `TLS_RESET_AFTER_CLIENTHELLO` |
| Redirects | A redirect that leaves the target's registered domain | `HTTP_REDIRECT_TO_UNRELATED_HOST` |
| http and https | The same request over both, compared by where it ends and by status class | `HTTP_HTTPS_RESPONSE_DIFFERENCE` |
| Not enough to compare | The run had no independent resolver, no control handshake, or no http comparison | `INTERFERENCE_INSUFFICIENT_EVIDENCE` |

The control name for the server-name comparison is `www.example.org` unless you choose another with `--control`. That domain is reserved for documentation: it is neutral and no real service answers to it.

Each of these appears in [Findings](../findings/) with the conditions under which it is wrong.

## Encrypted resolvers

A resolver is chosen with `--resolver`, and four forms are accepted:

| Form | Transport |
|---|---|
| `host`, `host:port`, `[v6]:port` | Plain DNS over UDP (TCP on truncation) |
| `tcp://host[:port]` | Plain DNS over TCP |
| `tls://host[:port]` | DNS over TLS, port 853 by default |
| `https://host[:port][/path]` | DNS over HTTPS, port 443 and path `/dns-query` by default |

Plain DNS can be read and answered by anything on the path. Asking the same resolver over TLS or HTTPS removes that, so a difference between the plain and the encrypted answer is informative. The server certificate is always verified against the host in the resolver address. For a host name (instead of an IP address) the operating system resolves it to connect; that one lookup uses the system resolver and is not measured.

## How to read the result

- **Observations are not accusations.** Findings say what was seen (for example "the same query received two different replies"). Hypotheses offer explanations, benign ones included, with what supports each, what argues against it and what was not observed.
- **Confidence is capped.** No hypothesis reaches `high` from a single measurement, and most of these stay `low` or `medium`. A finding is `warning` only when something besides the difference supports it, for example one of two answers does not connect.
- **Silence is not "all clear".** `INTERFERENCE_INSUFFICIENT_EVIDENCE` says which comparisons could not be made. No finding means the comparisons that ran showed nothing, not that nothing is wrong.
- **Compare from elsewhere.** The most useful next step is nearly always to repeat the run from a different network or machine and see whether the difference follows the network.

## Safe operation

nw tests only the target you name, with a small and fixed set of extra requests: a few more handshakes, one more DNS query, one http request. It never scans ports, tries exploits, or tests credentials; every request has a deadline and a size limit; and it changes no setting on your system. It never labels an event with an accusation on the strength of one observation, and it ships no circumvention features.

## Other security checks

`nw security inspect` makes security-oriented observations that are independent of interference: whether the name is DNSSEC-signed and whether your resolver validates it, the CNAME chain, how soon the certificate expires, whether the server still accepts TLS 1.0 or 1.1, whether plain http is upgraded to https, and whether the site sends `Strict-Transport-Security`. See [Findings](../findings/).

## Path probes

`nw path ping`, `nw path trace` and `nw path mtu` look at the path to one destination. ICMP is often filtered, deprioritized or rate-limited, so a missing reply is never presented as proof that a router is broken or that traffic is blocked. Where ICMP needs privileges that you do not have, ping and trace use TCP instead and say so. What each platform allows is in [Platform support](../platform-support/).
