---
title: Diagnosing a destination
description: How nw diagnose works, its profiles, and how to read a report.
weight: 6
---

`nw diagnose <target>` investigates how this machine reaches a destination. It runs the [measurements](../measurements/) in dependency order, then applies explicit rules to the evidence. It does not guess: every finding points at the measurements that support it, and every explanation says what is known and what was not checked.

```sh
nw diagnose example.com
nw diagnose https://example.com/health --profile deep
nw diagnose example.com:8443 --resolver 1.1.1.1
```

## The target

A host name, `host:port` or a URL.

| You type | nw tests |
|---|---|
| `example.com` | https on port 443 |
| `example.com:8443` | https on port 8443 |
| `example.com:80` | http on port 80 |
| `http://example.com/path` | http, requesting that path |
| `https://example.com/health` | https, requesting that path |
| `192.0.2.1`, `[2001:db8::1]:8443` | the address itself; DNS is skipped |

## The order of work

```text
name resolution (system resolver, plus each --resolver)
        |  fails: TCP, TLS and HTTP are skipped, with the reason
        v
address selection (placeholders such as 0.0.0.0 are dropped; IPv4 and IPv6 separated)
        v
TCP connection to the addresses of each family
        |  fails for a family: TLS and HTTP for that family are skipped
        v
TLS handshake (https targets only)
        |  fails for a family: HTTP for that family is skipped
        v
HTTP request, once per IP family that is ready
        v
rules: findings, hypotheses, recommendations
```

Independent steps run at the same time, up to the profile's limit. A step that cannot run is reported as `skipped` with its reason; it is never shown as a success. IPv4 and IPv6 are tested separately, because they often behave differently. A name with no AAAA record is not an IPv6 failure.

## Profiles

Profiles are fixed and documented here. They will become configurable in a later release.

| Profile | Measures | Addresses | Simultaneous |
|---|---|---|---|
| `quick` | DNS, TCP | up to 2 per IP family | 4 |
| `standard` (default) | DNS, TCP, TLS, HTTP | TCP to up to 4 per family; TLS to the first reachable one per family; one HTTP request per family | 6 |
| `deep` | DNS, TCP, TLS, HTTP | up to 8 per family; TLS to every reachable address | 8 |

`--timeout` (default 10 seconds) is the deadline of each measurement.

## Reading the report

The human report has these parts, in this order:

1. **Summary.** The state of each layer: `ok`, `FAIL`, `partial` (some addresses worked, some did not), `skipped` or `not run` (not part of the profile). Then one line: no actionable findings, or a problem and how many findings. There is no overall score on purpose: one number would hide a critical failure.
2. **Measurements.** What was observed, one entry each. Add `--verbose` for the details of each result.
3. **Findings.** What was observed to be wrong, from the rules. Each has a severity, the measurements it rests on, and its caveats: the known ways it can be wrong.
4. **Hypotheses.** Possible explanations, labeled as such. Each says what supports it, what argues against it, and what was not observed, with a qualitative confidence of `low`, `medium` or `high`. Confidence is a rough ranking, not a probability.
5. **Next steps.** Safe things to check or measure next. nw never changes your system.
6. **Environment.** The version, platform, resolvers and run ID, so someone else can reproduce it.

Findings and hypotheses are different things. A finding is about the evidence ("the TLS handshake failed after TCP succeeded"). A hypothesis is about a possible cause ("the server's configuration is incompatible", "a device on the path interfered") and is never a verdict.

## Severity and the exit status

| Severity | Meaning | Exit status |
|---|---|---|
| `error` | Nothing at this layer worked | `1` |
| `warning` | Part of it failed, or a server error | `1` |
| `info` | Context that is not a problem with the target, such as no IPv6 route on this network, or a 404 on the root path | `0` |

`nw diagnose` exits `0` when there is no `error` or `warning` finding, `1` when there is, `2` for a usage error and `130` when you press Ctrl-C. A target that fails is a result (`1`), not a tool error (`2`). The full list of rules and when each can be wrong is in [Findings](../findings/).

## Machine-readable output

`--output json` prints the [report](../report-schema/) with the measurements, findings, hypotheses, recommendations and the layer summary. Use `finding.code` and `error.code` in scripts; the messages may change.

## What it does not do

nw diagnose measures from where you are. It cannot tell you what other networks see, and it does not look inside your local network yet. Differences between resolvers, networks and address families are observations; the report does not claim to know why. nw sends nothing anywhere except the test traffic itself.
