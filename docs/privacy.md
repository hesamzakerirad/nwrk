---
title: Privacy
description: What nw sends, what it records, and what it leaves out.
weight: 10
---

nw runs on your machine. There is no account, no server of ours, no telemetry and no automatic update check. Nothing is uploaded.

## What nw contacts

nw sends network traffic only for the command you run, and only to what that command measures:

| Command | Contacts |
|---|---|
| `nw test`, `nw diagnose` | The target you name, the DNS resolvers involved (your system's and any you add with `--resolver`), and nothing else. Redirects are followed to the servers they point to, up to the limit. |
| `nw doctor` | The reference targets and resolvers of the region preset, listed in [Regions](../regions/), plus the resolvers you choose. Nothing else. |
| `nw reach` | The endpoints of the preset you choose (the built-in `dev` preset is listed in [Developer reachability](../reach/)) or the URLs you list, and your system resolver. Each endpoint is requested once per IP family, and once more over HTTP/3 (UDP) for https URLs unless you pass `--no-http3`. |
| `nw security inspect`, `nw security interference`, `nw diagnose --profile deep` | The target you name, with a few extra handshakes, DNS queries and one http request to it, and the resolvers involved. The interference comparison also connects to the target's addresses as returned by each resolver, and to the address of the control server name (the control name is sent only as the server name inside a handshake with the target's own address). |
| `nw path ping`, `trace`, `mtu` | The one host you name: ICMP echo requests, or TCP connections to the port you choose, some with a low TTL so that routers on the way may answer. |
| `nw network`, `nw config`, `nw version`, `nw completion` | Nothing. They read local information only. |

The route check of `nw doctor` asks the operating system which route it would use and sends no packet.

nw never writes files: it only reads the optional config file. (History, from a later release, will be local files that you control.)

## What a report contains

A report holds what the measurements saw: the host names you asked about, the IP addresses they resolved to, resolver addresses, certificate details (subject, issuer, validity, names), HTTP status codes and a short list of response headers, timings, and the version and platform of nw.

Think of it before sharing: the host names and addresses say what you were looking at.

## What nw leaves out

- **Cookies, response bodies and authorization headers** are never recorded. nw sends no cookies and no credentials, and URLs that contain a user name or password are refused.
- **Local addresses.** The `nw doctor` report records counts and kinds of interfaces and resolvers (for example "2 private"), not their addresses or names. `nw network` shows addresses, because showing them is its purpose; it prints to your terminal only.
- **Proxy credentials.** A proxy URL with a user name and password is shown without them.

Each measurement lists what it deliberately did not collect in its `redacted` field.

## The config file

The config file holds the settings `region`, `resolvers`, `timeout` and `color`. Do not put credentials in it; nw has no use for them.

## Third parties you choose to contact

Resolvers and targets are other people's servers. A resolver you query sees the names you ask for, and a target sees your address. The reference sets in `nw doctor` are public resolvers and large services; if you do not want them contacted, do not run `nw doctor`, or pick `--resolver` values you trust.
