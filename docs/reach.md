---
title: Developer reachability
description: Check the endpoints developers depend on and tell a server-side restriction from network interference.
weight: 12
---

`nw reach` requests a list of endpoints, such as GitHub, the Go module proxy, npm and PyPI, and sorts what went wrong into two groups. The group names are neutral on purpose: they describe what was observed, not who is behind it.

```sh
nw reach
nw reach --preset work
nw reach github.com proxy.golang.org --output json
```

## The two groups

| Group | What was observed | Finding |
|---|---|---|
| **Server-side restriction** | The exchange finished and the server's final answer refused the request: HTTP 403 or 451. | `REACH_SERVER_SIDE_RESTRICTION` |
| **Network interference** | The exchange did not finish in a normal way: a reset, a timeout, a failed handshake, or a private address for a public name. | `REACH_NETWORK_INTERFERENCE` |

A server-side restriction means the network delivered your request and a server, a CDN or a hosting provider declined it. Access rules, geographic policy and legal compliance, including sanctions, are examples of causes. nw cannot tell which one applies.

Network interference means a device on the path may have altered or dropped the exchange. A server outage and a broken route look the same from one network, so the confidence is `low`, or `medium` when several endpoints fail this way while others answer. It is never `high`.

Both findings carry caveats, and the hypotheses list what was not checked. The first useful next step is always the same: request the same URL from another network and compare.

## What it measures

For each endpoint nw:

1. resolves the name with the system resolver;
2. requests the URL once for each IP family that has an address, so IPv4 and IPv6 results sit side by side (`REACH_IP_FAMILY_DIFFERENCE` reports a difference);
3. probes HTTP/3 over UDP when the URL is https, using an address that answered over TCP (`REACH_HTTP3_FAILS_TCP_WORKS` reports a failure when the server advertises HTTP/3). Skip it with `--no-http3`.

The HTTP/3 probe is a HEAD request. It is recorded as an `http` measurement with `params.probe` set to `http3`.

## Endpoint presets

| Preset | Contains |
|---|---|
| `dev` | GitHub, `proxy.golang.org`, the npm registry, PyPI, Docker Hub, crates.io, Debian and Ubuntu mirrors, and the Homebrew index. `dev` is the default. |

Every built-in endpoint records why it was chosen; see `internal/endpoints/presets/dev.toml`.

### Your own presets

Define presets in the [config file](../commands/#nw-config). The format is the same as the built-in one. `name`, `description` and the per-endpoint `name` and `reason` are optional in the config file.

```toml
[[endpoint_presets]]
name = "work"
description = "Internal developer services"

[[endpoint_presets.endpoints]]
url = "https://git.example.com/"
name = "Git"

[[endpoint_presets.endpoints]]
url = "https://registry.example.com/"
```

A preset name uses lowercase letters, digits and hyphens, and may not reuse a built-in name. URLs must be http or https and carry no credentials. Choose a preset with `--preset`.

## What it contacts

Only the endpoints of the preset you choose, plus the system resolver. Nothing else. See [Privacy](../privacy/).

## Limits

- One run is one vantage point. nw cannot see why a server refused or where a packet was dropped.
- The response body is never kept, so a provider error page and an ordinary error page look alike.
- Some endpoints answer 401 or 404 at their root on purpose, for example the Docker registry. Those answers are not findings.
