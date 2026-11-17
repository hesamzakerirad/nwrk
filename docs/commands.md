---
title: Command reference
description: Commands, global flags, exit codes and output conventions of nw.
weight: 3
---

This page covers what nw can do today. New commands are added here as they ship.

With `--output json`, `nw test` and `nw diagnose` print a [report](../report-schema/) that follows a versioned schema.

## nw version

Prints the version, commit, build date and platform. It makes no network requests.

```sh
nw version
nw version --output json
```

`nw --version` prints just the version.

## nw test

Runs one measurement and prints what it observed. Each is independent: you can run `nw test tls` without running anything else first. What each measurement does, and what its errors mean, is in [Measurements](../measurements/).

| Command | Measures |
|---|---|
| `nw test dns <host>` | A and AAAA lookups, with the system resolver and any `--resolver` you add |
| `nw test tcp <host:port>` | A TCP connection to every address of the host |
| `nw test tls <host[:port]>` | A verified TLS handshake with every address (port 443 by default) |
| `nw test http <url>` | One HTTP or HTTPS request with stage timings and a bounded redirect chain |

```sh
nw test dns example.com
nw test dns example.com --resolver 1.1.1.1 --resolver tcp://9.9.9.9
nw test tcp example.com:443
nw test tls example.com
nw test http https://example.com --output json
```

Flags of `nw test`:

| Flag | Applies to | Meaning |
|---|---|---|
| `--resolver` | all four | A DNS resolver to measure next to the system one. Repeatable. `host[:port]` or `[v6]:port` (UDP), `tcp://host[:port]`, `tls://host[:port]` (DNS over TLS) or `https://host[:port][/path]` (DNS over HTTPS). For plain DNS the host must be an IP address; for `tls://` and `https://` it can be a name. |
| `--method` | `http` | `GET` (default) or `HEAD`. Other methods are not supported. |
| `--max-redirects` | `http` | Redirects to follow, 1 to 50. Default 10. |

The resolver list comes from the first of these that sets one: the `--resolver` flags, then the `NW_RESOLVERS` environment variable (comma-separated). The system resolver is always measured as well, so results from your chosen resolvers are compared with it, never silently replacing it. When you name a resolver, `tcp`, `tls` and `http` connect to the addresses of the first resolver you named that answered; if none did, they use the system resolver's, and say so in the measurement's `params.addresses_from`.

Exit status: `0` when every measurement succeeded, `1` when at least one failed, `2` for a usage error. A measurement that did not run because an earlier step failed is reported as `skipped` and does not count as a failure by itself. An HTTP response with an error status such as 404 or 503 is a completed measurement, so it exits `0`; the status code is in the report.

`--timeout` sets the deadline of each measurement. `--quiet` prints only the measurements that did not succeed.

## nw diagnose

Investigates a destination across DNS, TCP, TLS and HTTP, then explains what the evidence shows. How it works and how to read the report is in [Diagnosing a destination](../diagnostics/); every rule is in [Findings](../findings/).

```sh
nw diagnose example.com
nw diagnose https://example.com/health --profile deep
nw diagnose example.com:8443 --resolver 1.1.1.1 --output json
```

| Flag | Meaning |
|---|---|
| `--profile` | `quick`, `standard` (default) or `deep` |
| `--resolver` | A DNS resolver to compare with the system one; same syntax and `NW_RESOLVERS` as `nw test` |

The target is a host name, `host:port` or a URL. A bare host means https on port 443, and port 80 means http.

Exit status: `0` when no actionable finding was made, `1` when the target has a problem, `2` for a usage error, `130` when interrupted. `--quiet` prints only the findings; `--verbose` adds the details of each measurement.

## nw doctor

Checks this machine's own network setup, then the reference targets of a region preset, and says whether the problem is **local**, **domestic** or **international**. What it does, the verdicts, and every reference target are in [Regions and presets](../regions/); what it contacts is in [Privacy](../privacy/).

```sh
nw doctor
nw doctor --region ir
nw doctor --region ir --resolver 1.1.1.1 --resolver tcp://9.9.9.9 --output json
```

It uses the same report format as `nw diagnose`, with a `summary.verdict` and the status of each scope. `--region` is global, `ir`, or any preset listed in [Regions and presets](../regions/); the default is `global`. Exit status as for `nw diagnose`: `0` no actionable finding, `1` a problem, `2` usage error, `130` interrupted.

## nw network

Shows this machine's own network setup, read from the operating system. Nothing is sent over the network. These commands show addresses, because that is their purpose.

| Command | Shows |
|---|---|
| `nw network show` | A short summary: interfaces, default route, DNS servers, proxy |
| `nw network interfaces` | Interfaces with state, MTU and addresses |
| `nw network routes` | The routing table (not available on Windows) |
| `nw network dns-config` | The DNS servers and search domains the system uses |
| `nw network proxy` | Proxy settings applications may use, without credentials |

What each platform can and cannot show is listed in [Platform support](../platform-support/).

## nw config

nw reads an optional TOML file. `nw config path` prints where it is (it exists or not), and `nw config show` prints the effective settings with the source of each.

```sh
nw config path
nw config show
```

```toml
region = "ir"
resolvers = ["1.1.1.1", "tcp://9.9.9.9"]
timeout = "5s"
color = "auto"   # auto, always or never
```

| Platform | Location |
|---|---|
| Linux | `$XDG_CONFIG_HOME/nwrk/config.toml`, else `~/.config/nwrk/config.toml` |
| macOS | `~/Library/Application Support/nwrk/config.toml` |
| Windows | `%LOCALAPPDATA%\nwrk\config.toml` |

The `NW_CONFIG` variable overrides the location. Unknown keys are an error, so a typo cannot silently do nothing. nw never writes the file, and it must not hold credentials.

**Every setting follows one order:** the command-line flag, then the `NW_*` environment variable, then the config file, then the default.

| Setting | Flag | Variable | Default |
|---|---|---|---|
| `region` | `--region` | `NW_REGION` | `global` |
| `resolvers` | `--resolver` | `NW_RESOLVERS` | none (then the preset's, see [Regions](../regions/)) |
| `timeout` | `--timeout` | `NW_TIMEOUT` | `10s` |
| `color` | `--no-color` | `NW_COLOR` | `auto` |

`NO_COLOR` and `--no-color` always win over `color = "always"`.

## nw security

Checks built on the same measurements as `nw diagnose`, for one target. They test only that target with a small, fixed set of extra requests. See [Investigating interference](../interference/) and [Findings](../findings/).

| Command | Does |
|---|---|
| `nw security inspect <target>` | DNSSEC status and CNAME chain, certificate expiry, whether TLS 1.0 and 1.1 are accepted, http-to-https upgrade, HSTS |
| `nw security interference <target>` | Compares resolvers, listens for several DNS replies, compares handshakes by server name, compares http and https |

```sh
nw security inspect example.com
nw security interference example.com --resolver tls://9.9.9.9 --resolver 1.1.1.1
nw security interference example.com --control www.example.net
```

The target is a host name, `host:port` or a URL, as for `nw diagnose`. `--resolver` works as for `nw test`; for interference, add resolvers you trust, ideally encrypted ones, or the report says which comparisons it could not make. `--control` sets the neutral server name for the server-name comparison (default `www.example.org`). Exit status as for `nw diagnose`.

## nw path

Controlled probes of the path to one destination. ICMP is often filtered, deprioritized or rate-limited, so a missing reply is never shown as proof of a broken router or blocked traffic. The `--method` flag is `icmp`, `tcp`, or `auto` (ICMP, falling back to TCP when it is not permitted, with the reason printed).

| Command | Does | Flags |
|---|---|---|
| `nw path ping <host>` | Round-trip time and loss, by ICMP echo or by TCP connect time | `-c/--count 4`, `--interval 1s`, `--wait 2s`, `--method`, `--port 443` |
| `nw path trace <host>` | The hops toward the destination | `--max-hops 30`, `--queries 3`, `--wait 1s`, `--max-silent 5` (ICMP only), `--method`, `--port 443` |
| `nw path mtu <host>` | Interface MTU and the segment size of a connection, a hint and not a discovery | `--port 443` |

```sh
nw path ping example.com
sudo nw path trace example.com
nw path trace example.com --method tcp
nw path mtu example.com
```

Listing the routers of a trace needs ICMP privileges (root or `CAP_NET_RAW` on Linux and macOS) and is not available on Windows. Without them `trace` uses TCP, which shows how many hops away the destination answers but cannot see the routers, and says so. `ping` uses an unprivileged ICMP socket where the system allows it. Details and limits are in [Platform support](../platform-support/).

Exit status: `ping` and `trace` exit `0` when the destination answered and `1` when it did not; `mtu` exits `0` when the connection was made and `1` when it was not; all exit `2` for a usage error or when the method you asked for is not permitted. With `--output json` they print a document with a `schema_version`.

## nw completion

Generates a completion script for `bash`, `zsh`, `fish` or `powershell`. It makes no network requests.

```sh
# bash: load for the current session
source <(nw completion bash)

# zsh: install into your function path
nw completion zsh > "${fpath[1]}/_nw"

# fish
nw completion fish > ~/.config/fish/completions/nw.fish

# PowerShell
nw completion powershell | Out-String | Invoke-Expression
```

## Global flags

| Flag | Meaning | Default |
|---|---|---|
| `-o`, `--output` | `human` or `json` | `human` |
| `--no-color` | Turn off colored output | color on for terminals |
| `-v`, `--verbose` | Show more detail and debug logs on stderr | off |
| `-q`, `--quiet` | Hide nonessential output; errors and exit status remain | off |
| `--timeout` | Deadline for each network operation, for example `5s` | `10s` |
| `--region` | Region preset: `global` or `ir` | `global` |

`--verbose` and `--quiet` cannot be combined.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | The command ran and found no problem |
| `1` | The command ran and found a problem with the target |
| `2` | Usage error (bad flag, target or setting), or nw could not run the measurement |
| `130` | You interrupted the command with Ctrl-C |

For `nw diagnose`, `1` means at least one `error` or `warning` finding. For `nw test`, `1` means a measurement failed. A failing network target is a result (`1`), not a tool error (`2`).

## Output conventions

- Results are written to stdout. Logs, progress and errors go to stderr, so you can pipe or redirect results safely.
- Color is used only when stdout is a terminal. It is off for pipes and files, with `--no-color`, with the `NO_COLOR` environment variable, and when `TERM=dumb`. Color is never the only way a result is expressed.
- With `--output json`, every document has a `schema_version` field. Errors are also written as JSON, to stderr:

```json
{"schema_version":"1","error":{"kind":"usage","message":"invalid --output \"xml\" (want human or json)"}}
```

`kind` is `usage` for a mistake in how nw was called and `execution` when nw itself could not do its work. Both exit with code 2.
