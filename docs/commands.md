---
title: Command reference
description: Commands, global flags, exit codes and output conventions of nw.
weight: 3
---

This page covers what nw can do today. New commands are added here as they ship.

With `--output json`, the `nw test` commands print a [report](../report-schema/) that follows a versioned schema.

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
| `--resolver` | all four | A DNS resolver to measure next to the system one. Repeatable. `host`, `host:port`, `[v6]:port` or `tcp://host[:port]`. The host must be an IP address. |
| `--method` | `http` | `GET` (default) or `HEAD`. Other methods are not supported. |
| `--max-redirects` | `http` | Redirects to follow, 1 to 50. Default 10. |

The resolver list comes from the first of these that sets one: the `--resolver` flags, then the `NW_RESOLVERS` environment variable (comma-separated). The system resolver is always measured as well, so results from your chosen resolvers are compared with it, never silently replacing it. When you name a resolver, `tcp`, `tls` and `http` connect to the addresses that resolver returned.

Exit status: `0` when every measurement succeeded, `1` when at least one failed, `2` for a usage error. A measurement that did not run because an earlier step failed is reported as `skipped` and does not count as a failure by itself. An HTTP response with an error status such as 404 or 503 is a completed measurement, so it exits `0`; the status code is in the report.

`--timeout` sets the deadline of each measurement. `--quiet` prints only the measurements that did not succeed.

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

`--verbose` and `--quiet` cannot be combined.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | The command ran and found no problem |
| `1` | The command ran and found a problem with the target |
| `2` | Usage error (bad flag, target or setting), or nw could not run the measurement |
| `130` | You interrupted the command with Ctrl-C |

A failing network target is a result (`1`), not a tool error (`2`).

## Output conventions

- Results are written to stdout. Logs, progress and errors go to stderr, so you can pipe or redirect results safely.
- Color is used only when stdout is a terminal. It is off for pipes and files, with `--no-color`, with the `NO_COLOR` environment variable, and when `TERM=dumb`. Color is never the only way a result is expressed.
- With `--output json`, every document has a `schema_version` field. Errors are also written as JSON, to stderr:

```json
{"schema_version":"1","error":{"kind":"usage","message":"invalid --output \"xml\" (want human or json)"}}
```

`kind` is `usage` for a mistake in how nw was called and `execution` when nw itself could not do its work. Both exit with code 2.
