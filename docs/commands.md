---
title: Command reference
description: Commands, global flags, exit codes and output conventions of nw.
weight: 3
---

This page covers what nw can do today. New commands are added here as they ship.

## nw version

Prints the version, commit, build date and platform. It makes no network requests.

```sh
nw version
nw version --output json
```

`nw --version` prints just the version.

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

A failing network target is a result (`1`), not a tool error (`2`). Today no command returns `1` yet, because the diagnostic commands have not shipped.

## Output conventions

- Results are written to stdout. Logs, progress and errors go to stderr, so you can pipe or redirect results safely.
- Color is used only when stdout is a terminal. It is off for pipes and files, with `--no-color`, with the `NO_COLOR` environment variable, and when `TERM=dumb`. Color is never the only way a result is expressed.
- With `--output json`, every document has a `schema_version` field. Errors are also written as JSON, to stderr:

```json
{"schema_version":"1","error":{"kind":"usage","message":"invalid --output \"xml\" (want human or json)"}}
```

`kind` is `usage` for a mistake in how nw was called and `execution` when nw itself could not do its work. Both exit with code 2.
