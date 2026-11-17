# nwrk

`nw` is an open source command-line tool that measures how your network reaches a destination and explains what the evidence shows. It is local-first: no account, no server, and nothing is uploaded.

Website: https://nwrk.ir

> **Status: early development (v0.0.x).** Only `nw version` and shell completion work today. The diagnostic commands arrive in the next releases; see the [roadmap](docs/ROADMAP.md).

## Install

Linux and macOS:

```sh
curl -fsSL https://nwrk.ir/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://nwrk.ir/install.ps1 | iex
```

With Go:

```sh
go install github.com/hesamzakerirad/nwrk/cmd/nw@latest
```

Or download an archive from the [releases page](https://github.com/hesamzakerirad/nwrk/releases). Every release has `checksums.txt` and a cosign signature; see the [install guide](docs/install.md) for how to verify them.

## Use

```sh
nw version
nw version --output json
nw completion zsh
```

Global flags: `--output human|json`, `--no-color`, `--verbose`, `--quiet`, `--timeout`.

Exit codes: `0` no problem found, `1` problem found, `2` usage error or the tool could not run, `130` interrupted.

Color is on for terminals and off for pipes, `--no-color`, and the `NO_COLOR` environment variable.

## Where this is going

`nw diagnose example.com` will check DNS, TCP, TLS and HTTP in order, show which stage fails, and explain what that evidence does and does not prove. `nw doctor --region ir` will tell local, domestic and international failures apart, and you will be able to pick any DNS resolver with `--resolver`. See [docs/SPEC.md](docs/SPEC.md) and [docs/ROADMAP.md](docs/ROADMAP.md).

## Build from source

```sh
make build   # writes bin/nw
make test
make lint
```

## License

[MIT](LICENSE)
