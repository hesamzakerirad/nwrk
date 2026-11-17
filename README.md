# nwrk

`nw` is an open source command-line tool that measures how your network reaches a destination and explains what the evidence shows. It is local-first: no account, no server, and nothing is uploaded.

Website: https://nwrk.ir (English and Farsi)

> **Status: early development.** `nw diagnose` and the four measurements (`nw test dns|tcp|tls|http`) work today. `nw doctor`, regional presets and history arrive in the next releases; see the [roadmap](docs/ROADMAP.md).

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
nw diagnose example.com
nw diagnose https://example.com/health --profile deep
nw test dns example.com --resolver 1.1.1.1
nw test tcp example.com:443
nw test tls example.com
nw test http https://example.com --output json
nw version
nw completion zsh
```

`nw diagnose` measures DNS, TCP, TLS and HTTP in order, skips what cannot run with the reason, and explains the evidence: findings say what was observed, hypotheses say what might explain it and what was not checked. See [diagnosing a destination](docs/diagnostics.md), [findings](docs/findings.md), [measurements](docs/measurements.md) and the [JSON report schema](docs/report-schema.md).

Global flags: `--output human|json`, `--no-color`, `--verbose`, `--quiet`, `--timeout`.

Exit codes: `0` no problem found, `1` a problem found (`nw diagnose`) or a measurement failed (`nw test`), `2` usage error or the tool could not run, `130` interrupted.

Color is on for terminals and off for pipes, `--no-color`, and the `NO_COLOR` environment variable.

## Where this is going

`nw doctor --region ir` will tell local, domestic and international failures apart, and you can already pick any DNS resolver with `--resolver`. See [docs/SPEC.md](docs/SPEC.md) and [docs/ROADMAP.md](docs/ROADMAP.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## Build from source

```sh
make build   # writes bin/nw
make test
make lint
```

## License

[MIT](LICENSE)
