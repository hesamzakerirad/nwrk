# nwrk

`nw` is an open source command-line tool that measures how your network reaches a destination and explains what the evidence shows. It is local-first: no account, no server, and nothing is uploaded.

Website: https://nwrk.ir

> **Status: early development.** `nw doctor`, `nw diagnose`, `nw security inspect|interference`, `nw path ping|trace|mtu`, `nw reach`, the four measurements (`nw test dns|tcp|tls|http`), `nw network`, `nw config` and `nw community` work today. History and reports arrive in the next releases; see the [roadmap](docs/ROADMAP.md).

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
go install github.com/radestsam/nwrk/cmd/nw@latest
```

Or download an archive from the [releases page](https://github.com/radestsam/nwrk/releases). Changes for each version are listed in the [changelog](CHANGELOG.md). Every release has `checksums.txt` and a cosign signature; see the [install guide](docs/install.md) for how to verify them.

## Use

```sh
nw security interference example.com --resolver tls://9.9.9.9
nw path ping example.com
nw doctor --region ir
nw reach
nw diagnose example.com
nw diagnose https://example.com/health --profile deep
nw test dns example.com --resolver 1.1.1.1
nw test tcp example.com:443
nw test tls example.com
nw test http https://example.com --output json
nw version
nw completion zsh
```

`nw doctor` checks this machine and a region's reference targets and says whether the problem is local, domestic or international ([regions](docs/regions.md), [privacy](docs/privacy.md), [platform support](docs/platform-support.md)). [`nw security interference`](docs/interference.md) compares resolvers, listens for several DNS replies, compares handshakes by server name and http with https, and says what else could explain each difference. `nw diagnose` measures DNS, TCP, TLS and HTTP in order, skips what cannot run with the reason, and explains the evidence: findings say what was observed, hypotheses say what might explain it and what was not checked. See [diagnosing a destination](docs/diagnostics.md), [findings](docs/findings.md), [measurements](docs/measurements.md) and the [JSON report schema](docs/report-schema.md).

## Share Results With NWRK Status

`nw community` is the only part of nw that can send data. It is optional, and it never runs in the background.

```sh
nw community info                      # what is measured, sent and stored. Sends nothing.
nw community contribute --dry-run      # measure and show the result. Never contacts the server.
nw community contribute                # measure, show the result, upload if you agree
```

`contribute` asks before it measures and again before it uploads. Both questions default to no, and there is no flag that answers them for you. At the second question you can type `s` to see the exact message first. The upload holds, for each service, the check type, the IP version, the outcome, the time in milliseconds, and sometimes an HTTP status code, the number of DNS answers or an error code. It holds no address, certificate, header, URL or device identifier. The server stores the country and network (ASN) it sees for your connection, not the address. See `nw community info` for the full list, including where the server is hosted and how long results are kept.

* `--profile` picks the measurement profile. The default is `ir-core-v1`. A profile fixes the services, the time limits and the total budget (90 seconds), so `--timeout` does not apply.
* `--dry-run` never calls the challenge or submit endpoints. With `--output json` it prints the exact message. `--payload-file <path>` writes the exact message to a file (mode 0600).
* `--api` or `NW_COMMUNITY_API` sets the API address. The default is `https://api.nwrk.ir`. Plain `http` is accepted only for `localhost`, for development.
* If the upload fails, nw says why and keeps nothing. There is no queue and no retry. A rate limit answer says how long to wait.

The profiles, the message format and the checks that the server applies are in [`contracts/`](contracts/README.md). Only IPv4 or IPv6 that your machine can route is measured, and a service is measured over an IP version only if it has a record for it, so a missing measurement is never counted as a failure.

Global flags: `--output human|json`, `--no-color`, `--verbose`, `--quiet`, `--timeout`, `--region`. Every setting also has an `NW_*` variable and a config file key; see `nw config show`.

Exit codes: `0` no problem found, `1` a problem found (`nw diagnose`) or a measurement failed (`nw test`), `2` usage error or the tool could not run, `130` interrupted.

Color is on for terminals and off for pipes, `--no-color`, and the `NO_COLOR` environment variable.

## Where this is going

Next: local history, comparison over time and report export (with redaction), then package managers and `nw watch`. See [docs/SPEC.md](docs/SPEC.md) and [docs/ROADMAP.md](docs/ROADMAP.md).

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
