# nwrk Roadmap

This is the phase-by-phase build plan for `nw`. The product specification is in [SPEC.md](SPEC.md). Versions are capability milestones, not delivery dates.

| Phase | Release | Theme |
|---|---|---|
| [P0](#p0-foundation--v001) | v0.0.1 | Foundation: CLI skeleton, CI, releases, install scripts, website |
| [P1](#p1-measurements--v002) | v0.0.2 | Measurements: DNS, TCP, TLS, HTTP and schema v1 |
| [P2](#p2-diagnose--v010) | **v0.1.0** | Diagnose: orchestration and first rules (first announced release) |
| [P3](#p3-local-and-regional--v020) | v0.2.0 | `doctor`, network inspection, region presets, config file |
| [P4](#p4-interference-investigation--v030) | v0.3.0 | Interference rules, encrypted DNS, path diagnostics |
| [P5](#p5-history-and-reports--v040) | v0.4.0 | History, report export, redaction |
| [P6](#p6-distribution--v050) | v0.5.0 | Package managers |
| [P7](#p7-observability--v060) | v0.6.0 | `watch` and intermittent failures |
| [P8](#p8-stable--v100) | v1.0.0 | Frozen contracts |

## Ground rules for every phase

- A phase is done only when its exit criteria pass in CI on Linux, macOS, and Windows.
- Every phase ends with a tagged release built by GoReleaser, with `checksums.txt` and cosign keyless signatures.
- Docs and website change in the same pull request as the feature.
- Nothing from a later phase lands early unless this file is updated first.
- Core tests use local fixtures only. Public internet endpoints are allowed only in optional smoke tests.
- Findings and docs follow the technical wording policy (SPEC 8.5). No circumvention features.
- Exit codes: `0` no findings, `1` findings, `2` usage or tool error, `130` interrupted.

---

## P0: Foundation → v0.0.1

**Goal:** a real, installable, signed product that does almost nothing yet, so the whole delivery pipeline is proven before diagnostics exist.

### Repository

- [x] `go.mod` with module `github.com/hesamzakerirad/nwrk`; entry point `cmd/nw/main.go`
- [x] `LICENSE` (MIT), `README.md`, `PRINCIPLES.md`
- [x] `Makefile` targets: `build`, `test`, `lint`, `fmt`

### CLI

- [x] Cobra root command with global flags: `--output human|json`, `--no-color`, `--verbose`, `--quiet`, `--timeout`
- [x] `nw version`: version, commit, build date, Go version, OS/arch, in human and JSON form
- [x] `nw completion bash|zsh|fish|powershell`
- [x] Output layer: human renderer with color on for terminals, off for `--no-color`, `NO_COLOR`, or non-terminal stdout; JSON renderer; results on stdout, logs and errors on stderr
- [x] Exit code mapping (`0`/`1`/`2`/`130`); SIGINT cancels the root `context.Context`
- [x] `log/slog` to stderr; `--verbose` raises the level

### CI and releases

- [x] `ci.yml`: gofmt check, `go vet`, `staticcheck`, `govulncheck`, `go test -race` on ubuntu, macos, and windows runners
- [x] `.goreleaser.yaml`: linux, darwin, windows × amd64, arm64; `.tar.gz` (`.zip` for Windows); `checksums.txt`; cosign keyless signing
- [x] `release.yml`: runs on `v*` tags after CI passes, publishes to GitHub Releases

### Website and install

- [x] Hugo site in `site/` in English; pages: landing, install, "docs coming soon"
- [x] `site.yml`: builds and deploys to GitHub Pages on push to `main`; `site/static/CNAME` = `nwrk.ir`
- [x] `docs/` mounted into the site (`docs/` → `/docs/`)
- [x] `install.sh` (POSIX sh): detect OS/arch, download from GitHub Releases, verify SHA-256 against `checksums.txt`, install to `~/.local/bin` (or another user-writable dir on PATH), retry on network failure, print the manual download URL if all retries fail
- [x] `install.ps1`: same flow, installs to `%LOCALAPPDATA%\nwrk\bin` and adds it to the user PATH

### Maintainer tasks (manual, outside the repo)

- [ ] Point `nwrk.ir` DNS at GitHub Pages (A: 185.199.108.153, 185.199.109.153, 185.199.110.153, 185.199.111.153; AAAA: 2606:50c0:8000::153 through 2606:50c0:8003::153)
- [ ] Verify the domain in GitHub account settings (prevents domain takeover), set Pages source to GitHub Actions, enforce HTTPS
- [ ] Enable private vulnerability reporting on the repo

### Exit criteria

- `curl -fsSL https://nwrk.ir/install.sh | sh && nw version` works on fresh Linux and macOS machines; `irm https://nwrk.ir/install.ps1 | iex; nw version` works on Windows.
- A tampered archive is rejected by both install scripts.
- `cosign verify-blob` succeeds on the release `checksums.txt`.
- `nw version --output json` is valid JSON; `nw --bogus` exits `2`.
- `https://nwrk.ir` serves the site over valid HTTPS.

---

## P1: Measurements → v0.0.2

**Goal:** four trustworthy, independently runnable measurements behind a stable data contract.

### Domain and contract

- [x] Types: `DiagnosticRun`, `Measurement`, `Finding`, `Hypothesis`, `Recommendation`
- [x] Statuses: `success`, `failure`, `skipped`, `inconclusive`
- [x] Error taxonomy, for example: `dns.nxdomain`, `dns.servfail`, `dns.refused`, `dns.no_answer`, `dns.timeout`, `tcp.refused`, `tcp.timeout`, `tcp.unreachable`, `tcp.reset`, `tls.cert_expired`, `tls.cert_untrusted`, `tls.hostname_mismatch`, `tls.handshake_failure`, `tls.reset`, `tls.timeout`, `http.timeout`, `http.redirect_loop`, `http.protocol_error`
- [x] JSON schema v1: `docs/report-schema.md` plus a machine-readable JSON Schema file; golden-file tests

### Measurements

- [x] **DNS** (`miekg/dns`): A/AAAA, response code, timing, resolver used; system resolver discovery per platform (the baseline uses the OS resolver API and lists the configured servers; chosen resolvers are queried directly for exact response codes); repeatable `--resolver host[:port]` and `tcp://host[:port]`; `NW_RESOLVERS`; system resolver always measured as the baseline
- [x] **TCP**: per resolved address, address family, duration, classified error
- [x] **TLS**: verification always on; version, cipher suite, ALPN; certificate subject, issuer, validity, SANs, chain result; certificate errors kept separate from handshake/transport errors
- [x] **HTTP**: GET by default, bounded redirects and body size, `httptrace` timings (DNS, connect, TLS, first byte, total), selected headers; never store bodies, cookies, or authorization headers
- [x] Commands: `nw test dns|tcp|tls|http`, human and JSON output

### Testing

- [x] Fixtures (in `internal/fixtures`): local DNS server (NXDOMAIN, empty answer, SERVFAIL, REFUSED, no response), TCP listeners that refuse or never accept, TLS servers with expired, self-signed, and wrong-host certificates, HTTP server with redirect loops and slow responses
- [x] Fuzz tests for host, URL, `host:port`, and resolver-address parsers
- [x] Cancellation and deadline tests; no goroutine or socket leaks

### Docs

- [x] `docs/measurements.md`, test-command sections of `docs/commands.md`, `docs/report-schema.md`

### Exit criteria

- Every case in SPEC 16.2 has a passing fixture test on all three operating systems.
- All JSON output validates against schema v1.
- No core test touches the public internet.

---

## P2: Diagnose → v0.1.0

**Goal:** the first announced release. `nw diagnose <target>` satisfies SPEC section 23.

### Orchestration

- [ ] Dependency graph: target validation → DNS → address selection → TCP → TLS → HTTP
- [ ] Skipped tests carry an explicit reason; independent branches run concurrently under a per-profile limit
- [ ] IPv4 and IPv6 tested separately when both are available
- [ ] Profiles `quick`, `standard` (default), `deep`, hard-coded and documented

### Rule engine

- [ ] Rule definition: stable ID, version, required measurements, conditions, severity, caveats, next steps; deterministic evaluation
- [ ] First rules: `DNS_RESOLUTION_FAILURE`, `NO_USABLE_ADDRESS`, `TCP_CONNECTION_REFUSED`, `TCP_CONNECTION_TIMEOUT`, `TLS_CERTIFICATE_INVALID`, `TLS_HANDSHAKE_FAILURE_AFTER_TCP`, `HTTP_ERROR_RESPONSE`, `IP_FAMILY_BEHAVIOR_DIFFERENCE`
- [ ] Hypotheses with supporting, contradicting, and missing evidence and qualitative confidence (`low`, `medium`, `high`)
- [ ] Recommendations for safe next steps
- [ ] Human report layout per SPEC 13.1

### Project

- [ ] `CONTRIBUTING.md`, `SECURITY.md`, issue templates (bug, rule false positive, region preset proposal), pull request template
- [ ] Start accepting pull requests

### Docs

- [ ] `docs/diagnostics.md`, `docs/findings.md` (every rule with its false-positive conditions), full `docs/commands.md`; announcement on nwrk.ir

### Exit criteria

- SPEC section 23 holds for `nw diagnose`.
- Every rule has positive and negative fixture tests.
- Exit codes `0`, `1`, `2`, `130` are each covered by an end-to-end test.

---

## P3: Local and regional → v0.2.0

**Goal:** `nw doctor` tells the user whether the problem is local, domestic, or international.

- [ ] `nw doctor`: bounded checklist covering interfaces, default route, system resolvers, the `global` preset, and the selected region preset
- [ ] `nw network show|interfaces|routes|dns-config|proxy` via platform adapters (native APIs preferred over parsing command output)
- [ ] Region presets `global.toml` and `ir.toml` embedded from `internal/regions/presets/`; `--region` flag. `ir` anchors chosen for stability and neutrality, with the reason recorded per target
- [ ] Layered verdict: local / domestic / international
- [ ] Resolver comparison: system resolver vs chosen resolvers, differences reported as observations
- [ ] Config file (TOML): `nw config path`, `nw config show` with the source of each value; keys `region`, `resolvers`, `timeout`, `color`; precedence flag > `NW_*` env > config > default/preset
- [ ] Docs: `docs/regions.md`, `docs/platform-support.md`, `docs/privacy.md`

### Exit criteria

- On synthetic measurement sets for (a) no default route, (b) system DNS failing, (c) domestic reachable while international is blackholed, `nw doctor --region ir` names the correct layer.
- Every platform limitation found is listed in `docs/platform-support.md`.

---

## P4: Interference investigation → v0.3.0

**Goal:** evidence-based detection of DNS, TLS, and HTTP interference patterns, with honest uncertainty.

- [ ] Encrypted DNS resolvers: `tls://` (DoT) and `https://` (DoH)
- [ ] DNS rules: answer mismatch between system and chosen resolvers, private or reserved addresses returned for public names, signs of injected responses (for example multiple differing answers to one query)
- [ ] TLS rules: reset or timeout after ClientHello; SNI comparison (same IP, target server name vs a neutral control name)
- [ ] HTTP rules: unexpected redirect to an unrelated host, response differences between HTTP and HTTPS for the same target
- [ ] `nw security inspect` and `nw security interference`
- [ ] `nw path trace` (ICMP where permitted, TCP fallback), `nw path ping`, `nw path mtu`; privilege needs reported clearly
- [ ] `deep` profile includes the new checks
- [ ] DNSSEC status and CNAME chain inspection

### Exit criteria

- Every new rule has documented false-positive conditions plus positive and negative fixture tests.
- No rule reports `high` confidence from a single measurement.
- A wording-policy review of all new finding text passes.

---

## P5: History and reports → v0.4.0

**Goal:** runs can be kept, revisited, and shared safely.

- [ ] JSONL history in the platform state directory, with retention limit
- [ ] `nw history list`, `nw history show <run-id>`
- [ ] `nw report export <run-id> --format json|md`
- [ ] Redaction of local IP addresses, hostnames, and environment details
- [ ] Config keys: default profile, history retention, redaction preferences

### Exit criteria

- A redacted report contains no local addresses (tested).
- History written by v0.3.0 can still be read.

---

## P6: Distribution → v0.5.0

- [ ] Homebrew tap (`hesamzakerirad/homebrew-tap`), Scoop bucket, WinGet manifest, AUR `nwrk-bin`, all published by GoReleaser
- [ ] Install docs updated in both languages

### Exit criteria

- CI smoke jobs install `nw` through each channel and run `nw version`.

---

## P7: Observability → v0.6.0

- [ ] `nw watch <target>`: interval, count, bounded runtime, Ctrl-C safe
- [ ] Change detection between runs, intermittent-failure detection, configurable thresholds
- [ ] Output hooks: JSON lines on stdout and an optional command to run on state change

### Exit criteria

- A fixture with an injected intermittent failure is detected and reported.

---

## P8: Stable → v1.0.0

- [ ] CLI flags, commands, exit codes, and JSON schema v1 frozen; compatibility tests against golden output from earlier versions
- [ ] Performance, memory, and leak tests under repeated runs
- [ ] All docs current at release time
- [ ] Security disclosure process documented and exercised

### Exit criteria

- No breaking change needed to ship; the deprecation policy is published.

---

## After v1.0 (unscheduled)

- Optional external measurement networks (Globalping, RIPE Atlas)
- TUI
- SQLite history if JSONL becomes a bottleneck
- Additional region presets contributed by the community
