# Changelog

All notable changes to this project are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

Every release has a hand-written entry. The release workflow publishes the matching section as the GitHub release notes.

## [0.2.0] - 2026-11-17

### Added

- Platform inspection: interfaces, routes, DNS configuration and proxies.
- Region presets, a config file and layered settings.
- Local checks, `doctor` rules and a layered verdict.
- `nw doctor`, `nw network` and `nw config`.
- Documentation for regions, platform support and privacy.

## [0.1.0] - 2026-11-17

### Added

- Diagnostic rule engine and the first rules.
- `nw diagnose`, with profiles and dependency-aware ordering of measurements.
- Documentation for diagnostics, and issue templates.

### Changed

- The report schema now carries findings and summaries.

## [0.0.2] - 2026-11-17

### Added

- Domain model and report schema version 1, published as a JSON Schema.
- Input parsers for hosts, ports and URLs. They convert international domain names to punycode.
- DNS, TCP, TLS and HTTP measurements, tested against local fixtures.
- `nw test` commands with human and JSON reports.
- Documentation for the measurements and the report schema.
- A short fuzz run in CI for the input parsers.

## [0.0.1] - 2026-11-17

First release. It proves the delivery pipeline. The `nw` command does almost nothing yet.

### Added

- `nw` command-line skeleton with `version` and `completion` commands.
- Global flags `--output`, `--no-color`, `--verbose`, `--quiet` and `--timeout`.
- Exit codes `0`, `1`, `2` and `130`. Ctrl+C cancels running work.
- GitHub Actions CI on Linux, macOS and Windows.
- GoReleaser configuration with SHA-256 checksums and keyless cosign signatures.
- Install scripts for POSIX shell and PowerShell.
- Project specification, roadmap and principles under the MIT license.
- Hugo website for nwrk.ir, deployed with GitHub Pages.
