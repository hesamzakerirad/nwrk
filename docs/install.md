---
title: Install
description: Install nw on Linux, macOS or Windows and verify the download.
weight: 2
---

nw is a single binary. You do not need Go, an account or administrator rights.

## Linux and macOS

```sh
curl -fsSL https://nwrk.ir/install.sh | sh
```

The script downloads the release archive for your system from GitHub Releases, checks its SHA-256 checksum, and installs `nw` into `~/.local/bin`. If the checksum does not match, nothing is installed.

Options, set as environment variables:

| Variable | Meaning | Default |
|---|---|---|
| `NW_VERSION` | Version to install, for example `0.1.0` | latest release |
| `NW_INSTALL_DIR` | Install directory | `~/.local/bin` |

## Windows

In PowerShell:

```powershell
irm https://nwrk.ir/install.ps1 | iex
```

The script verifies the checksum, installs `nw.exe` into `%LOCALAPPDATA%\nwrk\bin`, and adds that folder to your user `PATH`. Open a new terminal afterwards. `NW_VERSION` and `NW_INSTALL_DIR` work here too.

## With Go

```sh
go install github.com/radestsam/nwrk/cmd/nw@latest
```

This builds from source and puts `nw` in your Go bin directory. That directory is `$(go env GOBIN)`, or `$(go env GOPATH)/bin` when `GOBIN` is not set. For most users it is `~/go/bin`.

Go prints only `go: downloading ...` when it succeeds. If your shell then says `command not found: nw`, the Go bin directory is not on your `PATH`. See [Troubleshooting](#troubleshooting).

## Manual download

Download the archive for your system and `checksums.txt` from the [releases page](https://github.com/radestsam/nwrk/releases). Archives are named `nw_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows), for Linux, macOS and Windows on `amd64` and `arm64`. Unpack the archive and put `nw` somewhere on your `PATH`.

## Check that it works

```sh
nw version
```

## Verify a download

Every release includes `checksums.txt`. Check your archive against it:

```sh
sha256sum --check --ignore-missing checksums.txt
```

On macOS use `shasum -a 256 --check --ignore-missing checksums.txt`.

`checksums.txt` is also signed with [cosign](https://docs.sigstore.dev/) using keyless signing from GitHub Actions. To prove that it was built by this project's release workflow:

```sh
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/radestsam/nwrk/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Troubleshooting

**The download is slow or fails.** GitHub can be slow or unreliable on some networks. The install scripts retry three times. If they still fail, they print the release page, where you can download the files by any means and follow the manual steps above.

**`nw: command not found`.** The install directory is not on your `PATH`. The installer tells you which directory to add. If you installed with Go, add the Go bin directory. For zsh, run this once and open a new terminal:

```sh
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.zshrc
```

For bash, use `~/.bashrc` instead of `~/.zshrc`. If you set `GOBIN`, add that directory instead. To run `nw` without changing `PATH`, use its full path, for example `~/go/bin/nw version`.

**A different `nw` runs.** The NW.js project also installs a program named `nw`. If `which nw` (or `where nw` on Windows) points elsewhere, put the nwrk install directory earlier in your `PATH`.

## Uninstall

Delete the binary: `~/.local/bin/nw` on Linux and macOS, or `%LOCALAPPDATA%\nwrk\bin\nw.exe` on Windows. nw stores no other files yet.
