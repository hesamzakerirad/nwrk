#!/bin/sh
# nw installer: https://nwrk.ir
#
#   curl -fsSL https://nwrk.ir/install.sh | sh
#
# Downloads the nw release archive from GitHub Releases, verifies its SHA-256
# checksum against checksums.txt, and installs the binary. No root needed.
#
# Environment:
#   NW_VERSION        version to install, for example 0.1.0 (default: latest)
#   NW_INSTALL_DIR    install directory (default: $HOME/.local/bin)
#   NW_DOWNLOAD_BASE  release download base URL (default: GitHub Releases)
set -eu

REPO="radestsam/nwrk"
RELEASES="https://github.com/$REPO/releases"
BASE="${NW_DOWNLOAD_BASE:-$RELEASES/download}"

say() { printf '%s\n' "$*"; }
err() { printf 'install: %s\n' "$*" >&2; }
die() { err "$*"; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

fetch() { # url dest
  if have curl; then
    curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 15 -o "$2" "$1"
  elif have wget; then
    wget -q -t 3 -T 15 -O "$2" "$1"
  else
    die "curl or wget is required"
  fi
}

latest_version() {
  if have curl; then
    # /releases/latest redirects to /releases/tag/vX.Y.Z; this avoids the
    # rate limits of the GitHub API.
    tag=$(curl -fsSLI --retry 3 --retry-delay 2 --connect-timeout 15 \
      -o /dev/null -w '%{url_effective}' "$RELEASES/latest") || return 1
    tag=${tag##*/}
  elif have wget; then
    tag=$(wget -qO- "https://api.github.com/repos/$REPO/releases/latest" |
      sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1) || return 1
  else
    die "curl or wget is required"
  fi
  case "$tag" in
    v[0-9]*) say "${tag#v}" ;;
    *) return 1 ;;
  esac
}

sha256_of() {
  if have sha256sum; then
    sha256sum "$1" | cut -d ' ' -f 1
  elif have shasum; then
    shasum -a 256 "$1" | cut -d ' ' -f 1
  elif have openssl; then
    openssl dgst -sha256 "$1" | sed 's/^.*= *//'
  else
    die "sha256sum, shasum or openssl is required to verify the download"
  fi
}

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) die "unsupported OS $(uname -s); on Windows use install.ps1" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

version="${NW_VERSION:-}"
version="${version#v}"
if [ -z "$version" ]; then
  version=$(latest_version) || die "could not find the latest release; see $RELEASES or set NW_VERSION"
fi

archive="nw_${version}_${os}_${arch}.tar.gz"
url="$BASE/v$version/$archive"
sums_url="$BASE/v$version/checksums.txt"
dir="${NW_INSTALL_DIR:-$HOME/.local/bin}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Installing nw $version ($os/$arch)"
if ! fetch "$url" "$tmp/$archive" || ! fetch "$sums_url" "$tmp/checksums.txt"; then
  err "download failed"
  err "download $archive and checksums.txt manually from $RELEASES/tag/v$version"
  exit 1
fi

want=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1 }' "$tmp/checksums.txt")
[ -n "$want" ] || die "$archive is not listed in checksums.txt"
got=$(sha256_of "$tmp/$archive")
if [ "$got" != "$want" ]; then
  die "checksum mismatch for $archive (expected $want, got $got); nothing was installed"
fi
say "Checksum verified"

tar -xzf "$tmp/$archive" -C "$tmp" nw || die "could not extract nw from $archive"
mkdir -p "$dir" || die "could not create $dir; set NW_INSTALL_DIR to a writable directory"
# Copy under a temporary name, then rename, so a running nw is replaced safely.
if ! { cp "$tmp/nw" "$dir/.nw.new" && chmod 755 "$dir/.nw.new" && mv -f "$dir/.nw.new" "$dir/nw"; }; then
  die "could not write $dir/nw"
fi

say "Installed $dir/nw"
"$dir/nw" version | head -n 1

case ":$PATH:" in
  *":$dir:"*) ;;
  *)
    say ""
    say "$dir is not on your PATH, so the shell cannot find nw yet."
    say "Until then it can say \"Command 'nw' not found\" and suggest an unrelated package."
    say "To fix this, run the command below, then open a new terminal:"
    case "${SHELL:-}" in
      */zsh) rc='~/.zshrc' ;;
      *) rc='~/.bashrc' ;;
    esac
    say ""
    say "  echo 'export PATH=\"$dir:\$PATH\"' >> $rc"
    say ""
    say "To run nw now, use its full path: $dir/nw"
    ;;
esac
other=$(command -v nw 2>/dev/null || true)
if [ -n "$other" ] && [ "$other" != "$dir/nw" ]; then
  say "Note: $other is found first on your PATH and will run instead of this nw."
fi
