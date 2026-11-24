#!/bin/sh
# Tests site/static/install.sh against a local fake release, so no network or
# real release is needed. Run from the repository root.
set -eu

root=$(pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; *) echo "unsupported OS"; exit 1 ;; esac
case "$(uname -m)" in x86_64 | amd64) arch=amd64 ;; *) arch=arm64 ;; esac
version=9.9.9
archive="nw_${version}_${os}_${arch}.tar.gz"
rel="$tmp/rel/v$version"
mkdir -p "$rel" "$tmp/stage"

go build -ldflags "-X github.com/radestsam/nwrk/internal/buildinfo.Version=$version" \
  -o "$tmp/stage/nw" ./cmd/nw
cp LICENSE README.md "$tmp/stage/"
tar -czf "$rel/$archive" -C "$tmp/stage" nw LICENSE README.md
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$rel" && sha256sum "$archive" >checksums.txt)
else
  (cd "$rel" && shasum -a 256 "$archive" >checksums.txt)
fi

install_sh() { # install dir
  NW_DOWNLOAD_BASE="file://$tmp/rel" NW_VERSION="$version" NW_INSTALL_DIR="$1" \
    sh "$root/site/static/install.sh"
}

echo "== good archive"
install_sh "$tmp/good"
"$tmp/good/nw" version --output json | grep -q "\"version\": \"$version\""

echo "== tampered archive is rejected"
printf 'tampered' >>"$rel/$archive"
if install_sh "$tmp/bad" 2>"$tmp/bad.err"; then
  echo "FAIL: tampered archive was installed"
  exit 1
fi
grep -q 'checksum mismatch' "$tmp/bad.err"
[ ! -e "$tmp/bad/nw" ]

echo "== missing release fails cleanly"
if NW_DOWNLOAD_BASE="file://$tmp/none" NW_VERSION=1.0.0 NW_INSTALL_DIR="$tmp/none-bin" \
  sh "$root/site/static/install.sh" 2>"$tmp/none.err"; then
  echo "FAIL: missing release did not fail"
  exit 1
fi
grep -q 'download failed' "$tmp/none.err"

echo "install.sh tests passed"
