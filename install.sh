#!/bin/sh
set -eu

REPO="balyakin/sudocheck"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
TMP_DIR="${TMPDIR:-/tmp}/sudocheck-install"
API_URL="https://api.github.com/repos/$REPO/releases/latest"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"

case "$os" in
  linux) ;;
  *)
    echo "unsupported OS: $os" >&2
    exit 1
    ;;
esac

case "$arch" in
  x86_64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  armv7l) arch="arm" ;;
  *)
    echo "unsupported arch: $arch" >&2
    exit 1
    ;;
esac

release_json="$(curl -fsSL "$API_URL")"
latest="$(printf '%s\n' "$release_json" | grep '"tag_name"' | cut -d '"' -f 4 | head -n 1)"
archive_url="$(
  printf '%s\n' "$release_json" |
    grep '"browser_download_url":' |
    cut -d '"' -f 4 |
    grep "${os}_${arch}.*\\.tar\\.gz$" |
    head -n 1
)"
checksum_url="$(
  printf '%s\n' "$release_json" |
    grep '"browser_download_url":' |
    cut -d '"' -f 4 |
    grep '/checksums.txt$' |
    head -n 1
)"

if [ -z "$latest" ]; then
  echo "could not determine latest release tag for $REPO" >&2
  exit 1
fi

if [ -z "$archive_url" ]; then
  echo "could not find release archive for ${os}/${arch}" >&2
  echo "available assets:" >&2
  printf '%s\n' "$release_json" | grep '"browser_download_url":' | cut -d '"' -f 4 >&2
  exit 1
fi

if [ -z "$checksum_url" ]; then
  echo "could not find checksums.txt in latest release" >&2
  exit 1
fi

archive="$(basename "$archive_url")"

rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"
cd "$TMP_DIR"

curl -fsSLO "$archive_url"
curl -fsSLO "$checksum_url"
checksum_line="$(grep "[ *]$archive$" checksums.txt || true)"
if [ -z "$checksum_line" ]; then
  echo "checksums.txt does not contain checksum for $archive" >&2
  echo "checksums.txt contents:" >&2
  cat checksums.txt >&2
  exit 1
fi
printf '%s\n' "$checksum_line" | sha256sum -c -
tar xzf "$archive"

if [ -w "$INSTALL_DIR" ]; then
  mv sudocheck "$INSTALL_DIR/sudocheck"
else
  sudo mv sudocheck "$INSTALL_DIR/sudocheck"
fi

echo "sudocheck $latest installed to $INSTALL_DIR/sudocheck"
