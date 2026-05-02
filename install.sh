#!/bin/sh
set -eu

REPO="balyakin/sudocheck"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
TMP_DIR="${TMPDIR:-/tmp}/sudocheck-install"

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

latest="$(curl -sSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | cut -d '"' -f 4)"
archive="sudocheck_${os}_${arch}.tar.gz"
base_url="https://github.com/$REPO/releases/download/$latest"

rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"
cd "$TMP_DIR"

curl -sSLO "$base_url/$archive"
curl -sSLO "$base_url/checksums.txt"
grep "$archive" checksums.txt | sha256sum -c -
tar xzf "$archive"

if [ -w "$INSTALL_DIR" ]; then
  mv sudocheck "$INSTALL_DIR/sudocheck"
else
  sudo mv sudocheck "$INSTALL_DIR/sudocheck"
fi

echo "sudocheck $latest installed to $INSTALL_DIR/sudocheck"

