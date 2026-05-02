#!/bin/sh
set -eu

REPO="balyakin/sudocheck"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
TMP_DIR="${TMPDIR:-/tmp}/sudocheck-install"
API_URL="https://api.github.com/repos/$REPO/releases/latest"
MODULE="github.com/$REPO"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
uname_arch="$(uname -m)"
arch="$uname_arch"

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

install_binary() {
  source_path="$1"
  if [ -w "$INSTALL_DIR" ]; then
    mv "$source_path" "$INSTALL_DIR/sudocheck"
  else
    sudo mv "$source_path" "$INSTALL_DIR/sudocheck"
  fi
}

install_from_source() {
  if ! command -v go >/dev/null 2>&1; then
    echo "no published release found and Go is not installed" >&2
    echo "create a GitHub Release with binaries or install Go and run:" >&2
    echo "  go install $MODULE@latest" >&2
    exit 1
  fi

  echo "no published release found; installing from source with go install" >&2
  GOBIN="$TMP_DIR/bin" go install "$MODULE@latest"
  install_binary "$TMP_DIR/bin/sudocheck"
  echo "sudocheck installed to $INSTALL_DIR/sudocheck"
  exit 0
}

if ! release_json="$(curl -fsSL "$API_URL")"; then
  install_from_source
fi
latest="$(printf '%s\n' "$release_json" | grep '"tag_name"' | cut -d '"' -f 4 | head -n 1)"
archive_url="$(
  printf '%s\n' "$release_json" |
    grep '"browser_download_url":' |
    cut -d '"' -f 4 |
    awk -v os="$os" -v arch="$arch" -v uname_arch="$uname_arch" '
      function matches_arch(value) {
        return index(value, arch) > 0 ||
          index(value, uname_arch) > 0 ||
          (arch == "amd64" && index(value, "x86_64") > 0) ||
          (arch == "arm64" && index(value, "aarch64") > 0)
      }
      {
        value = tolower($0)
        if (index(value, os) > 0 && matches_arch(value) && value ~ /\.tar\.gz$/) {
          print $0
          exit
        }
      }
    ' |
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
  install_from_source
fi

if [ -z "$archive_url" ]; then
  echo "could not find release archive for ${os}/${arch}; trying source install" >&2
  echo "available assets:" >&2
  printf '%s\n' "$release_json" | grep '"browser_download_url":' | cut -d '"' -f 4 >&2
  install_from_source
fi

if [ -z "$checksum_url" ]; then
  echo "could not find checksums.txt in latest release" >&2
  exit 1
fi

archive="$(basename "$archive_url")"

rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"
cd "$TMP_DIR"

curl -fLsS -o "$archive" "$archive_url"
curl -fLsS -o checksums.txt "$checksum_url"
checksum_line="$(grep "$archive" checksums.txt || true)"
if [ -z "$checksum_line" ]; then
  echo "checksums.txt does not contain checksum for $archive" >&2
  echo "checksums.txt contents:" >&2
  cat checksums.txt >&2
  exit 1
fi
checksum="$(printf '%s\n' "$checksum_line" | sed -n 's/.*\([A-Fa-f0-9]\{64\}\).*/\1/p' | head -n 1)"
if [ -z "$checksum" ]; then
  echo "could not parse SHA256 checksum for $archive" >&2
  echo "$checksum_line" >&2
  exit 1
fi
printf '%s  %s\n' "$checksum" "$archive" | sha256sum -c -
tar xzf "$archive"

install_binary sudocheck

echo "sudocheck $latest installed to $INSTALL_DIR/sudocheck"
