#!/usr/bin/env bash
# FaultWall — one-command try.
#
#   curl -fsSL https://app.faultwall.com/try.sh | bash
#       → demo Postgres + scripted demo agents, live view in ~60s
#
#   curl -fsSL https://app.faultwall.com/try.sh | bash -s -- postgres://user:pass@host:5432/db
#       → FaultWall in MONITOR mode (never blocks) in front of YOUR database
#
# No sudo, no YAML, no Go toolchain. Installs the binary to ~/.faultwall/bin
# (override with FAULTWALL_DIR) and runs `faultwall try` with your arguments.
#
# Env overrides:
#   FAULTWALL_VERSION        release tag (default: latest)
#   FAULTWALL_DIR            install dir (default: ~/.faultwall/bin)
#   FAULTWALL_DOWNLOAD_BASE  alternate release mirror (…/<version>/<asset>)
#   FAULTWALL_NO_RUN=1       install only, don't start
set -euo pipefail

REPO="shreyasXV/faultwall"
VERSION="${FAULTWALL_VERSION:-latest}"
DIR="${FAULTWALL_DIR:-$HOME/.faultwall/bin}"
BASE="${FAULTWALL_DOWNLOAD_BASE:-https://github.com/${REPO}/releases/download}"

say() { printf '%s\n' "$*" >&2; }
die() { say "✗ $*"; exit 1; }

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar  >/dev/null 2>&1 || die "tar is required"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture: $ARCH" ;;
esac
case "$OS" in
  linux|darwin) ;;
  *) die "unsupported OS: $OS (try Docker: docker run -it -p 8080:8080 -p 5433:5433 ghcr.io/shreyasxv/faultwall try)" ;;
esac

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else echo ""; fi
}

if [[ "$VERSION" == "latest" ]]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/') || true
  [[ -n "$VERSION" ]] || die "could not resolve latest release (set FAULTWALL_VERSION=vX.Y.Z)"
fi

BIN="$DIR/faultwall"
NEED=1
if [[ -x "$BIN" ]] && "$BIN" version 2>/dev/null | grep -q " ${VERSION}\$"; then
  NEED=0
fi

if [[ "$NEED" -eq 1 ]]; then
  ASSET="faultwall-${VERSION}-${OS}-${ARCH}.tar.gz"
  TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
  say "→ Downloading FaultWall ${VERSION} (${OS}/${ARCH})…"
  curl -fsSL "${BASE}/${VERSION}/${ASSET}" -o "$TMP/$ASSET" || die "download failed: ${BASE}/${VERSION}/${ASSET}"
  if curl -fsSL "${BASE}/${VERSION}/checksums.txt" -o "$TMP/checksums.txt" 2>/dev/null; then
    EXPECTED=$(grep " ${ASSET}\$\| \*${ASSET}\$\|  ${ASSET}\$" "$TMP/checksums.txt" | awk '{print $1}' | head -1 || true)
    ACTUAL=$(sha256_of "$TMP/$ASSET")
    if [[ -n "$EXPECTED" && -n "$ACTUAL" && "$EXPECTED" != "$ACTUAL" ]]; then
      die "checksum mismatch for $ASSET"
    fi
  fi
  tar -xzf "$TMP/$ASSET" -C "$TMP"
  EXTRACTED=$(find "$TMP" -maxdepth 1 -type f -name 'faultwall*' ! -name '*.tar.gz' ! -name 'checksums.txt' | head -1)
  [[ -n "$EXTRACTED" ]] || die "binary not found in $ASSET"
  mkdir -p "$DIR"
  mv "$EXTRACTED" "$BIN"; chmod +x "$BIN"
  say "  ✓ installed $BIN"
fi

[[ "${FAULTWALL_NO_RUN:-0}" == "1" ]] && { say "Installed. Run: $BIN try"; exit 0; }

# Re-attach stdin to the terminal so Ctrl+C works when piped from curl.
if [[ ! -t 0 ]] && { true </dev/tty; } 2>/dev/null; then
  exec "$BIN" try "$@" </dev/tty
fi
exec "$BIN" try "$@"
