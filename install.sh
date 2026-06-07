#!/usr/bin/env bash
# FaultWall installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/shreyasXV/faultwall/main/install.sh | bash
#   curl -fsSL .../install.sh | bash -s -- --version v0.3.0
#   curl -fsSL .../install.sh | bash -s -- --dir ~/bin
#   curl -fsSL .../install.sh | bash -s -- --token TFW_xxx --control-plane https://api.faultwall.com
#
# Flags:
#   --version VER        Release tag to install (default: latest)
#   --dir DIR            Install directory (default: /usr/local/bin)
#   --token TOKEN        Control-plane tenant token (enables auto-enroll + phone-home)
#   --control-plane URL  Control-plane base URL (e.g. https://api.faultwall.com)
#   --mode MODE          Enrollment mode: monitor (default) | proxy
#   --dry-run            Parse flags + print plan, then exit (no download/install)
#   --help, -h           Show this help
#
set -euo pipefail

REPO="shreyasXV/faultwall"
BIN_NAME="faultwall"
INSTALL_DIR="/usr/local/bin"
VERSION="latest"
FW_TOKEN=""
CONTROL_PLANE=""
MODE="monitor"
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)       VERSION="$2"; shift 2 ;;
    --dir)           INSTALL_DIR="$2"; shift 2 ;;
    --token)         FW_TOKEN="$2"; shift 2 ;;
    --control-plane) CONTROL_PLANE="$2"; shift 2 ;;
    --mode)          MODE="$2"; shift 2 ;;
    --dry-run)       DRY_RUN=1; shift ;;
    --help|-h)
      grep '^#' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# Normalize mode
case "$MODE" in
  monitor|proxy) ;;
  *) echo "Invalid --mode '$MODE' (use monitor|proxy); defaulting to monitor" >&2; MODE="monitor" ;;
esac

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "dry-run: VERSION=$VERSION INSTALL_DIR=$INSTALL_DIR MODE=$MODE"
  echo "dry-run: CONTROL_PLANE=${CONTROL_PLANE:-<none>} TOKEN=$( [[ -n "$FW_TOKEN" ]] && echo '<set>' || echo '<none>' )"
  exit 0
fi

# Detect OS and arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac
case "$OS" in
  linux|darwin) ;;
  *) echo "Unsupported OS: $OS" >&2; exit 1 ;;
esac

# Resolve latest version tag if needed
if [[ "$VERSION" == "latest" ]]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -o '"tag_name": *"[^"]*"' \
    | head -1 \
    | sed 's/"tag_name": *"\([^"]*\)"/\1/')
  if [[ -z "$VERSION" ]]; then
    echo "Failed to resolve latest version" >&2
    exit 1
  fi
fi

ASSET="faultwall-${VERSION}-${OS}-${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"

echo "🔒 FaultWall installer"
echo "    version: $VERSION"
echo "    target:  $OS/$ARCH"
echo "    url:     $URL"
echo

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "→ Downloading..."
curl -fsSL "$URL" -o "$TMP/$ASSET"

# Verify checksum if available
if curl -fsSL "https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt" -o "$TMP/checksums.txt" 2>/dev/null; then
  echo "→ Verifying checksum..."
  EXPECTED=$(grep "$ASSET" "$TMP/checksums.txt" | awk '{print $1}')
  if [[ -n "$EXPECTED" ]]; then
    ACTUAL=$(shasum -a 256 "$TMP/$ASSET" | awk '{print $1}')
    if [[ "$EXPECTED" != "$ACTUAL" ]]; then
      echo "✗ Checksum mismatch!" >&2
      echo "  expected: $EXPECTED" >&2
      echo "  got:      $ACTUAL" >&2
      exit 1
    fi
    echo "  ✓ checksum verified"
  fi
fi

echo "→ Extracting..."
tar -xzf "$TMP/$ASSET" -C "$TMP"

# Find the extracted binary, excluding the tarball itself
EXTRACTED=$(find "$TMP" -maxdepth 1 -name 'faultwall-*' -type f ! -name '*.tar.gz' ! -name '*.tgz' | head -1)
if [[ -z "$EXTRACTED" ]]; then
  echo "✗ Binary not found after extraction" >&2
  exit 1
fi

# Verify it's actually an executable, not a misnamed archive
if file "$EXTRACTED" | grep -qE 'gzip|compressed|archive'; then
  echo "✗ Expected binary but got archive: $EXTRACTED" >&2
  echo "  file type: $(file -b "$EXTRACTED")" >&2
  exit 1
fi

# Install
if [[ -w "$INSTALL_DIR" ]]; then
  mv "$EXTRACTED" "$INSTALL_DIR/$BIN_NAME"
  chmod +x "$INSTALL_DIR/$BIN_NAME"
else
  echo "→ Installing to $INSTALL_DIR (needs sudo)..."
  sudo mv "$EXTRACTED" "$INSTALL_DIR/$BIN_NAME"
  sudo chmod +x "$INSTALL_DIR/$BIN_NAME"
fi

echo
echo "✅ Installed faultwall $VERSION → $INSTALL_DIR/$BIN_NAME"

# ── Control-plane enrollment (optional, non-fatal) ──
# If --token + --control-plane were supplied, register this installation and
# write a local config so the proxy can phone home (metadata only — never
# query text or policy bodies).
if [[ -n "$FW_TOKEN" && -n "$CONTROL_PLANE" ]]; then
  CP_URL="${CONTROL_PLANE%/}"
  CONFIG_DIR="${HOME}/.faultwall"
  CONFIG_FILE="${CONFIG_DIR}/config.toml"
  HOST_NAME="$(hostname 2>/dev/null || echo unknown)"

  echo
  echo "→ Enrolling with control plane $CP_URL (mode: $MODE)..."
  mkdir -p "$CONFIG_DIR"

  ENROLL_BODY=$(printf '{"hostname":"%s","mode":"%s","version":"%s","pg_target_redacted":"%s"}' \
    "$HOST_NAME" "$MODE" "$VERSION" "redacted")

  ENROLL_OK=0
  ENROLL_RESP=""
  if ENROLL_RESP=$(curl -fsSL -X POST "${CP_URL}/v1/enroll" \
        -H "Authorization: Bearer ${FW_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$ENROLL_BODY" 2>/dev/null); then
    ENROLL_OK=1
  fi

  # Best-effort parse of installation_id from the JSON response.
  INSTALL_ID=""
  if [[ -n "$ENROLL_RESP" ]]; then
    INSTALL_ID=$(printf '%s' "$ENROLL_RESP" \
      | grep -o '"installation_id": *"[^"]*"' \
      | head -1 | sed 's/.*"installation_id": *"\([^"]*\)".*/\1/')
  fi

  # Write config regardless so the proxy can retry phone-home later.
  umask 077
  cat > "$CONFIG_FILE" <<EOF
# FaultWall control-plane link — written by install.sh
# Metadata-only telemetry. Query text and policy bodies stay on this host.
[control_plane]
url = "${CP_URL}"
token = "${FW_TOKEN}"
mode = "${MODE}"
installation_id = "${INSTALL_ID}"
telemetry_enabled = true
EOF
  chmod 600 "$CONFIG_FILE" 2>/dev/null || true

  if [[ "$ENROLL_OK" -eq 1 ]]; then
    echo "  ✓ enrolled (installation_id: ${INSTALL_ID:-unknown})"
  else
    echo "  ⚠️  enroll request failed — wrote config anyway; the proxy will retry phone-home on start." >&2
  fi
  echo "  → config: $CONFIG_FILE"
fi

echo
echo "Next: run"
echo "  faultwall init"
echo "  faultwall --proxy --policies faultwall.yaml"
