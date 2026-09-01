#!/usr/bin/env bash
set -Eeuo pipefail

# idNX universal installer for macOS and Linux.
#
#   curl -fsSL https://idnx.sh | bash
#   curl -fsSL https://idnx.sh | VERSION=v0.2.2 bash
#   curl -fsSL https://idnx.sh | IDNX_INSTALL_DIR="$HOME/.local/bin" bash

REPO="${IDNX_REPO:-marirs/idnx}"
BIN_NAME="idnx"
INSTALL_DIR="${IDNX_INSTALL_DIR:-/usr/local/bin}"
VERSION="${VERSION:-latest}"

if [[ -t 1 ]]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  BLUE='\033[0;34m'
  YELLOW='\033[1;33m'
  CYAN='\033[0;36m'
  BOLD='\033[1m'
  NC='\033[0m'
else
  RED='' GREEN='' BLUE='' YELLOW='' CYAN='' BOLD='' NC=''
fi

info() { printf '%b[*]%b %s\n' "$BLUE" "$NC" "$*"; }
warn() { printf '%b[!]%b %s\n' "$YELLOW" "$NC" "$*" >&2; }
die()  { printf '%b[!]%b %s\n' "$RED" "$NC" "$*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

cleanup() {
  if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then
    rm -rf -- "$TMP_DIR"
  fi
}
trap cleanup EXIT INT TERM

printf '%b%b' "$CYAN" "$BOLD"
printf '%s\n' \
  '  _     _ _   _  __  __' \
  ' (_) __| | \ | | \ \/ /' \
  ' | |/ _` |  \| |  \  / ' \
  ' | | (_| | |\  |  /  \ ' \
  ' |_|\__,_|_| \_| /_/\_\ '
printf '%b' "$NC"
info "Installing ${BOLD}idNX${NC} (Network Identification & Deep eXploration Tool)..."

need_cmd uname
need_cmd curl
need_cmd tar
need_cmd mktemp

case "$(uname -s)" in
  Darwin) OS_TARGET="apple-darwin" ;;
  Linux)  OS_TARGET="unknown-linux-gnu" ;;
  *)
    die "Unsupported operating system: $(uname -s). Pre-built shell installs support macOS and Linux; Windows builds are available from https://github.com/${REPO}/releases"
    ;;
esac

case "$(uname -m)" in
  x86_64|amd64)  ARCH_TARGET="x86_64" ;;
  arm64|aarch64) ARCH_TARGET="aarch64" ;;
  *)
    die "Unsupported architecture: $(uname -m). Build from source with: cargo install --git https://github.com/${REPO}.git"
    ;;
esac

TARGET="${ARCH_TARGET}-${OS_TARGET}"
ARCHIVE_NAME="${BIN_NAME}-${TARGET}.tar.gz"

if [[ "$VERSION" == "latest" ]]; then
  RELEASE_URL="https://github.com/${REPO}/releases/latest/download"
  VERSION_LABEL="latest"
else
  [[ "$VERSION" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([._+-][A-Za-z0-9.-]+)?$ ]] \
    || die "Invalid VERSION value: $VERSION"
  RELEASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
  VERSION_LABEL="$VERSION"
fi

ARCHIVE_URL="${RELEASE_URL}/${ARCHIVE_NAME}"
CHECKSUM_URL="${ARCHIVE_URL}.sha256"
TMP_DIR="$(mktemp -d)"
ARCHIVE_PATH="${TMP_DIR}/${ARCHIVE_NAME}"
CHECKSUM_PATH="${ARCHIVE_PATH}.sha256"

info "Detected platform: ${CYAN}${TARGET}${NC}"
info "Downloading ${VERSION_LABEL} release..."
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 1 \
  "$ARCHIVE_URL" -o "$ARCHIVE_PATH" \
  || die "No release binary was found for ${TARGET}. Check https://github.com/${REPO}/releases"
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 1 \
  "$CHECKSUM_URL" -o "$CHECKSUM_PATH" \
  || die "The checksum file is missing: ${ARCHIVE_NAME}.sha256"

info "Verifying SHA-256 checksum..."
EXPECTED_SHA="$(awk 'NR == 1 { print $1 }' "$CHECKSUM_PATH")"
[[ "$EXPECTED_SHA" =~ ^[A-Fa-f0-9]{64}$ ]] || die "The published checksum is invalid."

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_SHA="$(sha256sum "$ARCHIVE_PATH" | awk '{ print $1 }')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL_SHA="$(shasum -a 256 "$ARCHIVE_PATH" | awk '{ print $1 }')"
else
  die "Neither sha256sum nor shasum is available; refusing an unverified install."
fi

ACTUAL_SHA="$(printf '%s' "$ACTUAL_SHA" | tr '[:upper:]' '[:lower:]')"
EXPECTED_SHA="$(printf '%s' "$EXPECTED_SHA" | tr '[:upper:]' '[:lower:]')"
[[ "$ACTUAL_SHA" == "$EXPECTED_SHA" ]] \
  || die "Checksum verification failed; the downloaded archive was not installed."

tar -xzf "$ARCHIVE_PATH" -C "$TMP_DIR"
[[ -f "${TMP_DIR}/${BIN_NAME}" ]] || die "Archive did not contain the ${BIN_NAME} binary."
chmod 0755 "${TMP_DIR}/${BIN_NAME}"

install_binary() {
  local destination="${INSTALL_DIR}/${BIN_NAME}"
  mkdir -p "$INSTALL_DIR" 2>/dev/null || true

  if [[ -d "$INSTALL_DIR" && -w "$INSTALL_DIR" ]]; then
    install -m 0755 "${TMP_DIR}/${BIN_NAME}" "$destination"
  elif command -v sudo >/dev/null 2>&1; then
    info "Installing to ${INSTALL_DIR} with sudo..."
    sudo mkdir -p "$INSTALL_DIR"
    sudo install -m 0755 "${TMP_DIR}/${BIN_NAME}" "$destination"
  elif [[ -z "${IDNX_INSTALL_DIR:-}" ]]; then
    INSTALL_DIR="${HOME}/.local/bin"
    destination="${INSTALL_DIR}/${BIN_NAME}"
    mkdir -p "$INSTALL_DIR"
    install -m 0755 "${TMP_DIR}/${BIN_NAME}" "$destination"
    warn "sudo is unavailable; installed to ${INSTALL_DIR} instead."
  else
    die "Cannot write to ${INSTALL_DIR}, and sudo is unavailable."
  fi
}

need_cmd install
install_binary

INSTALLED_PATH="${INSTALL_DIR}/${BIN_NAME}"
[[ -x "$INSTALLED_PATH" ]] || die "Installation verification failed: ${INSTALLED_PATH} is not executable."

INSTALLED_VERSION="$($INSTALLED_PATH --version 2>/dev/null || true)"
if [[ -n "$INSTALLED_VERSION" ]]; then
  printf '%b[+]%b Installed %s to %s\n' "$GREEN" "$NC" "$INSTALLED_VERSION" "$INSTALLED_PATH"
else
  printf '%b[+]%b Installed idNX to %s\n' "$GREEN" "$NC" "$INSTALLED_PATH"
fi

if [[ ":${PATH}:" != *":${INSTALL_DIR}:"* ]]; then
  warn "${INSTALL_DIR} is not currently in PATH. Add this to your shell profile:"
  printf '  export PATH="%s:$PATH"\n' "$INSTALL_DIR"
fi

printf '\n%bQuick start:%b\n' "$CYAN$BOLD" "$NC"
printf '%s\n' \
  '  idnx               # Discover the local and cascaded network' \
  '  sudo idnx          # Include LLDP/CDP/MNDP Layer 2 discovery' \
  '  idnx --output json # Export the asset inventory to JSON'
