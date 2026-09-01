#!/usr/bin/env bash
set -e

# idNX Installer Script
# Usage: curl -sSL idnx.sh | bash
# or:    curl -sSL https://raw.githubusercontent.com/marirs/idnx/master/install.sh | bash

REPO="marirs/idnx"
BIN_NAME="idnx"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "  _     _ _   _  __  __"
echo " (_) __| | \ | | \ \/ /"
echo " | |/ _` |  \| |  \  / "
echo " | | (_| | |\  |  /  \ "
echo " |_|\__,_|_| \_| /_/\_\ "
echo -e "${NC}"
echo -e "${BLUE}[*]${NC} Installing ${BOLD}idNX${NC} (Network Identification & Deep eXploration Tool)..."

# 1. Detect Operating System
OS="$(uname -s)"
case "$OS" in
    Darwin)
        OS_TARGET="apple-darwin"
        ;;
    Linux)
        OS_TARGET="unknown-linux-gnu"
        ;;
    *)
        echo -e "${RED}[!] Unsupported Operating System: $OS${NC}"
        echo "idNX currently provides pre-built binaries for macOS and Linux."
        echo "For Windows, download the latest zip from: https://github.com/${REPO}/releases"
        exit 1
        ;;
esac

# 2. Detect Architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)
        ARCH_TARGET="x86_64"
        ;;
    arm64|aarch64)
        ARCH_TARGET="aarch64"
        ;;
    *)
        echo -e "${RED}[!] Unsupported architecture: $ARCH${NC}"
        echo "Please build idNX from source using: cargo install --git https://github.com/${REPO}.git"
        exit 1
        ;;
esac

TARGET="${ARCH_TARGET}-${OS_TARGET}"
echo -e "${BLUE}[*]${NC} Detected platform: ${CYAN}${TARGET}${NC}"

# 3. Determine Latest Release Version
if [ -z "$VERSION" ]; then
    echo -e "${BLUE}[*]${NC} Fetching latest release info from GitHub..."
    LATEST_TAG=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [ -z "$LATEST_TAG" ] || [ "$LATEST_TAG" = "null" ]; then
        echo -e "${YELLOW}[!] Could not resolve latest tag via GitHub API (possibly rate-limited). Falling back to v0.1.0${NC}"
        VERSION="v0.1.0"
    else
        VERSION="$LATEST_TAG"
    fi
fi

echo -e "${BLUE}[*]${NC} Target version: ${GREEN}${VERSION}${NC}"

# 4. Download and Extract
ARCHIVE_NAME="${BIN_NAME}-${TARGET}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE_NAME}"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo -e "${BLUE}[*]${NC} Downloading ${DOWNLOAD_URL}..."
if ! curl -sSL --fail "$DOWNLOAD_URL" -o "$TMP_DIR/$ARCHIVE_NAME"; then
    echo -e "${RED}[!] Failed to download binary for ${TARGET} (${VERSION}).${NC}"
    echo "Check available assets at: https://github.com/${REPO}/releases"
    exit 1
fi

echo -e "${BLUE}[*]${NC} Extracting archive..."
tar -xzf "$TMP_DIR/$ARCHIVE_NAME" -C "$TMP_DIR"

if [ ! -f "$TMP_DIR/$BIN_NAME" ]; then
    echo -e "${RED}[!] Binary $BIN_NAME not found in downloaded archive.${NC}"
    exit 1
fi

chmod +x "$TMP_DIR/$BIN_NAME"

# 5. Install Binary
INSTALL_DIR="/usr/local/bin"
USE_SUDO=0

if [ -w "$INSTALL_DIR" ]; then
    cp "$TMP_DIR/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
elif command -v sudo >/dev/null 2>&1; then
    echo -e "${YELLOW}[*]${NC} Elevating privileges with sudo to install into ${INSTALL_DIR}..."
    sudo cp "$TMP_DIR/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
    cp "$TMP_DIR/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
    echo -e "${YELLOW}[*]${NC} Installed to user directory: ${INSTALL_DIR}"
fi

# 6. Verify Installation
echo -e "${GREEN}[+]${NC} Verifying installation..."
if command -v idnx >/dev/null 2>&1; then
    INSTALLED_VER=$(idnx --version 2>/dev/null || echo "$VERSION")
    echo -e "${GREEN}${BOLD}✓ idNX (${INSTALLED_VER}) successfully installed to ${INSTALL_DIR}/${BIN_NAME}!${NC}"
else
    echo -e "${GREEN}${BOLD}✓ idNX successfully installed to ${INSTALL_DIR}/${BIN_NAME}!${NC}"
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        echo -e "${YELLOW}[!] Warning: ${INSTALL_DIR} is not currently in your \$PATH.${NC}"
        echo -e "Add it to your shell profile:"
        echo -e "  export PATH=\"\$PATH:${INSTALL_DIR}\""
    fi
fi

echo ""
echo -e "${CYAN}${BOLD}Quick Start:${NC}"
echo -e "  idnx               # Auto-detect interface & scan local + cascaded subnets"
echo -e "  sudo idnx          # Full Layer 2 discovery (LLDP / CDP switch ports)"
echo -e "  idnx --output json # Export complete asset inventory to JSON"
echo ""
