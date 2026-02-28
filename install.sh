#!/usr/bin/env bash
# macshield installer - installs the Swift binary or Bash fallback
set -euo pipefail

PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PATH

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"

# Detect Homebrew-managed install
if [[ "$SCRIPT_DIR" == *"/libexec"* ]] && command -v macshield &>/dev/null; then
    INSTALL_PATH="$(command -v macshield)"
    echo "macshield is already installed by Homebrew at $INSTALL_PATH"
    echo "Run 'macshield --help' to get started."
    exit 0
fi

INSTALL_PATH="/usr/local/bin/macshield"
SWIFT_BINARY="$SCRIPT_DIR/.build/release/MacShield"
BASH_SCRIPT="$SCRIPT_DIR/macshield.sh"

echo ""
echo "=== macshield installer ==="
echo ""
echo "macshield is a read-only macOS security analyzer."
echo "It checks your system security posture, scans ports, lists"
echo "persistence items, and audits app permissions."
echo ""
echo "It does NOT modify your system. No background processes."
echo "No LaunchAgents. No Keychain writes."
echo ""

# Determine which version to install
if [[ -f "$SWIFT_BINARY" ]]; then
    SOURCE="$SWIFT_BINARY"
    echo "Found compiled Swift binary (v1.0.0)."
    echo "This installer copies MacShield to $INSTALL_PATH"
elif [[ -f "$BASH_SCRIPT" ]]; then
    SOURCE="$BASH_SCRIPT"
    echo "Swift binary not found. Using Bash reference version (v0.5.0)."
    echo "To build the Swift version: swift build -c release"
    echo ""
    echo "This installer copies macshield.sh to $INSTALL_PATH"
else
    echo "Error: Neither Swift binary nor macshield.sh found in $SCRIPT_DIR"
    exit 1
fi

echo ""
echo "Review the source: https://github.com/qinnovates/macshield"
echo ""

printf "Install? [y/N]: "
read -r reply
if [[ ! "$reply" =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

sudo cp "$SOURCE" "$INSTALL_PATH"
sudo chmod 755 "$INSTALL_PATH"

echo ""
echo "Installed macshield to $INSTALL_PATH"
echo ""
echo "Quick start:"
echo "  macshield audit          # Full security posture check"
echo "  macshield scan           # Scan open ports"
echo "  macshield connections    # Who your Mac is talking to"
echo "  macshield persistence    # List startup items and agents"
echo "  macshield permissions    # Check app privacy permissions"
echo "  macshield --help         # All commands"
echo ""
