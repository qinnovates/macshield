#!/usr/bin/env bash
# macshield installer - copies the analyzer to /usr/local/bin
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

echo ""
echo "=== macshield installer ==="
echo ""
echo "macshield is a read-only macOS security analyzer."
echo "It checks your system security posture, scans ports, lists"
echo "persistence items, and audits app permissions."
echo ""
echo "It does NOT modify your system. No sudo needed. No background"
echo "processes. No LaunchAgents. No Keychain writes."
echo ""
echo "This installer copies macshield.sh to $INSTALL_PATH"
echo ""
echo "Review the source: cat $SCRIPT_DIR/macshield.sh"
echo ""

printf "Install? [y/N]: "
read -r reply
if [[ ! "$reply" =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

sudo cp "$SCRIPT_DIR/macshield.sh" "$INSTALL_PATH"
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
