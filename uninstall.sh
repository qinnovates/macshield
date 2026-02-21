#!/usr/bin/env bash
# macshield uninstaller
set -euo pipefail

INSTALL_PATH="/usr/local/bin/macshield"
SUDOERS_PATH="/etc/sudoers.d/macshield"
PLIST_NAME="com.qinnovates.macshield.plist"
LAUNCHAGENT_PATH="$HOME/Library/LaunchAgents/$PLIST_NAME"
STATE_FILE="/tmp/macshield.state"

ask() {
    local prompt="$1"
    local reply
    printf "%s [y/N]: " "$prompt"
    read -r reply
    [[ "$reply" =~ ^[Yy]$ ]]
}

echo ""
echo "=== macshield uninstaller ==="
echo ""
echo "This will remove:"
echo "  1. $INSTALL_PATH"
echo "  2. $SUDOERS_PATH (sudoers fragment)"
echo "  3. $LAUNCHAGENT_PATH"
echo "  4. Keychain entries under \"com.macshield.trusted\" and \"com.macshield.hostname\""
echo "  5. Ephemeral state file ($STATE_FILE)"
echo ""
echo "Your hostname and firewall settings will remain as currently set."
echo ""

if ! ask "Proceed?"; then
    echo "Aborted."
    exit 0
fi

echo ""

# Unload LaunchAgent
if launchctl list | grep -q "com.qinnovates.macshield" 2>/dev/null; then
    echo "Unloading LaunchAgent..."
    launchctl bootout "gui/$(id -u)/$PLIST_NAME" 2>/dev/null || true
fi

# Remove files
for f in "$INSTALL_PATH" "$LAUNCHAGENT_PATH"; do
    if [[ -f "$f" ]]; then
        echo "Removing $f"
        if [[ "$f" == /usr/* ]] || [[ "$f" == /etc/* ]]; then
            sudo rm -f "$f"
        else
            rm -f "$f"
        fi
    fi
done

# Remove sudoers
if [[ -f "$SUDOERS_PATH" ]]; then
    echo "Removing $SUDOERS_PATH"
    sudo rm -f "$SUDOERS_PATH"
fi

# Clear Keychain entries
echo "Removing Keychain entries..."
while security delete-generic-password -s "com.macshield.trusted" 2>/dev/null; do
    true
done
security delete-generic-password -s "com.macshield.hostname" 2>/dev/null || true

# Remove state file
rm -f "$STATE_FILE"
rm -f /tmp/macshield.lock
rm -f /tmp/macshield.stdout.log
rm -f /tmp/macshield.stderr.log

echo ""
echo "=== macshield has been completely removed ==="
echo ""
echo "Your hostname and firewall settings were left as-is."
echo "To manually reset stealth mode:"
echo "  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off"
echo ""
