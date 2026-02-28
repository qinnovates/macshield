#!/usr/bin/env bash
# macshield uninstaller
set -euo pipefail

PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PATH

INSTALL_PATH="/usr/local/bin/macshield"

echo ""
echo "=== macshield uninstaller ==="
echo ""
echo "This will remove:"
echo "  1. $INSTALL_PATH"
echo ""

# Clean up legacy artifacts from older versions (v0.4.x and earlier)
LEGACY_ITEMS=""
if launchctl list 2>/dev/null | grep -q "com.qinnovates.macshield"; then
    LEGACY_ITEMS+="  - LaunchAgent (will be unloaded)"$'\n'
fi
[[ -f "$HOME/Library/LaunchAgents/com.qinnovates.macshield.plist" ]] && \
    LEGACY_ITEMS+="  - $HOME/Library/LaunchAgents/com.qinnovates.macshield.plist"$'\n'
[[ -f "/Library/LaunchDaemons/com.qinnovates.macshield.plist" ]] && \
    LEGACY_ITEMS+="  - /Library/LaunchDaemons/com.qinnovates.macshield.plist"$'\n'
[[ -f "/etc/sudoers.d/macshield" ]] && \
    LEGACY_ITEMS+="  - /etc/sudoers.d/macshield (sudoers fragment)"$'\n'

if [[ -n "$LEGACY_ITEMS" ]]; then
    echo "Legacy artifacts from older macshield versions found:"
    echo "$LEGACY_ITEMS"
fi

printf "Proceed? [y/N]: "
read -r reply
if [[ ! "$reply" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

echo ""

# Clean up legacy LaunchAgent/Daemon
if launchctl list 2>/dev/null | grep -q "com.qinnovates.macshield"; then
    echo "Unloading legacy LaunchAgent..."
    launchctl bootout "gui/$(id -u)/com.qinnovates.macshield" 2>/dev/null || true
fi
rm -f "$HOME/Library/LaunchAgents/com.qinnovates.macshield.plist"

if [[ -f "/Library/LaunchDaemons/com.qinnovates.macshield.plist" ]]; then
    echo "Removing legacy LaunchDaemon..."
    sudo launchctl bootout system/com.qinnovates.macshield.plist 2>/dev/null || true
    sudo rm -f "/Library/LaunchDaemons/com.qinnovates.macshield.plist"
fi

# Remove legacy sudoers fragment
if [[ -f "/etc/sudoers.d/macshield" ]]; then
    echo "Removing legacy sudoers fragment..."
    sudo rm -f "/etc/sudoers.d/macshield"
fi

# Remove legacy Keychain entries
security delete-generic-password -s "com.macshield.integrity" 2>/dev/null || true
while security delete-generic-password -s "com.macshield.trusted" 2>/dev/null; do true; done
security delete-generic-password -s "com.macshield.hostname" 2>/dev/null || true

# Remove binary
if [[ -f "$INSTALL_PATH" ]]; then
    echo "Removing $INSTALL_PATH"
    sudo rm -f "$INSTALL_PATH"
fi

# Remove temp files
rm -f /tmp/macshield.state /tmp/macshield.lock
rm -f /tmp/macshield.stdout.log /tmp/macshield.stderr.log
rm -f /tmp/macshield-port-report.txt /tmp/macshield-audit-report.txt

echo ""
echo "=== macshield has been completely removed ==="
echo ""
