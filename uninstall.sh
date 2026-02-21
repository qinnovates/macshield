#!/usr/bin/env bash
# macshield uninstaller
set -euo pipefail

# Harden PATH and umask
PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PATH
umask 077

INSTALL_PATH="/usr/local/bin/macshield"
PLIST_NAME="com.qinnovates.macshield.plist"
AGENT_PATH="$HOME/Library/LaunchAgents/$PLIST_NAME"
DAEMON_PATH="/Library/LaunchDaemons/$PLIST_NAME"
SUDOERS_PATH="/etc/sudoers.d/macshield"
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
echo "  2. LaunchAgent ($AGENT_PATH)"
[[ -f "$DAEMON_PATH" ]] && echo "  2b. Legacy LaunchDaemon ($DAEMON_PATH)"
echo "  3. Sudoers authorization ($SUDOERS_PATH)"
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
if launchctl list 2>/dev/null | grep -q "com.qinnovates.macshield"; then
    echo "Unloading LaunchAgent..."
    launchctl bootout "gui/$(id -u)/com.qinnovates.macshield" 2>/dev/null || true
fi

# Unload legacy LaunchDaemon if present (v0.2.0)
if sudo launchctl list 2>/dev/null | grep -q "com.qinnovates.macshield"; then
    echo "Unloading legacy LaunchDaemon..."
    sudo launchctl bootout system/"$PLIST_NAME" 2>/dev/null || true
fi

# Remove files
if [[ -f "$INSTALL_PATH" ]]; then
    echo "Removing $INSTALL_PATH"
    sudo rm -f "$INSTALL_PATH"
fi

if [[ -f "$AGENT_PATH" ]]; then
    echo "Removing $AGENT_PATH"
    rm -f "$AGENT_PATH"
fi

if [[ -f "$DAEMON_PATH" ]]; then
    echo "Removing legacy $DAEMON_PATH"
    sudo rm -f "$DAEMON_PATH"
fi

# Remove sudoers fragment
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
