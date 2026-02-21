#!/usr/bin/env bash
# macshield installer - explicit consent at every step
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_PATH="/usr/local/bin/macshield"
PLIST_NAME="com.qinnovates.macshield.plist"
DAEMON_PATH="/Library/LaunchDaemons/$PLIST_NAME"

log() {
    echo "[macshield] $*"
}

ask() {
    local prompt="$1"
    local reply
    printf "%s [y/N]: " "$prompt"
    read -r reply
    [[ "$reply" =~ ^[Yy]$ ]]
}

# ---------------------------------------------------------------------------

echo ""
echo "=== macshield installer ==="
echo ""
echo "macshield automatically hardens your Mac on untrusted WiFi networks."
echo ""
echo "This installer will:"
echo ""
echo "  1. Copy macshield.sh to $INSTALL_PATH"
echo "  2. Install a LaunchDaemon that triggers on network changes"
echo "     The daemon runs as root so no sudoers fragment is needed."
echo "     The script is pure bash and fully auditable."
echo "  3. Optionally add your current network as trusted"
echo ""
echo "Each step requires your explicit approval."
echo ""

# ---------------------------------------------------------------------------
# Step 1: Install binary
# ---------------------------------------------------------------------------

echo "Step 1: Install macshield to $INSTALL_PATH"
echo "  This makes the 'macshield' command available system-wide."
if ask "  Proceed?"; then
    sudo cp "$SCRIPT_DIR/macshield.sh" "$INSTALL_PATH"
    sudo chmod 755 "$INSTALL_PATH"
    log "Installed macshield to $INSTALL_PATH"
else
    echo "  Skipped."
fi
echo ""

# ---------------------------------------------------------------------------
# Step 2: LaunchDaemon
# ---------------------------------------------------------------------------

echo "Step 2: Install LaunchDaemon"
echo "  This watches for WiFi network changes and triggers macshield automatically."
echo "  It runs as root (no sudoers fragment needed). It watches:"
echo "    /Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"
echo "    /Library/Preferences/SystemConfiguration/preferences.plist"
echo ""
echo "  The daemon runs a pure bash script. You can audit every line:"
echo "    cat $INSTALL_PATH"
echo ""
if ask "  Install this?"; then
    # Unload first if already loaded (ignore errors)
    sudo launchctl bootout system/"$PLIST_NAME" 2>/dev/null || true

    sudo cp "$SCRIPT_DIR/$PLIST_NAME" "$DAEMON_PATH"
    sudo chown root:wheel "$DAEMON_PATH"
    sudo chmod 644 "$DAEMON_PATH"

    sudo launchctl bootstrap system "$DAEMON_PATH"
    log "Installed and loaded LaunchDaemon"
else
    echo "  Skipped. You can trigger macshield manually with 'sudo macshield harden'."
fi
echo ""

# ---------------------------------------------------------------------------
# Step 3: Trust current network
# ---------------------------------------------------------------------------

echo "Step 3: Trust current network?"

WIFI_IFACE=$(networksetup -listallhardwareports | awk '/Wi-Fi|AirPort/{getline; print $2}')
CURRENT_SSID=""
if [[ -n "$WIFI_IFACE" ]]; then
    # Method 1: ipconfig (most reliable on modern macOS)
    CURRENT_SSID=$(ipconfig getsummary "$WIFI_IFACE" 2>/dev/null | awk -F' : ' '/SSID/{print $2; exit}')

    # Method 2: networksetup (fallback)
    if [[ -z "$CURRENT_SSID" ]]; then
        OUTPUT=$(networksetup -getairportnetwork "$WIFI_IFACE" 2>/dev/null || echo "")
        SSID_CANDIDATE="${OUTPUT#*: }"
        if [[ -n "$SSID_CANDIDATE" && "$SSID_CANDIDATE" != *"not associated"* && "$SSID_CANDIDATE" != "$OUTPUT" ]]; then
            CURRENT_SSID="$SSID_CANDIDATE"
        fi
    fi

    # Method 3: system_profiler (slowest fallback)
    if [[ -z "$CURRENT_SSID" ]]; then
        CURRENT_SSID=$(system_profiler SPAirPortDataType 2>/dev/null \
            | awk '/Current Network Information:/{getline; gsub(/^[ \t]+|:$/,""); print; exit}')
    fi
fi

if [[ -n "$CURRENT_SSID" ]]; then
    echo "  You are currently connected to: \"$CURRENT_SSID\""
    if ask "  Add as trusted? Protections will be relaxed on this network."; then
        "$INSTALL_PATH" trust 2>/dev/null || bash "$SCRIPT_DIR/macshield.sh" trust
        log "Current network added as trusted."
    else
        echo "  Skipped."
    fi
else
    echo "  Not connected to WiFi. Skipping."
fi
echo ""

# ---------------------------------------------------------------------------
# Step 4: Store personal hostname
# ---------------------------------------------------------------------------

CURRENT_HOSTNAME=$(scutil --get ComputerName 2>/dev/null || echo "")
GENERIC_HOSTNAME=$(system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/Model Name/{print $2}')

if [[ -n "$CURRENT_HOSTNAME" && "$CURRENT_HOSTNAME" != "$GENERIC_HOSTNAME" ]]; then
    echo "  Storing your personal hostname in Keychain for restoration on trusted networks."
    echo "  Current hostname: \"$CURRENT_HOSTNAME\""
    if ask "  Store this?"; then
        security add-generic-password \
            -s "com.macshield.hostname" \
            -a "personal" \
            -w "$CURRENT_HOSTNAME" \
            -U 2>/dev/null || true
        log "Hostname stored in Keychain."
    else
        echo "  Skipped."
    fi
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

echo ""
echo "=== Installation complete ==="
echo ""
[[ -f "$INSTALL_PATH" ]] && echo "  Installed: $INSTALL_PATH"
[[ -f "$DAEMON_PATH" ]] && echo "  Installed: $DAEMON_PATH"
echo ""
echo "  Run 'macshield --check' to see current status."
echo "  Run 'macshield trust' to trust the current network."
echo "  Run 'macshield --help' for all commands."
echo ""
