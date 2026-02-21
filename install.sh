#!/usr/bin/env bash
# macshield installer - explicit consent at every step
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_PATH="/usr/local/bin/macshield"
SUDOERS_PATH="/etc/sudoers.d/macshield"
PLIST_NAME="com.qinnovates.macshield.plist"
LAUNCHAGENT_DIR="$HOME/Library/LaunchAgents"
LAUNCHAGENT_PATH="$LAUNCHAGENT_DIR/$PLIST_NAME"

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
echo "  2. Install a sudoers fragment at $SUDOERS_PATH"
echo "     This grants passwordless sudo for ONLY:"
echo "       - Toggle firewall stealth mode"
echo "       - Set hostname (ComputerName, LocalHostName, HostName)"
echo "       - Start/stop NetBIOS daemon"
echo "  3. Install a LaunchAgent that triggers on network changes"
echo "  4. Optionally add your current network as trusted"
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
# Step 2: Sudoers fragment
# ---------------------------------------------------------------------------

SUDOERS_CONTENT='# Installed by macshield - network-aware security hardening
# Grants passwordless access to ONLY these specific commands:
Cmnd_Alias MACSHIELD_CMDS = \
    /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on, \
    /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off, \
    /usr/sbin/scutil --set ComputerName *, \
    /usr/sbin/scutil --set LocalHostName *, \
    /usr/sbin/scutil --set HostName *, \
    /bin/launchctl bootout system/com.apple.netbiosd, \
    /bin/launchctl enable system/com.apple.netbiosd, \
    /bin/launchctl kickstart system/com.apple.netbiosd

%admin ALL=(root) NOPASSWD: MACSHIELD_CMDS'

echo "Step 2: Install sudoers fragment"
echo "  This file grants passwordless sudo for 8 specific commands only."
echo "  The exact contents are:"
echo ""
echo "  ---"
echo "$SUDOERS_CONTENT" | sed 's/^/  /'
echo "  ---"
echo ""
if ask "  Install this?"; then
    # Write to temp file and validate before installing
    TEMP_SUDOERS=$(mktemp)
    echo "$SUDOERS_CONTENT" > "$TEMP_SUDOERS"
    chmod 440 "$TEMP_SUDOERS"

    # Validate syntax
    if sudo visudo -cf "$TEMP_SUDOERS" >/dev/null 2>&1; then
        sudo cp "$TEMP_SUDOERS" "$SUDOERS_PATH"
        sudo chmod 440 "$SUDOERS_PATH"
        sudo chown root:wheel "$SUDOERS_PATH"
        rm -f "$TEMP_SUDOERS"
        log "Installed sudoers fragment to $SUDOERS_PATH"
    else
        rm -f "$TEMP_SUDOERS"
        echo "  ERROR: Sudoers syntax validation failed. Not installing."
        echo "  This is a bug. Please report it at https://github.com/qinnovates/macshield/issues"
    fi
else
    echo "  Skipped. Note: macshield will prompt for password on each trigger."
fi
echo ""

# ---------------------------------------------------------------------------
# Step 3: LaunchAgent
# ---------------------------------------------------------------------------

echo "Step 3: Install LaunchAgent"
echo "  This watches for WiFi network changes and triggers macshield automatically."
echo "  It runs as YOUR user (not root). It watches:"
echo "    /Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"
echo "    /Library/Preferences/SystemConfiguration/preferences.plist"
if ask "  Install this?"; then
    mkdir -p "$LAUNCHAGENT_DIR"
    cp "$SCRIPT_DIR/$PLIST_NAME" "$LAUNCHAGENT_PATH"

    # Unload first if already loaded (ignore errors)
    launchctl bootout "gui/$(id -u)/$PLIST_NAME" 2>/dev/null || true

    launchctl bootstrap "gui/$(id -u)" "$LAUNCHAGENT_PATH"
    log "Installed and loaded LaunchAgent"
else
    echo "  Skipped. You can trigger macshield manually with 'macshield harden'."
fi
echo ""

# ---------------------------------------------------------------------------
# Step 4: Trust current network
# ---------------------------------------------------------------------------

echo "Step 4: Trust current network?"

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
# Step 5: Store personal hostname
# ---------------------------------------------------------------------------

CURRENT_HOSTNAME=$(scutil --get ComputerName 2>/dev/null || echo "")
GENERIC_HOSTNAME=$(system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/Model Name/{print $2}')

if [[ -n "$CURRENT_HOSTNAME" && "$CURRENT_HOSTNAME" != "$GENERIC_HOSTNAME" ]]; then
    echo "  Storing your personal hostname in Keychain for restoration on trusted networks."
    echo "  Current hostname: \"$CURRENT_HOSTNAME\""
    if ask "  Store this?"; then
        if command -v macshield >/dev/null 2>&1; then
            # Use the keychain function from the installed script
            security add-generic-password \
                -s "com.macshield.hostname" \
                -a "personal" \
                -w "$CURRENT_HOSTNAME" \
                -U 2>/dev/null || true
        fi
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
[[ -f "$SUDOERS_PATH" ]] && echo "  Installed: $SUDOERS_PATH"
[[ -f "$LAUNCHAGENT_PATH" ]] && echo "  Installed: $LAUNCHAGENT_PATH"
echo ""
echo "  Run 'macshield --check' to see current status."
echo "  Run 'macshield trust' to trust the current network."
echo "  Run 'macshield --help' for all commands."
echo ""
