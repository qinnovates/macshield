#!/usr/bin/env bash
# macshield installer - explicit consent at every step
set -euo pipefail

# Harden PATH and umask
PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PATH
umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
INSTALL_PATH="/usr/local/bin/macshield"
PLIST_NAME="com.qinnovates.macshield.plist"
AGENT_DIR="$HOME/Library/LaunchAgents"
AGENT_PATH="$AGENT_DIR/$PLIST_NAME"
SUDOERS_PATH="/etc/sudoers.d/macshield"

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
echo "DISCLAIMER: macshield is provided as-is, without warranty of any kind."
echo "It modifies system settings including your firewall, computer name,"
echo "and network services. While all changes are reversible, you accept"
echo "full responsibility for running this software on your machine."
echo ""
echo "macshield is NOT a VPN, does NOT encrypt your traffic, and does NOT"
echo "make you anonymous. It reduces your local network footprint only."
echo "For full documentation, limitations, and what macshield does not do:"
echo "  https://github.com/qinnovates/macshield"
echo ""
echo "Review the source code before installing: cat $SCRIPT_DIR/macshield.sh"
echo ""
echo "This installer will:"
echo ""
echo "  1. Copy macshield.sh to $INSTALL_PATH"
echo "  2. Install a sudoers authorization so macshield can run privileged"
echo "     commands (stealth mode, hostname, NetBIOS) without a password"
echo "     prompt on every network change. No wildcards, exact commands only."
echo "  3. Install a LaunchAgent that triggers on network changes"
echo "     The agent runs as YOUR user, not root."
echo "  4. Optionally add your current network as trusted"
echo ""
echo "Each step requires your explicit approval."
echo ""

if ! ask "I understand and want to proceed with installation"; then
    echo "  Installation cancelled."
    exit 0
fi
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
# Step 2: Sudoers authorization (scoped, no wildcards)
# ---------------------------------------------------------------------------

echo "Step 2: Authorize privileged commands"
echo ""
echo "  macshield needs elevated privileges for 3 operations:"
echo "    - Stealth mode (socketfilterfw)"
echo "    - Hostname changes (scutil)"
echo "    - NetBIOS control (launchctl)"
echo ""
echo "  This installs a sudoers fragment at $SUDOERS_PATH"
echo "  granting NOPASSWD for ONLY these exact commands:"
echo ""
echo "    /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"
echo "    /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off"
echo "    /usr/sbin/scutil --set ComputerName *"
echo "    /usr/sbin/scutil --set LocalHostName *"
echo "    /usr/sbin/scutil --set HostName *"
echo "    /bin/launchctl bootout system/com.apple.netbiosd"
echo "    /bin/launchctl enable system/com.apple.netbiosd"
echo "    /bin/launchctl kickstart system/com.apple.netbiosd"
echo ""
echo "  You can review the file anytime: cat $SUDOERS_PATH"
echo "  You can revoke this anytime: sudo rm $SUDOERS_PATH"
echo ""
if ask "  Install sudoers authorization?"; then
    # Write sudoers fragment via a temp file with visudo validation
    SUDOERS_TMP=$(mktemp) || die "Failed to create temp file"
    trap 'rm -f "${SUDOERS_TMP:-}"' EXIT
    cat > "$SUDOERS_TMP" <<'SUDOERS'
# macshield - network-aware macOS security hardening
# Grants the admin group passwordless sudo for exact macshield commands only.
# Installed by macshield. Remove with: sudo rm /etc/sudoers.d/macshield

%admin ALL=(root) NOPASSWD: /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
%admin ALL=(root) NOPASSWD: /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off
%admin ALL=(root) NOPASSWD: /usr/sbin/scutil --set ComputerName *
%admin ALL=(root) NOPASSWD: /usr/sbin/scutil --set LocalHostName *
%admin ALL=(root) NOPASSWD: /usr/sbin/scutil --set HostName *
%admin ALL=(root) NOPASSWD: /bin/launchctl bootout system/com.apple.netbiosd
%admin ALL=(root) NOPASSWD: /bin/launchctl enable system/com.apple.netbiosd
%admin ALL=(root) NOPASSWD: /bin/launchctl kickstart system/com.apple.netbiosd
SUDOERS

    # Validate syntax before installing
    if sudo visudo -c -f "$SUDOERS_TMP" 2>/dev/null; then
        sudo cp "$SUDOERS_TMP" "$SUDOERS_PATH"
        sudo chown root:wheel "$SUDOERS_PATH"
        sudo chmod 440 "$SUDOERS_PATH"
        log "Sudoers authorization installed at $SUDOERS_PATH"
    else
        echo "  ERROR: Sudoers syntax validation failed. Skipping."
    fi
    rm -f "$SUDOERS_TMP"
else
    echo "  Skipped. macshield will prompt for your password on each network change."
fi
echo ""

# ---------------------------------------------------------------------------
# Step 3: LaunchAgent (runs as your user)
# ---------------------------------------------------------------------------

echo "Step 3: Install LaunchAgent"
echo "  This watches for WiFi network changes and triggers macshield automatically."
echo "  It runs as YOUR user (not root). It watches:"
echo "    /Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"
echo "    /Library/Preferences/SystemConfiguration/preferences.plist"
echo ""
echo "  The agent runs a pure bash script. You can audit every line:"
echo "    cat $INSTALL_PATH"
echo ""
if ask "  Install this?"; then
    # Unload first if already loaded (ignore errors)
    launchctl bootout "gui/$(id -u)/com.qinnovates.macshield" 2>/dev/null || true

    # Remove old LaunchDaemon if present (v0.2.0 upgrade path)
    if [[ -f "/Library/LaunchDaemons/$PLIST_NAME" ]]; then
        log "Removing old LaunchDaemon from v0.2.0..."
        sudo launchctl bootout system/"$PLIST_NAME" 2>/dev/null || true
        sudo rm -f "/Library/LaunchDaemons/$PLIST_NAME"
    fi

    mkdir -p "$AGENT_DIR"
    cp "$SCRIPT_DIR/$PLIST_NAME" "$AGENT_PATH"

    launchctl bootstrap "gui/$(id -u)" "$AGENT_PATH"
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
    echo "  WARNING: macshield will CHANGE YOUR COMPUTER NAME on untrusted networks."
    echo ""
    echo "  On untrusted WiFi, your hostname will be set to a generic name"
    echo "  (e.g., \"MacBook Pro\") to prevent identity leaking over the local network."
    echo "  This affects how your Mac appears in:"
    echo "    - AirDrop and Bluetooth"
    echo "    - Terminal prompt (if it shows hostname)"
    echo "    - System Preferences > Sharing"
    echo "    - Any app that reads your computer name"
    echo ""
    echo "  Your current name (\"$CURRENT_HOSTNAME\") will be saved in Keychain"
    echo "  and automatically restored when you connect to a trusted network."
    echo ""
    if ask "  Accept hostname changes and store \"$CURRENT_HOSTNAME\" for restoration?"; then
        security add-generic-password \
            -s "com.macshield.hostname" \
            -a "personal" \
            -w "$CURRENT_HOSTNAME" \
            -U 2>/dev/null || true
        log "Hostname stored in Keychain."
    else
        echo "  Skipped. macshield will still change your hostname on untrusted"
        echo "  networks, but it will not be able to restore your personal name."
    fi
fi

# ---------------------------------------------------------------------------
# Step 6: DNS configuration (optional)
# ---------------------------------------------------------------------------

echo "Step 6: Configure secure DNS? (optional)"
echo ""
echo "  Your DNS provider can see every domain you visit. Your ISP's default"
echo "  DNS logs your browsing history and may sell it to advertisers."
echo ""
echo "  Changing DNS is one of the simplest privacy improvements you can make."
echo "  macshield can set your DNS on the WiFi interface to a privacy-focused"
echo "  provider. This only affects DNS lookups, not your traffic content."
echo ""
echo "  Options:"
echo "    1) Cloudflare  (1.1.1.1, 1.0.0.1)   - Fast, privacy-first, no logging"
echo "    2) Quad9       (9.9.9.9, 149.112.112.112) - Blocks malware domains, Swiss privacy law"
echo "    3) Mullvad     (100.64.0.7)           - No logging, runs by a VPN company with strong privacy record"
echo "    4) Keep current DNS (no change)"
echo ""
echo "  Note: No DNS provider today offers post-quantum encryption for DNS"
echo "  queries. DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) use classical"
echo "  TLS, which is sufficient for now. PQ DNS is not yet standardized."
echo ""

DNS_CHOICE=""
printf "  Choose [1/2/3/4]: "
read -r DNS_CHOICE

case "$DNS_CHOICE" in
    1)
        echo ""
        echo "  Setting DNS to Cloudflare (1.1.1.1, 1.0.0.1)"
        echo "  Running: networksetup -setdnsservers Wi-Fi 1.1.1.1 1.0.0.1"
        echo ""
        if ask "  Proceed?"; then
            networksetup -setdnsservers Wi-Fi 1.1.1.1 1.0.0.1
            log "DNS set to Cloudflare."
        else
            echo "  Skipped."
        fi
        ;;
    2)
        echo ""
        echo "  Setting DNS to Quad9 (9.9.9.9, 149.112.112.112)"
        echo "  Running: networksetup -setdnsservers Wi-Fi 9.9.9.9 149.112.112.112"
        echo "  Quad9 blocks known malware domains at the DNS level."
        echo ""
        if ask "  Proceed?"; then
            networksetup -setdnsservers Wi-Fi 9.9.9.9 149.112.112.112
            log "DNS set to Quad9."
        else
            echo "  Skipped."
        fi
        ;;
    3)
        echo ""
        echo "  Setting DNS to Mullvad (100.64.0.7)"
        echo "  Running: networksetup -setdnsservers Wi-Fi 100.64.0.7"
        echo "  Mullvad DNS only works if you are connected to Mullvad VPN."
        echo ""
        if ask "  Proceed?"; then
            networksetup -setdnsservers Wi-Fi 100.64.0.7
            log "DNS set to Mullvad."
        else
            echo "  Skipped."
        fi
        ;;
    *)
        echo "  Keeping current DNS. No changes."
        ;;
esac
echo ""

# ---------------------------------------------------------------------------
# Step 7: SOCKS proxy (optional)
# ---------------------------------------------------------------------------

echo "Step 7: Configure SOCKS proxy? (optional)"
echo ""
echo "  A SOCKS proxy routes your traffic through a secure tunnel."
echo "  This is useful if you run a local proxy (e.g., ssh -D, Tor,"
echo "  or a VPN with SOCKS support)."
echo ""
echo "  macshield can configure macOS to use a SOCKS proxy on your"
echo "  WiFi interface. This setting persists until you disable it."
echo ""
echo "  Options:"
echo "    1) localhost:9050  (Tor default)    - Routes traffic through Tor network"
echo "    2) localhost:1080  (SSH tunnel)     - Common for 'ssh -D 1080' tunnels"
echo "    3) Custom          (you specify)    - Enter your own host:port"
echo "    4) Skip            (no proxy)"
echo ""
echo "  Note: SOCKS proxies encrypt the tunnel, not the traffic inside it."
echo "  Use HTTPS sites for end-to-end encryption. No SOCKS implementation"
echo "  today uses post-quantum cryptography. PQ support in TLS is emerging"
echo "  (Chrome and Cloudflare have experimental PQ key exchange) but not"
echo "  yet available in SOCKS proxies."
echo ""

PROXY_CHOICE=""
printf "  Choose [1/2/3/4]: "
read -r PROXY_CHOICE

case "$PROXY_CHOICE" in
    1)
        echo ""
        echo "  Setting SOCKS proxy to localhost:9050 (Tor)"
        echo "  Running: networksetup -setsocksfirewallproxy Wi-Fi localhost 9050"
        echo ""
        echo "  Make sure Tor is running (e.g., 'brew install tor && tor')."
        echo ""
        if ask "  Proceed?"; then
            networksetup -setsocksfirewallproxy Wi-Fi localhost 9050
            networksetup -setsocksfirewallproxystate Wi-Fi on
            log "SOCKS proxy set to localhost:9050 (Tor)."
        else
            echo "  Skipped."
        fi
        ;;
    2)
        echo ""
        echo "  Setting SOCKS proxy to localhost:1080 (SSH tunnel)"
        echo "  Running: networksetup -setsocksfirewallproxy Wi-Fi localhost 1080"
        echo ""
        echo "  Make sure your SSH tunnel is running:"
        echo "    ssh -D 1080 -N user@your-server.com"
        echo ""
        if ask "  Proceed?"; then
            networksetup -setsocksfirewallproxy Wi-Fi localhost 1080
            networksetup -setsocksfirewallproxystate Wi-Fi on
            log "SOCKS proxy set to localhost:1080 (SSH tunnel)."
        else
            echo "  Skipped."
        fi
        ;;
    3)
        echo ""
        printf "  Enter SOCKS proxy host (e.g., localhost): "
        read -r PROXY_HOST
        printf "  Enter SOCKS proxy port (e.g., 1080): "
        read -r PROXY_PORT

        # Validate inputs
        if [[ ! "$PROXY_HOST" =~ ^[a-zA-Z0-9._-]+$ ]]; then
            echo "  ERROR: Invalid hostname. Use only letters, numbers, dots, hyphens."
            echo "  Skipping proxy setup."
        elif [[ ! "$PROXY_PORT" =~ ^[0-9]+$ ]] || (( PROXY_PORT < 1 || PROXY_PORT > 65535 )); then
            echo "  ERROR: Port must be a number between 1 and 65535."
            echo "  Skipping proxy setup."
        else
            echo ""
            echo "  Setting SOCKS proxy to $PROXY_HOST:$PROXY_PORT"
            echo "  Running: networksetup -setsocksfirewallproxy Wi-Fi $PROXY_HOST $PROXY_PORT"
            echo ""
            if ask "  Proceed?"; then
                networksetup -setsocksfirewallproxy Wi-Fi "$PROXY_HOST" "$PROXY_PORT"
                networksetup -setsocksfirewallproxystate Wi-Fi on
                log "SOCKS proxy set to $PROXY_HOST:$PROXY_PORT."
            else
                echo "  Skipped."
            fi
        fi
        ;;
    *)
        echo "  Skipping proxy setup. No changes."
        ;;
esac
echo ""

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

echo ""
echo "=== Installation complete ==="
echo ""
[[ -f "$INSTALL_PATH" ]] && echo "  Installed: $INSTALL_PATH"
[[ -f "$AGENT_PATH" ]] && echo "  Installed: $AGENT_PATH (LaunchAgent, runs as your user)"
[[ -f "$SUDOERS_PATH" ]] && echo "  Installed: $SUDOERS_PATH (revoke with: sudo rm $SUDOERS_PATH)"
echo ""
echo "  Run 'macshield --check' to see current status."
echo "  Run 'macshield trust' to trust the current network."
echo "  Run 'macshield --help' for all commands."
echo ""
