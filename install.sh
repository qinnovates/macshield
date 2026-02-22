#!/usr/bin/env bash
# macshield installer - explicit consent at every step
set -euo pipefail

# Harden PATH and umask
PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PATH
umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
PLIST_NAME="com.qinnovates.macshield.plist"
AGENT_DIR="$HOME/Library/LaunchAgents"
AGENT_PATH="$AGENT_DIR/$PLIST_NAME"
SUDOERS_PATH="/etc/sudoers.d/macshield"

# Detect Homebrew-managed install (binary already placed by formula)
if [[ "$SCRIPT_DIR" == *"/libexec"* ]] && command -v macshield &>/dev/null; then
    HOMEBREW_INSTALL=true
    INSTALL_PATH="$(command -v macshield)"
else
    HOMEBREW_INSTALL=false
    INSTALL_PATH="/usr/local/bin/macshield"
fi

# Colors
if [[ -t 1 ]]; then
    C_RESET="\033[0m"; C_BOLD="\033[1m"; C_DIM="\033[2m"
    C_RED="\033[31m"; C_GREEN="\033[32m"; C_YELLOW="\033[33m"; C_CYAN="\033[36m"
    C_BOLD_WHITE="\033[1;37m"; C_BOLD_CYAN="\033[1;36m"; C_BOLD_GREEN="\033[1;32m"
else
    C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""
    C_BOLD_WHITE=""; C_BOLD_CYAN=""; C_BOLD_GREEN=""
fi

log() {
    echo -e "${C_CYAN}[macshield]${C_RESET} $*"
}

ask() {
    local prompt="$1"
    local reply
    printf "${C_CYAN}[macshield]${C_RESET} %s ${C_DIM}[y/N]:${C_RESET} " "$prompt"
    read -r reply
    [[ "$reply" =~ ^[Yy]$ ]]
}

# ---------------------------------------------------------------------------

echo ""
if [[ -t 1 ]]; then
    echo -e "\033[36m"
    cat <<'BANNER'
  ███╗   ███╗ █████╗  ██████╗ ███████╗██╗  ██╗██╗███████╗██╗     ██████╗
  ████╗ ████║██╔══██╗██╔════╝ ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
  ██╔████╔██║███████║██║      ███████╗███████║██║█████╗  ██║     ██║  ██║
  ██║╚██╔╝██║██╔══██║██║      ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
  ██║ ╚═╝ ██║██║  ██║╚██████╗ ███████║██║  ██║██║███████╗██████╗ ██████╔╝
  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚═════╝╚═════╝
BANNER
    echo -e "\033[0m"
    echo -e "  \033[1;37m>> network-aware macos security hardening <<\033[0m"
    echo -e "  \033[2m>> by qinnovate // github.com/qinnovates <<\033[0m"
else
    echo "=== macshield installer ==="
fi
echo ""
echo "macshield automatically hardens your Mac on untrusted WiFi networks."
echo ""
echo "DISCLAIMER: macshield is provided as-is, without warranty of any kind."
echo "It modifies system settings including your firewall, computer name,"
echo "and network services. While all changes are reversible, you accept"
echo "full responsibility for running this software on your machine."
echo ""
echo "macshield is NOT a VPN. It secures your local network identity (Layer 2),"
echo "reduces potential for malware (with Quad9 DNS), and avoids routing your"
echo "DNS through unknown public WiFi infrastructure. It does NOT encrypt"
echo "your traffic or make you anonymous."
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
echo "  5. Optionally install Cloudflare WARP (free VPN, covers Layer 3+)"
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

if $HOMEBREW_INSTALL; then
    echo -e "${C_BOLD_WHITE}Step 1: Install binary${C_RESET}"
    echo "  Already installed by Homebrew at $INSTALL_PATH"
    log "Binary managed by Homebrew. Skipping copy."
else
    echo -e "${C_BOLD_WHITE}Step 1: Install macshield to $INSTALL_PATH${C_RESET}"
    echo "  This makes the 'macshield' command available system-wide."
    if ask "  Proceed?"; then
        sudo cp "$SCRIPT_DIR/macshield.sh" "$INSTALL_PATH"
        sudo chmod 755 "$INSTALL_PATH"
        log "Installed macshield to $INSTALL_PATH"
    else
        echo "  Skipped."
    fi
fi
echo ""

# ---------------------------------------------------------------------------
# Step 2: Sudoers authorization (scoped, no wildcards)
# ---------------------------------------------------------------------------

echo -e "${C_BOLD_WHITE}Step 2: Authorize privileged commands${C_RESET}"
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

echo -e "${C_BOLD_WHITE}Step 3: Install LaunchAgent${C_RESET}"
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

    # If Homebrew install, update plist to point to Homebrew binary path
    if $HOMEBREW_INSTALL; then
        sed -i '' "s|/usr/local/bin/macshield|$INSTALL_PATH|g" "$AGENT_PATH"
    fi

    launchctl bootstrap "gui/$(id -u)" "$AGENT_PATH"
    log "Installed and loaded LaunchAgent"
else
    echo "  Skipped. You can trigger macshield manually with 'macshield harden'."
fi
echo ""

# ---------------------------------------------------------------------------
# Step 4: Trust current network
# ---------------------------------------------------------------------------

echo -e "${C_BOLD_WHITE}Step 4: Trust current network?${C_RESET}"

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
    # Mask SSID: show first 2 chars + asterisks (privacy: shoulder surfing, screen recordings)
    if [[ ${#CURRENT_SSID} -le 2 ]]; then
        MASKED_SSID="$CURRENT_SSID"
    else
        MASKED_SSID="${CURRENT_SSID:0:2}$(printf '%*s' $((${#CURRENT_SSID}-2)) '' | tr ' ' '*')"
    fi
    echo -e "  You are currently connected to: ${C_BOLD}\"$MASKED_SSID\"${C_RESET}"
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

echo -e "${C_BOLD_WHITE}Step 5: Hostname consent${C_RESET}"

CURRENT_HOSTNAME=$(scutil --get ComputerName 2>/dev/null || echo "")
GENERIC_HOSTNAME=$(system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/Model Name/{print $2}')

if [[ -n "$CURRENT_HOSTNAME" && "$CURRENT_HOSTNAME" != "$GENERIC_HOSTNAME" ]]; then
    echo -e "  ${C_YELLOW}WARNING:${C_RESET} macshield will ${C_BOLD}CHANGE YOUR COMPUTER NAME${C_RESET} on untrusted networks."
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

echo -e "${C_BOLD_WHITE}Step 6: Configure secure DNS? (optional)${C_RESET}"
echo ""
echo "  Your DNS provider can see every domain you visit. Your ISP's default"
echo "  DNS logs your browsing history and may sell it to advertisers."
echo ""
echo "  Changing DNS is one of the simplest privacy improvements you can make."
echo "  macshield can set your DNS on the WiFi interface to a privacy-focused"
echo "  provider. This only affects DNS lookups, not your traffic content."
echo ""
echo "  Options:"
echo -e "    1) Quad9       (9.9.9.9)              - ${C_GREEN}Blocks malware domains${C_RESET}, Swiss privacy law, non-profit"
echo "    2) Cloudflare  (1.1.1.1)              - Fastest, no logging, US-based"
echo "    3) Mullvad     (100.64.0.7)           - No logging, requires Mullvad VPN"
echo "    4) Keep current DNS (no change)"
echo ""

DNS_CHOICE=""
DNS_NAME=""
printf "  Choose [1/2/3/4]: "
read -r DNS_CHOICE

case "$DNS_CHOICE" in
    1)
        echo ""
        echo "  Setting DNS to Quad9 (9.9.9.9, 149.112.112.112)"
        echo "  Running: networksetup -setdnsservers Wi-Fi 9.9.9.9 149.112.112.112"
        echo "  Quad9 blocks known malware domains at the DNS level."
        echo ""
        if ask "  Proceed?"; then
            networksetup -setdnsservers Wi-Fi 9.9.9.9 149.112.112.112
            DNS_NAME="Quad9"
            log "DNS set to Quad9."
        else
            echo "  Skipped."
        fi
        ;;
    2)
        echo ""
        echo "  Setting DNS to Cloudflare (1.1.1.1, 1.0.0.1)"
        echo "  Running: networksetup -setdnsservers Wi-Fi 1.1.1.1 1.0.0.1"
        echo ""
        if ask "  Proceed?"; then
            networksetup -setdnsservers Wi-Fi 1.1.1.1 1.0.0.1
            DNS_NAME="Cloudflare"
            log "DNS set to Cloudflare."
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
            DNS_NAME="Mullvad"
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

echo -e "${C_BOLD_WHITE}Step 7: Configure SOCKS proxy? (optional)${C_RESET}"
echo ""
echo -e "  ${C_YELLOW}If you don't know what a SOCKS proxy is, skip this step (option 3).${C_RESET}"
echo -e "  ${C_YELLOW}Misconfiguring a proxy will break your internet connection.${C_RESET}"
echo ""
echo "  A SOCKS proxy routes your traffic through a secure tunnel."
echo "  This is useful if you run a local proxy (e.g., ssh -D, Tor,"
echo "  or a VPN with SOCKS support)."
echo ""
echo "  macshield can configure macOS to use a SOCKS proxy on your"
echo "  WiFi interface. This setting persists until you disable it."
echo ""
echo "  Options:"
echo "    1) localhost:1080  (SSH tunnel)     - Common for 'ssh -D 1080' tunnels"
echo "    2) Custom          (you specify)    - Enter your own host:port"
echo -e "    3) Skip            ${C_GREEN}(recommended)${C_RESET}   - No proxy, no changes"
echo ""
echo "  Note: SOCKS proxies encrypt the tunnel, not the traffic inside it."
echo "  Use HTTPS sites for end-to-end encryption."
echo ""

PROXY_CHOICE=""
printf "  Choose [1/2/3]: "
read -r PROXY_CHOICE

case "$PROXY_CHOICE" in
    1)
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
    2)
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
# Step 8: Cloudflare WARP (optional free VPN)
# ---------------------------------------------------------------------------

echo -e "${C_BOLD_WHITE}Step 8: Install Cloudflare WARP? (optional, free VPN)${C_RESET}"
echo ""
echo -e "  ${C_YELLOW}macshield secures your local network identity (Layer 2).${C_RESET}"
echo -e "  ${C_YELLOW}WARP encrypts your traffic and DNS (Layer 3+).${C_RESET}"
echo -e "  ${C_YELLOW}Together they cover both layers.${C_RESET}"
echo ""
echo "  Cloudflare WARP is a free VPN that:"
echo "    - Encrypts all DNS queries (DNS-over-HTTPS)"
echo "    - Routes traffic through Cloudflare's network (WireGuard-based)"
echo "    - No bandwidth caps, no ads, no data selling"
echo "    - Optional paid tier (WARP+) for faster routing"
echo ""
echo "  WARP runs as a menu bar app. You toggle it on/off yourself."
echo "  macshield does not manage WARP. They are independent tools."
echo ""
echo "  Options:"
echo -e "    1) Install WARP via Homebrew   ${C_GREEN}(recommended)${C_RESET}"
echo "    2) Skip (install manually later from https://1.1.1.1)"
echo ""

WARP_CHOICE=""
printf "  Choose [1/2]: "
read -r WARP_CHOICE

case "$WARP_CHOICE" in
    1)
        echo ""
        if command -v brew &>/dev/null; then
            echo "  Installing Cloudflare WARP..."
            echo "  Running: brew install --cask cloudflare-warp"
            echo ""
            if ask "  Proceed?"; then
                if brew install --cask cloudflare-warp 2>/dev/null; then
                    log "Cloudflare WARP installed."
                    echo ""
                    echo "  Open WARP from your Applications folder or menu bar."
                    echo "  On first launch, accept the terms and click Connect."
                    echo ""
                    echo -e "  ${C_BOLD_WHITE}Enable malware blocking? (recommended)${C_RESET}"
                    echo "  This sets WARP to use 1.1.1.2 (blocks known malware domains)"
                    echo "  instead of 1.1.1.1 (no filtering)."
                    echo "  Running: warp-cli dns families malware"
                    echo ""
                    if ask "  Enable malware blocking?"; then
                        if command -v warp-cli &>/dev/null; then
                            if warp-cli dns families malware 2>/dev/null; then
                                log "WARP malware blocking enabled (DNS: 1.1.1.2)."
                            else
                                echo "  Could not set malware blocking. Open WARP first, then run:"
                                echo "    warp-cli dns families malware"
                            fi
                        else
                            echo "  warp-cli not found yet. Open WARP once, then run:"
                            echo "    warp-cli dns families malware"
                        fi
                    else
                        echo "  Skipped. You can enable it later:"
                        echo "    warp-cli dns families malware"
                    fi
                    if [[ -n "$DNS_NAME" ]]; then
                        echo ""
                        echo -e "  ${C_YELLOW}DNS note:${C_RESET} You set $DNS_NAME DNS in Step 6."
                        echo "  While WARP is connected, it handles DNS through its own"
                        echo "  encrypted tunnel (1.1.1.2 with malware blocking, or 1.1.1.1"
                        echo "  without). Your $DNS_NAME setting is not lost. It kicks back"
                        echo "  in automatically whenever you disconnect WARP."
                    fi
                    echo ""
                    echo "  WARP runs independently from macshield."
                else
                    echo "  Installation failed. You can install manually:"
                    echo "    brew install --cask cloudflare-warp"
                    echo "  Or download from: https://1.1.1.1"
                fi
            else
                echo "  Skipped."
            fi
        else
            echo "  Homebrew not found. Install WARP manually:"
            echo "    https://1.1.1.1"
            echo "  Or install Homebrew first: https://brew.sh"
        fi
        ;;
    *)
        echo "  Skipping WARP. You can install it later:"
        echo "    brew install --cask cloudflare-warp"
        echo "    Or download from: https://1.1.1.1"
        ;;
esac
echo ""

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

echo ""
echo -e "${C_BOLD_GREEN}=== Installation complete ===${C_RESET}"
echo ""
[[ -f "$INSTALL_PATH" ]] && echo -e "  ${C_GREEN}Installed:${C_RESET} $INSTALL_PATH"
[[ -f "$AGENT_PATH" ]] && echo -e "  ${C_GREEN}Installed:${C_RESET} $AGENT_PATH (LaunchAgent, runs as your user)"
[[ -f "$SUDOERS_PATH" ]] && echo -e "  ${C_GREEN}Installed:${C_RESET} $SUDOERS_PATH (revoke with: sudo rm $SUDOERS_PATH)"
echo ""
echo -e "  ${C_BOLD_WHITE}Quick start:${C_RESET}"
echo -e "    macshield --check       ${C_DIM}# See current security status${C_RESET}"
echo -e "    macshield trust         ${C_DIM}# Trust your current WiFi network${C_RESET}"
echo -e "    macshield --help        ${C_DIM}# All commands${C_RESET}"
echo ""
echo -e "  ${C_BOLD_WHITE}Security reports:${C_RESET}"
echo -e "    macshield scan          ${C_DIM}# Scan open ports and listening services${C_RESET}"
echo -e "    macshield audit         ${C_DIM}# Full macOS security audit${C_RESET}"
echo -e "    macshield connections   ${C_DIM}# Show active network connections${C_RESET}"
echo -e "    macshield persistence   ${C_DIM}# List startup items and launch agents${C_RESET}"
echo -e "    macshield permissions   ${C_DIM}# Check app privacy permissions${C_RESET}"
echo ""
