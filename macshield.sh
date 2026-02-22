#!/usr/bin/env bash
# macshield - Network-aware macOS security hardening
# https://github.com/qinnovates/macshield
# License: Apache 2.0

set -euo pipefail

# Harden PATH to prevent command hijacking
PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PATH

# Restrict file creation permissions (owner-only by default)
umask 077

VERSION="0.4.1"
KEYCHAIN_SERVICE="com.macshield.trusted"
KEYCHAIN_HOSTNAME="com.macshield.hostname"
STATE_FILE="/tmp/macshield.state"
LOCK_FILE="/tmp/macshield.lock"
SCAN_REPORT="/tmp/macshield-port-report.txt"
AUDIT_REPORT="/tmp/macshield-audit-report.txt"
SETTLE_DELAY=2

# ---------------------------------------------------------------------------
# Symlink-safe file writes (defense against /tmp symlink attacks)
# ---------------------------------------------------------------------------

safe_write() {
    # Write to a path only if it is not a symlink. Prevents a local attacker
    # from planting a symlink at a predictable /tmp path to overwrite
    # arbitrary files.
    local path="$1"
    local content="$2"
    if [[ -L "$path" ]]; then
        die "Refusing to write: $path is a symlink (possible attack)"
    fi
    echo "$content" > "$path"
}

safe_write_single() {
    # Like safe_write but for single-line content (e.g., state file)
    local path="$1"
    local content="$2"
    if [[ -L "$path" ]]; then
        die "Refusing to write: $path is a symlink (possible attack)"
    fi
    printf '%s' "$content" > "$path"
}

# ---------------------------------------------------------------------------
# Self-integrity check (detect tampering of the macshield binary)
# ---------------------------------------------------------------------------

verify_integrity() {
    local expected actual script_path
    script_path="$(command -v macshield 2>/dev/null || echo "$0")"
    expected=$(security find-generic-password \
        -s "com.macshield.integrity" \
        -a "sha256" \
        -w 2>/dev/null) || return 0  # No hash stored = skip (first run / pre-upgrade)
    actual=$(shasum -a 256 "$script_path" | awk '{print $1}')
    if [[ "$expected" != "$actual" ]]; then
        echo ""
        echo -e "${C_RED}[INTEGRITY FAILURE]${C_RESET} macshield has been modified since installation."
        echo ""
        echo "  Expected SHA-256: $expected"
        echo "  Actual SHA-256:   $actual"
        echo "  Script path:      $script_path"
        echo ""
        echo "  This could mean:"
        echo "    - Someone or something modified the macshield binary"
        echo "    - You updated macshield without re-running setup"
        echo ""
        echo "  To fix: re-install macshield to store a new integrity hash."
        echo "    brew reinstall macshield   # Homebrew"
        echo "    ./install.sh              # Manual"
        echo ""
        echo "  macshield will NOT run until integrity is verified."
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Cleanup on exit (release locks, kill timer processes)
# ---------------------------------------------------------------------------

cleanup() {
    # Release flock file descriptor if open
    exec 200>&- 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Colors (disabled if not a terminal)
# ---------------------------------------------------------------------------

if [[ -t 1 ]]; then
    C_RESET="\033[0m"
    C_BOLD="\033[1m"
    C_DIM="\033[2m"
    C_RED="\033[31m"
    C_GREEN="\033[32m"
    C_YELLOW="\033[33m"
    C_BLUE="\033[34m"
    C_CYAN="\033[36m"
    C_WHITE="\033[37m"
    C_BOLD_CYAN="\033[1;36m"
    C_BOLD_GREEN="\033[1;32m"
    C_BOLD_RED="\033[1;31m"
    C_BOLD_YELLOW="\033[1;33m"
    C_BOLD_WHITE="\033[1;37m"
else
    C_RESET="" C_BOLD="" C_DIM="" C_RED="" C_GREEN="" C_YELLOW=""
    C_BLUE="" C_CYAN="" C_WHITE="" C_BOLD_CYAN="" C_BOLD_GREEN=""
    C_BOLD_RED="" C_BOLD_YELLOW="" C_BOLD_WHITE=""
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() {
    echo -e "${C_CYAN}[macshield]${C_RESET} $*"
}

log_header() {
    echo -e "${C_BOLD_CYAN}[macshield]${C_RESET} ${C_BOLD_WHITE}$*${C_RESET}"
}

log_success() {
    echo -e "${C_CYAN}[macshield]${C_RESET} ${C_GREEN}$*${C_RESET}"
}

log_warn() {
    echo -e "${C_CYAN}[macshield]${C_RESET} ${C_YELLOW}$*${C_RESET}"
}

log_error() {
    echo -e "${C_CYAN}[macshield]${C_RESET} ${C_RED}$*${C_RESET}"
}

log_dim() {
    echo -e "${C_CYAN}[macshield]${C_RESET} ${C_DIM}$*${C_RESET}"
}

die() {
    echo -e "${C_BOLD_RED}[macshield] ERROR:${C_RESET} ${C_RED}$*${C_RESET}" >&2
    exit 1
}

ask() {
    local prompt="$1"
    local reply
    printf "${C_CYAN}[macshield]${C_RESET} %s ${C_DIM}[y/N]:${C_RESET} " "$prompt"
    read -r reply
    [[ "$reply" =~ ^[Yy]$ ]]
}

ask_default_yes() {
    local prompt="$1"
    local reply
    printf "${C_CYAN}[macshield]${C_RESET} %s ${C_DIM}[Y/n]:${C_RESET} " "$prompt"
    read -r reply
    [[ ! "$reply" =~ ^[Nn]$ ]]
}

require_macos() {
    [[ "$(uname)" == "Darwin" ]] || die "macshield only runs on macOS"
}

# ---------------------------------------------------------------------------
# Hardware / network detection
# ---------------------------------------------------------------------------

get_wifi_interface() {
    local iface
    iface=$(networksetup -listallhardwareports | awk '/Wi-Fi|AirPort/{getline; print $2}')
    echo "${iface:-}"
}

get_current_ssid() {
    local iface ssid

    iface=$(get_wifi_interface)
    [[ -z "$iface" ]] && return 1

    # Method 1: ipconfig getsummary (most reliable on modern macOS)
    ssid=$(ipconfig getsummary "$iface" 2>/dev/null | awk -F' : ' '/SSID/{print $2; exit}')
    if [[ -n "$ssid" ]]; then
        echo "$ssid"
        return 0
    fi

    # Method 2: networksetup (legacy, unreliable on some macOS versions)
    local output
    output=$(networksetup -getairportnetwork "$iface" 2>/dev/null) || true
    ssid="${output#*: }"
    if [[ -n "$ssid" && "$ssid" != *"not associated"* && "$ssid" != "$output" ]]; then
        echo "$ssid"
        return 0
    fi

    # Method 3: system_profiler (slowest, but always works)
    ssid=$(system_profiler SPAirPortDataType 2>/dev/null \
        | awk '/Current Network Information:/{getline; gsub(/^[ \t]+|:$/,""); print; exit}')
    if [[ -n "$ssid" ]]; then
        echo "$ssid"
        return 0
    fi

    return 1
}

get_hardware_uuid() {
    ioreg -d2 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'
}

get_generic_hostname() {
    local model
    model=$(system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/Model Name/{print $2}')
    [[ -z "$model" ]] && model="Mac"
    # Convert spaces to hyphens for hostname format
    echo "${model// /-}"
}

get_generic_display_name() {
    local model
    model=$(system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/Model Name/{print $2}')
    [[ -z "$model" ]] && model="Mac"
    echo "$model"
}

# ---------------------------------------------------------------------------
# HMAC computation
# ---------------------------------------------------------------------------

compute_hmac() {
    local ssid="$1"
    local uuid
    uuid=$(get_hardware_uuid)
    # HMAC-SHA256 with hardware UUID as key
    echo -n "$ssid" | openssl dgst -sha256 -hmac "$uuid" -hex 2>/dev/null | awk '{print $NF}'
}

# ---------------------------------------------------------------------------
# Keychain operations
# ---------------------------------------------------------------------------

keychain_store_trusted() {
    local hash="$1"
    # Store hash as account name under our service
    security add-generic-password \
        -s "$KEYCHAIN_SERVICE" \
        -a "$hash" \
        -w "trusted" \
        -U 2>/dev/null || true
}

keychain_remove_trusted() {
    local hash="$1"
    security delete-generic-password \
        -s "$KEYCHAIN_SERVICE" \
        -a "$hash" 2>/dev/null || true
}

keychain_is_trusted() {
    local hash="$1"
    security find-generic-password \
        -s "$KEYCHAIN_SERVICE" \
        -a "$hash" 2>/dev/null >/dev/null
}

keychain_store_hostname() {
    local hostname="$1"
    security add-generic-password \
        -s "$KEYCHAIN_HOSTNAME" \
        -a "personal" \
        -w "$hostname" \
        -U 2>/dev/null || true
}

keychain_get_hostname() {
    security find-generic-password \
        -s "$KEYCHAIN_HOSTNAME" \
        -a "personal" \
        -w 2>/dev/null || echo ""
}

keychain_clear_all() {
    # Delete all trusted network entries
    while security delete-generic-password -s "$KEYCHAIN_SERVICE" 2>/dev/null; do
        true
    done
    # Delete stored hostname
    security delete-generic-password -s "$KEYCHAIN_HOSTNAME" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# State tracking (ephemeral, /tmp)
# ---------------------------------------------------------------------------

get_state() {
    [[ -f "$STATE_FILE" ]] && cat "$STATE_FILE" || echo "unknown"
}

set_state() {
    safe_write_single "$STATE_FILE" "$1"
}

# ---------------------------------------------------------------------------
# Privilege elevation
# ---------------------------------------------------------------------------

# Run a command with sudo. When triggered by the LaunchAgent, the sudoers
# fragment grants NOPASSWD for the exact commands macshield needs. When run
# manually, the user gets the standard macOS password prompt.
run_privileged() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

# ---------------------------------------------------------------------------
# Protection actions
# ---------------------------------------------------------------------------

do_harden() {
    local current_state
    current_state=$(get_state)

    if [[ "$current_state" == "hardened" ]]; then
        log "Already hardened. No changes needed."
        return 0
    fi

    log ""
    log_header "Applying protections:"

    # 1. Stealth mode
    log "  ${C_BOLD}[1/3]${C_RESET} Enabling stealth mode (blocks ICMP pings and port scans)"
    log_dim "        Running: socketfilterfw --setstealthmode on"
    run_privileged /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on >/dev/null 2>&1
    log_success "        Done."

    # 2. Generic hostname
    local generic_display generic_host
    generic_display=$(get_generic_display_name)
    generic_host=$(get_generic_hostname)

    # Save current hostname if we haven't already
    local stored
    stored=$(keychain_get_hostname)
    if [[ -z "$stored" ]]; then
        local current_name
        current_name=$(scutil --get ComputerName 2>/dev/null || echo "")
        if [[ -n "$current_name" && "$current_name" != "$generic_display" ]]; then
            keychain_store_hostname "$current_name"
        fi
    fi

    log "  ${C_BOLD}[2/3]${C_RESET} Changing hostname to generic \"${C_YELLOW}$generic_display${C_RESET}\" (hides identity)"
    log_dim "        Running: scutil --set ComputerName \"$generic_display\""
    run_privileged /usr/sbin/scutil --set ComputerName "$generic_display"
    log_dim "        Running: scutil --set LocalHostName \"$generic_host\""
    run_privileged /usr/sbin/scutil --set LocalHostName "$generic_host"
    log_dim "        Running: scutil --set HostName \"$generic_host\""
    run_privileged /usr/sbin/scutil --set HostName "$generic_host"
    log_success "        Done."

    # 3. NetBIOS
    log "  ${C_BOLD}[3/3]${C_RESET} Disabling NetBIOS (closes ports 137/138, stops name broadcast)"
    log_dim "        Running: launchctl bootout system/com.apple.netbiosd"
    if run_privileged /bin/launchctl bootout system/com.apple.netbiosd 2>/dev/null; then
        log_success "        Done."
    else
        log_warn "        Note: NetBIOS daemon was already stopped or is SIP-protected."
    fi

    set_state "hardened"
    log ""
    log_success "All protections active. Your Mac is hardened."
}

do_relax() {
    local current_state
    current_state=$(get_state)

    if [[ "$current_state" == "relaxed" ]]; then
        log "Already relaxed. No changes needed."
        return 0
    fi

    log ""
    log_header "Relaxing protections:"

    # 1. Stealth mode off
    log "  ${C_BOLD}[1/3]${C_RESET} Disabling stealth mode (AirDrop, Spotify Connect, etc. will work)"
    log_dim "        Running: socketfilterfw --setstealthmode off"
    run_privileged /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off >/dev/null 2>&1
    log_success "        Done."

    # 2. Restore personal hostname
    local personal_name
    personal_name=$(keychain_get_hostname)
    if [[ -n "$personal_name" ]]; then
        local personal_host="${personal_name// /-}"
        # Remove characters invalid for LocalHostName (only alphanumeric and hyphens)
        personal_host=$(echo "$personal_host" | sed "s/[^a-zA-Z0-9-]//g")

        log "  ${C_BOLD}[2/3]${C_RESET} Restoring personal hostname \"${C_GREEN}$personal_name${C_RESET}\""
        log_dim "        Running: scutil --set ComputerName \"$personal_name\""
        run_privileged /usr/sbin/scutil --set ComputerName "$personal_name"
        log_dim "        Running: scutil --set LocalHostName \"$personal_host\""
        run_privileged /usr/sbin/scutil --set LocalHostName "$personal_host"
        log_dim "        Running: scutil --set HostName \"$personal_host\""
        run_privileged /usr/sbin/scutil --set HostName "$personal_host"
        log_success "        Done."
    else
        log_dim "  [2/3] No personal hostname stored in Keychain. Skipping."
    fi

    # 3. NetBIOS back on
    log "  ${C_BOLD}[3/3]${C_RESET} Re-enabling NetBIOS"
    log_dim "        Running: launchctl enable system/com.apple.netbiosd"
    run_privileged /bin/launchctl enable system/com.apple.netbiosd 2>/dev/null || true
    log_dim "        Running: launchctl kickstart system/com.apple.netbiosd"
    if run_privileged /bin/launchctl kickstart system/com.apple.netbiosd 2>/dev/null; then
        log_success "        Done."
    else
        log_warn "        Note: NetBIOS daemon could not be started (may be SIP-protected)."
    fi

    set_state "relaxed"
    log ""
    log_success "Protections relaxed. Full network functionality restored."
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_trigger() {
    # Lock to prevent concurrent execution
    exec 200>"$LOCK_FILE"
    if ! flock -n 200; then
        log "Another instance is running. Exiting."
        exit 0
    fi

    # Settle delay: network state may not be final immediately
    sleep "$SETTLE_DELAY"

    log_header "Network change detected"

    local ssid
    if ! ssid=$(get_current_ssid); then
        log_warn "No WiFi connection detected. Defaulting to hardened mode."
        do_harden
        return
    fi

    log "Current SSID: ${C_DIM}(hidden from logs)${C_RESET}"
    log_dim "Computing network fingerprint..."

    local hash
    hash=$(compute_hmac "$ssid")

    log_dim "Checking trusted networks in Keychain..."

    if keychain_is_trusted "$hash"; then
        log_success "Result: TRUSTED network"
        do_relax
    else
        log_warn "Result: UNTRUSTED network"
        do_harden
    fi
}

cmd_check() {
    log_header "macshield v${VERSION}"
    log ""

    # Current state
    local state
    state=$(get_state)
    if [[ "$state" == "hardened" ]]; then
        log "Current state: ${C_BOLD_RED}$state${C_RESET}"
    elif [[ "$state" == "relaxed" ]]; then
        log "Current state: ${C_BOLD_GREEN}$state${C_RESET}"
    else
        log "Current state: ${C_YELLOW}$state${C_RESET}"
    fi

    # WiFi info
    local ssid
    if ssid=$(get_current_ssid); then
        log "WiFi connected: ${C_GREEN}yes${C_RESET}"

        local hash
        hash=$(compute_hmac "$ssid")
        if keychain_is_trusted "$hash"; then
            log "Network trust: ${C_BOLD_GREEN}TRUSTED${C_RESET}"
        else
            log "Network trust: ${C_BOLD_RED}UNTRUSTED${C_RESET}"
        fi
    else
        log "WiFi connected: ${C_YELLOW}no${C_RESET}"
    fi

    # Stealth mode
    local stealth
    stealth=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null || echo "unknown")
    if [[ "$stealth" == *"enabled"* ]]; then
        log "Stealth mode: ${C_GREEN}$stealth${C_RESET}"
    else
        log "Stealth mode: ${C_YELLOW}$stealth${C_RESET}"
    fi

    # Hostname
    local hostname
    hostname=$(scutil --get ComputerName 2>/dev/null || echo "unknown")
    log "Hostname: ${C_BOLD}$hostname${C_RESET}"

    local generic
    generic=$(get_generic_display_name)
    if [[ "$hostname" == "$generic" ]]; then
        log "Hostname type: ${C_YELLOW}generic (hardened)${C_RESET}"
    else
        log "Hostname type: ${C_GREEN}personal${C_RESET}"
    fi

    # Stored personal hostname
    local stored
    stored=$(keychain_get_hostname)
    if [[ -n "$stored" ]]; then
        log "Stored personal hostname: ${C_DIM}$stored${C_RESET}"
    else
        log "Stored personal hostname: ${C_DIM}(none)${C_RESET}"
    fi

    # LaunchAgent
    local agent_path="$HOME/Library/LaunchAgents/com.qinnovates.macshield.plist"
    if [[ -f "$agent_path" ]]; then
        log "LaunchAgent: ${C_GREEN}installed${C_RESET}"
    else
        log "LaunchAgent: ${C_RED}not installed${C_RESET}"
    fi

    # Sudoers fragment
    if [[ -f "/etc/sudoers.d/macshield" ]]; then
        log "Sudoers authorization: ${C_GREEN}installed${C_RESET}"
    else
        log "Sudoers authorization: ${C_YELLOW}not installed (manual sudo prompts)${C_RESET}"
    fi

    # DNS (from system config)
    local wifi_iface
    wifi_iface=$(get_wifi_interface)
    if [[ -n "$wifi_iface" ]]; then
        local dns_servers
        dns_servers=$(networksetup -getdnsservers Wi-Fi 2>/dev/null | tr '\n' ', ' | sed 's/,$//')
        if [[ -n "$dns_servers" && "$dns_servers" != *"any DNS"* ]]; then
            log "DNS servers: ${C_CYAN}$dns_servers${C_RESET}"
        else
            log "DNS servers: ${C_YELLOW}system default (ISP)${C_RESET}"
        fi
    fi
}

cmd_trust() {
    local ssid
    if ! ssid=$(get_current_ssid); then
        die "Not connected to any WiFi network."
    fi

    local hash
    hash=$(compute_hmac "$ssid")

    if keychain_is_trusted "$hash"; then
        log "This network is already trusted."
        return 0
    fi

    keychain_store_trusted "$hash"
    log_success "Network added to trusted list."
    log_dim "Fingerprint stored in Keychain (HMAC hash, not SSID)."

    # If currently hardened, relax now
    if [[ "$(get_state)" == "hardened" ]]; then
        log "Relaxing protections for trusted network..."
        do_relax
    fi
}

cmd_trust_paranoid() {
    # Remove all trusted networks
    keychain_clear_all
    log_warn "Paranoid mode: all trusted networks removed."
    log "macshield will treat ${C_BOLD_RED}ALL${C_RESET} networks as untrusted."
    log_dim "Use 'macshield relax' to manually relax (expires on disconnect)."
    do_harden
}

cmd_untrust() {
    local ssid
    if ! ssid=$(get_current_ssid); then
        die "Not connected to any WiFi network."
    fi

    local hash
    hash=$(compute_hmac "$ssid")

    keychain_remove_trusted "$hash"
    log_warn "Network removed from trusted list."

    # Harden if we're currently relaxed
    if [[ "$(get_state)" == "relaxed" ]]; then
        log "Hardening for untrusted network..."
        do_harden
    fi
}

cmd_relax() {
    local duration="${1:-}"

    echo ""
    log_header "=== Manual Relax ==="
    echo ""
    log "This will:"
    log "  ${C_GREEN}1.${C_RESET} Disable stealth mode (AirDrop, Spotify Connect, etc. will work)"
    log "  ${C_GREEN}2.${C_RESET} Restore your personal hostname from Keychain"
    log "  ${C_GREEN}3.${C_RESET} Re-enable NetBIOS"
    echo ""
    log_dim "These changes use sudo for 3 system commands."
    if [[ -n "$duration" ]]; then
        log "Protections will be re-applied after $duration."
    else
        log "Protections will be re-applied on the next network change."
    fi
    echo ""

    if ! ask "Proceed?"; then
        log "Cancelled."
        return 0
    fi
    echo ""

    if [[ -n "$duration" ]]; then
        # Parse duration first (validate before making changes)
        local seconds=0
        if [[ "$duration" =~ ^([0-9]+)h$ ]]; then
            seconds=$(( ${BASH_REMATCH[1]} * 3600 ))
        elif [[ "$duration" =~ ^([0-9]+)m$ ]]; then
            seconds=$(( ${BASH_REMATCH[1]} * 60 ))
        elif [[ "$duration" =~ ^([0-9]+)s$ ]]; then
            seconds=${BASH_REMATCH[1]}
        else
            die "Invalid duration format. Use: 2h, 30m, or 300s"
        fi

        log "Temporarily relaxing protections for $duration..."
        do_relax

        log "Will re-harden in $duration ($seconds seconds)."
        # Run timer in background
        (
            sleep "$seconds"
            log "Timed relax expired. Re-hardening..."
            do_harden
        ) &
        disown
    else
        log "Manually relaxing protections..."
        do_relax
        log "Note: protections will be re-applied on next network change."
    fi
}

cmd_harden() {
    echo ""
    log_header "=== Manual Harden ==="
    echo ""
    log "This will:"
    log "  ${C_RED}1.${C_RESET} Enable stealth mode (blocks ICMP pings and port scans)"
    log "  ${C_RED}2.${C_RESET} Set your hostname to a generic name (e.g., \"MacBook Pro\")"
    log "  ${C_RED}3.${C_RESET} Disable NetBIOS (close ports 137/138, stop name broadcast)"
    echo ""
    log_warn "WARNING: Hostname change"
    log "  Changing your computer name affects how your Mac appears on local"
    log "  networks, in AirDrop, Bluetooth, Terminal prompts, and Sharing"
    log "  preferences. Some apps that reference your hostname may behave"
    log "  differently. Your original name is saved in Keychain and restored"
    log "  when you return to a trusted network or run 'macshield relax'."
    echo ""
    log_dim "These changes use sudo for 3 system commands."
    log_dim "Protections will be re-evaluated on the next network change."
    echo ""

    if ! ask "Proceed?"; then
        log "Cancelled."
        return 0
    fi
    echo ""
    do_harden
}

cmd_install() {
    local installer=""

    # Method 1: Homebrew Cellar path (resolves through symlink)
    local real_bin
    real_bin="$(realpath "$0" 2>/dev/null || readlink -f "$0" 2>/dev/null || echo "")"
    if [[ -n "$real_bin" ]]; then
        local cellar_dir
        cellar_dir="$(dirname "$real_bin")"
        if [[ -f "$cellar_dir/../libexec/install.sh" ]]; then
            installer="$(cd "$cellar_dir/../libexec" && pwd -P)/install.sh"
        fi
    fi

    # Method 2: Same directory as the script
    if [[ -z "$installer" ]]; then
        local script_dir
        script_dir="$(cd "$(dirname "$0")" && pwd -P)"
        if [[ -f "$script_dir/install.sh" ]]; then
            installer="$script_dir/install.sh"
        fi
    fi

    # Method 3: Homebrew prefix query
    if [[ -z "$installer" ]] && command -v brew &>/dev/null; then
        local prefix
        prefix="$(brew --prefix macshield 2>/dev/null || echo "")"
        if [[ -n "$prefix" && -f "$prefix/libexec/install.sh" ]]; then
            installer="$prefix/libexec/install.sh"
        fi
    fi

    [[ -z "$installer" ]] && die "install.sh not found. Re-clone from https://github.com/qinnovates/macshield"
    exec bash "$installer"
}

cmd_uninstall() {
    local uninstaller=""

    local real_bin
    real_bin="$(realpath "$0" 2>/dev/null || readlink -f "$0" 2>/dev/null || echo "")"
    if [[ -n "$real_bin" ]]; then
        local cellar_dir
        cellar_dir="$(dirname "$real_bin")"
        if [[ -f "$cellar_dir/../libexec/uninstall.sh" ]]; then
            uninstaller="$(cd "$cellar_dir/../libexec" && pwd -P)/uninstall.sh"
        fi
    fi

    if [[ -z "$uninstaller" ]]; then
        local script_dir
        script_dir="$(cd "$(dirname "$0")" && pwd -P)"
        if [[ -f "$script_dir/uninstall.sh" ]]; then
            uninstaller="$script_dir/uninstall.sh"
        fi
    fi

    if [[ -z "$uninstaller" ]] && command -v brew &>/dev/null; then
        local prefix
        prefix="$(brew --prefix macshield 2>/dev/null || echo "")"
        if [[ -n "$prefix" && -f "$prefix/libexec/uninstall.sh" ]]; then
            uninstaller="$prefix/libexec/uninstall.sh"
        fi
    fi

    [[ -z "$uninstaller" ]] && die "uninstall.sh not found."
    exec bash "$uninstaller"
}

cmd_scan() {
    local auto_purge="${1:-}"
    local quiet="${2:-}"

    # --- Interactive preamble (skip with --quiet) ---
    if [[ "$quiet" != "--quiet" ]]; then
        echo ""
        log_header "=== Port Scan ==="
        echo ""
        log "${C_BOLD}What this does:${C_RESET}"
        log "  Scans your Mac for all open TCP and UDP ports using 'lsof'."
        log "  Labels each port with what it does (DNS, Bonjour, AirPlay, etc.)."
        log "  Flags non-standard ports as ${C_YELLOW}** REVIEW **${C_RESET} for your attention."
        echo ""
        log "${C_BOLD}What this does NOT do:${C_RESET}"
        log "  - No network calls. The scan reads local system state only."
        log "  - No data leaves your machine. Ever."
        echo ""
        log "${C_BOLD}What happens to the results:${C_RESET}"
        log "  Results are displayed to your terminal and never saved to disk."
        log "  No files are created. After the report, you will be offered the"
        log "  option to wipe your terminal scrollback so no trace remains."
        echo ""
        log_dim "  For scripting or non-interactive use:"
        log_dim "    macshield scan --purge 5m   Save report, auto-delete after 5 minutes"
        log_dim "    macshield scan --quiet      Scan without prompts, display only"
        echo ""
        log_dim "Security note:"
        log_dim "  This scan reads local system state only (lsof, socketfilterfw)."
        log_dim "  It sends zero packets to the network. Safe on any WiFi, including"
        log_dim "  public networks. No admin can detect it because nothing leaves"
        log_dim "  your machine. Verify: grep -n 'curl\|wget\|nc ' macshield.sh"
        echo ""

        if ! ask "Proceed with port scan?"; then
            log "Scan cancelled."
            return 0
        fi
        echo ""
    fi

    log "Scanning open ports..."
    log ""

    # Look up known system ports (bash 3 compatible, no associative arrays)
    port_note() {
        local p="$1"
        # Handle non-numeric ports (lsof shows * for unbound)
        case "$p" in
            *[!0-9]*) echo "(unbound)"; return ;;
        esac
        case "$p" in
            53)    echo "DNS (domain name resolution)" ;;
            80)    echo "HTTP" ;;
            88)    echo "Kerberos authentication" ;;
            123)   echo "NTP (time sync)" ;;
            137)   echo "NetBIOS name service" ;;
            138)   echo "NetBIOS datagram" ;;
            443)   echo "HTTPS" ;;
            500)   echo "IKE (VPN key exchange)" ;;
            631)   echo "CUPS (printing)" ;;
            1900)  echo "SSDP / UPnP discovery" ;;
            3722)  echo "DeviceLink2 (iOS sync)" ;;
            5000)  echo "AirPlay / UPnP" ;;
            5353)  echo "mDNS / Bonjour" ;;
            7000)  echo "AirPlay streaming" ;;
            *)
                if (( p >= 49152 )); then
                    echo "ephemeral (normal)"
                else
                    echo "** REVIEW **"
                fi
                ;;
        esac
    }

    # Build the report
    local report=""
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")

    report+="================================================================"$'\n'
    report+="  macshield Port Scan Report"$'\n'
    report+="  Generated: $timestamp"$'\n'
    report+="  Host: $(scutil --get ComputerName 2>/dev/null || echo unknown)"$'\n'
    report+="================================================================"$'\n'
    report+=""$'\n'

    # Listening ports via lsof (no root needed for user processes)
    log "  Running: lsof -iTCP -sTCP:LISTEN -P -n (listing TCP listeners)"
    local listen_output
    listen_output=$(lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null || true)

    log "  Running: lsof -iUDP -P -n (listing UDP ports)"
    local listen_udp
    listen_udp=$(lsof -iUDP -P -n 2>/dev/null || true)

    log "  Running: socketfilterfw --getglobalstate (checking firewall)"
    log "  Running: socketfilterfw --getstealthmode (checking stealth mode)"
    log ""

    # TCP listeners
    report+="--- TCP LISTENING PORTS ---"$'\n'
    report+=""$'\n'

    local tcp_count=0
    local warn_count=0

    if [[ -n "$listen_output" ]]; then
        # Header
        report+="$(printf '  %-8s %-24s %-8s %s\n' "PORT" "PROCESS" "PID" "NOTE")"$'\n'
        report+="  $(printf '%0.s-' {1..70})"$'\n'

        while IFS= read -r line; do
            # Skip header
            [[ "$line" == COMMAND* ]] && continue

            local cmd pid addr port
            cmd=$(echo "$line" | awk '{print $1}')
            pid=$(echo "$line" | awk '{print $2}')
            addr=$(echo "$line" | awk '{print $9}')
            port="${addr##*:}"

            local note
            note=$(port_note "$port")
            [[ "$note" == "** REVIEW **" ]] && ((warn_count++))

            report+="$(printf '  %-8s %-24s %-8s %s\n' "$port" "$cmd" "$pid" "$note")"$'\n'
            ((tcp_count++))
        done <<< "$listen_output"
    else
        report+="  No TCP listening ports detected."$'\n'
    fi

    report+=""$'\n'
    report+="  Total TCP listeners: $tcp_count"$'\n'
    report+="  Ports to review: $warn_count"$'\n'
    report+=""$'\n'

    # UDP listeners (summary only, UDP is noisy)
    report+="--- UDP PORTS ---"$'\n'
    report+=""$'\n'

    local udp_count=0
    if [[ -n "$listen_udp" ]]; then
        report+="$(printf '  %-8s %-24s %-8s %s\n' "PORT" "PROCESS" "PID" "NOTE")"$'\n'
        report+="  $(printf '%0.s-' {1..70})"$'\n'

        # Deduplicate by port+process
        local seen_udp=""
        while IFS= read -r line; do
            [[ "$line" == COMMAND* ]] && continue

            local cmd pid addr port
            cmd=$(echo "$line" | awk '{print $1}')
            pid=$(echo "$line" | awk '{print $2}')
            addr=$(echo "$line" | awk '{print $9}')
            port="${addr##*:}"

            # Skip if already seen this port+process combo
            local key="${port}:${cmd}"
            [[ "$seen_udp" == *"$key"* ]] && continue
            seen_udp+=" $key"

            local note
            note=$(port_note "$port")

            report+="$(printf '  %-8s %-24s %-8s %s\n' "$port" "$cmd" "$pid" "$note")"$'\n'
            ((udp_count++))
        done <<< "$listen_udp"
    else
        report+="  No UDP ports detected."$'\n'
    fi

    report+=""$'\n'
    report+="  Total UDP ports: $udp_count"$'\n'
    report+=""$'\n'

    # Firewall status
    report+="--- FIREWALL STATUS ---"$'\n'
    report+=""$'\n'
    local fw_status
    fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")
    report+="  Firewall: $fw_status"$'\n'
    local stealth_status
    stealth_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null || echo "unknown")
    report+="  Stealth mode: $stealth_status"$'\n'
    report+=""$'\n'

    # Warnings
    report+="--- WARNINGS ---"$'\n'
    report+=""$'\n'
    report+="  Closing ports may break system features (AirDrop, printing,"$'\n'
    report+="  screen sharing, iCloud sync, etc). Research each port before"$'\n'
    report+="  disabling the service behind it."$'\n'
    report+=""$'\n'
    report+="  Ports marked ** REVIEW ** are non-standard and worth investigating."$'\n'
    report+="  They may be legitimate (dev servers, Docker, etc.) or unexpected."$'\n'
    report+=""$'\n'
    report+="================================================================"$'\n'

    # Display the report
    echo "$report"

    # --- Offer to wipe terminal scrollback (interactive only) ---
    if [[ "$quiet" != "--quiet" && -z "$auto_purge" ]]; then
        echo ""
        log "The report is in your terminal scrollback. To leave no trace,"
        log "you can wipe the scrollback now. This clears your entire terminal"
        log "history (not just the report), so scroll up and copy anything you"
        log "need before saying yes."
        echo ""
        if ask "Wipe terminal scrollback?"; then
            clear
            printf '\e[3J'
            log_success "Terminal scrollback cleared. No trace of the report remains."
        else
            log_dim "Scrollback kept. You can clear it later:"
            log_dim "  printf '\\e[3J' && clear"
            log_dim "Or close this terminal window."
        fi
    fi

    # --- Save to disk only with explicit --purge flag (always auto-deletes) ---
    if [[ -n "$auto_purge" ]]; then
        # Non-interactive with explicit purge duration
        safe_write "$SCAN_REPORT" "$report"
        chmod 600 "$SCAN_REPORT"
        log "Report saved to $SCAN_REPORT (local only, not synced anywhere)"

        local seconds=0
        if [[ "$auto_purge" =~ ^([0-9]+)h$ ]]; then
            seconds=$(( ${BASH_REMATCH[1]} * 3600 ))
        elif [[ "$auto_purge" =~ ^([0-9]+)m$ ]]; then
            seconds=$(( ${BASH_REMATCH[1]} * 60 ))
        elif [[ "$auto_purge" =~ ^([0-9]+)s$ ]]; then
            seconds=${BASH_REMATCH[1]}
        else
            die "Invalid auto-purge duration. Use: 5m, 1h, or 300s"
        fi

        log "Auto-purge scheduled: report will be deleted in $auto_purge."
        ( sleep "$seconds"; rm -f "$SCAN_REPORT" ) &
        disown
    fi
}

# ---------------------------------------------------------------------------
# Optional security commands (not run by default)
# Inspired by Lynis (CISOfy), mOSL, drduh's macOS Security Guide,
# and MacSecureCheck. All checks are pure bash, no dependencies,
# no network calls.
# ---------------------------------------------------------------------------

audit_check() {
    # Print a PASS/WARN/INFO line
    local status="$1"
    local label="$2"
    local detail="${3:-}"
    case "$status" in
        PASS) printf "  [\033[32mPASS\033[0m] %s" "$label" ;;
        WARN) printf "  [\033[33mWARN\033[0m] %s" "$label" ;;
        FAIL) printf "  [\033[31mFAIL\033[0m] %s" "$label" ;;
        INFO) printf "  [\033[36mINFO\033[0m] %s" "$label" ;;
    esac
    [[ -n "$detail" ]] && printf " - %s" "$detail"
    echo ""
}

cmd_audit() {
    echo ""
    log_header "=== Security Audit ==="
    echo ""
    log "This checks your system security posture. Read-only, no changes."
    log_dim "No data leaves your machine. No network calls."
    echo ""

    local pass_count=0
    local warn_count=0
    local fail_count=0

    # --- System Protection ---
    log_header "--- System Protection ---"
    echo ""

    # SIP
    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "unknown")
    if [[ "$sip_status" == *"enabled"* ]]; then
        audit_check PASS "System Integrity Protection (SIP)" "enabled"
        ((pass_count++)) || true
    else
        audit_check FAIL "System Integrity Protection (SIP)" "disabled or unknown"
        ((fail_count++)) || true
    fi

    # FileVault
    local fv_status
    fv_status=$(fdesetup status 2>/dev/null || echo "unknown")
    if [[ "$fv_status" == *"On"* ]]; then
        audit_check PASS "FileVault disk encryption" "enabled"
        ((pass_count++)) || true
    else
        audit_check WARN "FileVault disk encryption" "not enabled"
        ((warn_count++)) || true
    fi

    # Gatekeeper
    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "unknown")
    if [[ "$gk_status" == *"enabled"* ]]; then
        audit_check PASS "Gatekeeper" "enabled"
        ((pass_count++)) || true
    else
        audit_check FAIL "Gatekeeper" "disabled"
        ((fail_count++)) || true
    fi

    # Firewall
    local fw_status
    fw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")
    if [[ "$fw_status" == *"enabled"* ]]; then
        audit_check PASS "Application Firewall" "enabled"
        ((pass_count++)) || true
    else
        audit_check WARN "Application Firewall" "disabled"
        ((warn_count++)) || true
    fi

    # Stealth mode
    local stealth
    stealth=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null || echo "unknown")
    if [[ "$stealth" == *"enabled"* ]]; then
        audit_check PASS "Stealth mode" "enabled"
        ((pass_count++)) || true
    else
        audit_check INFO "Stealth mode" "disabled (macshield enables this on untrusted networks)"
    fi

    # Lockdown Mode (macOS Ventura+)
    local lockdown
    lockdown=$(defaults read .GlobalPreferences LDMGlobalEnabled 2>/dev/null || echo "missing")
    if [[ "$lockdown" == "1" ]]; then
        audit_check PASS "Lockdown Mode" "enabled"
        ((pass_count++)) || true
    else
        audit_check INFO "Lockdown Mode" "not enabled (extreme protection, breaks many features)"
    fi

    # Secure Boot (Apple Silicon)
    local secure_boot
    secure_boot=$(system_profiler SPiBridgeDataType 2>/dev/null | awk -F': ' '/Secure Boot/{print $2}')
    if [[ -z "$secure_boot" ]]; then
        # Try Apple Silicon method
        secure_boot=$(bputil -d 2>/dev/null | awk '/Security Mode/{print $NF}' || echo "")
    fi
    if [[ -n "$secure_boot" ]]; then
        if [[ "$secure_boot" == *"Full"* ]]; then
            audit_check PASS "Secure Boot" "$secure_boot"
            ((pass_count++)) || true
        else
            audit_check WARN "Secure Boot" "$secure_boot (Full Security recommended)"
            ((warn_count++)) || true
        fi
    fi

    # XProtect
    local xprotect_ver
    xprotect_ver=$(system_profiler SPInstallHistoryDataType 2>/dev/null \
        | awk '/XProtect/{getline; getline; print; exit}' | awk -F': ' '{print $2}' | xargs)
    if [[ -n "$xprotect_ver" ]]; then
        audit_check INFO "XProtect" "last update: $xprotect_ver"
    fi

    echo ""

    # --- Sharing Services ---
    log_header "--- Sharing Services ---"
    echo ""

    # Remote Login (SSH)
    local ssh_status
    ssh_status=$(systemsetup -getremotelogin 2>/dev/null || echo "unknown")
    if [[ "$ssh_status" == *"Off"* ]]; then
        audit_check PASS "Remote Login (SSH)" "disabled"
        ((pass_count++)) || true
    else
        audit_check WARN "Remote Login (SSH)" "enabled (port 22 open to network)"
        ((warn_count++)) || true
    fi

    # Screen Sharing
    if launchctl list 2>/dev/null | grep -q "com.apple.screensharing"; then
        audit_check WARN "Screen Sharing" "enabled (remote desktop access open)"
        ((warn_count++)) || true
    else
        audit_check PASS "Screen Sharing" "disabled"
        ((pass_count++)) || true
    fi

    # File Sharing (SMB)
    if launchctl list 2>/dev/null | grep -q "com.apple.smbd"; then
        audit_check WARN "File Sharing (SMB)" "enabled (network file shares open)"
        ((warn_count++)) || true
    else
        audit_check PASS "File Sharing (SMB)" "disabled"
        ((pass_count++)) || true
    fi

    # Remote Management (ARD)
    if launchctl list 2>/dev/null | grep -q "com.apple.RemoteDesktop"; then
        audit_check WARN "Remote Management (ARD)" "enabled"
        ((warn_count++)) || true
    else
        audit_check PASS "Remote Management (ARD)" "disabled"
        ((pass_count++)) || true
    fi

    # Remote Apple Events
    local rae_status
    rae_status=$(systemsetup -getremoteappleevents 2>/dev/null || echo "unknown")
    if [[ "$rae_status" == *"Off"* ]]; then
        audit_check PASS "Remote Apple Events" "disabled"
        ((pass_count++)) || true
    else
        audit_check WARN "Remote Apple Events" "enabled"
        ((warn_count++)) || true
    fi

    # Bluetooth discoverable
    local bt_disco
    bt_disco=$(defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>/dev/null || echo "")
    if [[ "$bt_disco" == "0" ]]; then
        audit_check PASS "Bluetooth" "disabled"
        ((pass_count++)) || true
    else
        audit_check INFO "Bluetooth" "enabled (normal, but disable on untrusted networks if not needed)"
    fi

    # AirDrop discoverability
    local airdrop
    airdrop=$(defaults read com.apple.sharingd DiscoverableMode 2>/dev/null || echo "unknown")
    case "$airdrop" in
        "Off")
            audit_check PASS "AirDrop" "receiving disabled"
            ((pass_count++)) || true
            ;;
        "Contacts Only"|"ContactsOnly")
            audit_check PASS "AirDrop" "contacts only"
            ((pass_count++)) || true
            ;;
        "Everyone")
            audit_check WARN "AirDrop" "set to Everyone (anyone nearby can send you files)"
            ((warn_count++)) || true
            ;;
        *)
            audit_check INFO "AirDrop" "could not determine setting"
            ;;
    esac

    echo ""

    # --- Privacy Settings ---
    log_header "--- Privacy Settings ---"
    echo ""

    # Analytics
    local analytics
    analytics=$(defaults read "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist" AutoSubmit 2>/dev/null || echo "unknown")
    if [[ "$analytics" == "0" ]]; then
        audit_check PASS "Share Mac Analytics" "disabled"
        ((pass_count++)) || true
    elif [[ "$analytics" == "1" ]]; then
        audit_check WARN "Share Mac Analytics" "enabled (sends usage data to Apple)"
        ((warn_count++)) || true
    else
        audit_check INFO "Share Mac Analytics" "could not determine"
    fi

    # Siri
    local siri
    siri=$(defaults read com.apple.assistant.support "Assistant Enabled" 2>/dev/null || echo "unknown")
    if [[ "$siri" == "0" ]]; then
        audit_check PASS "Siri" "disabled"
        ((pass_count++)) || true
    elif [[ "$siri" == "1" ]]; then
        audit_check INFO "Siri" "enabled (sends voice data to Apple for processing)"
    else
        audit_check INFO "Siri" "could not determine"
    fi

    # Spotlight Suggestions (sends queries to Apple)
    local spotlight
    spotlight=$(defaults read com.apple.lookup.shared LookupSuggestionsDisabled 2>/dev/null || echo "unknown")
    if [[ "$spotlight" == "1" ]]; then
        audit_check PASS "Spotlight Suggestions" "disabled (queries stay local)"
        ((pass_count++)) || true
    else
        audit_check INFO "Spotlight Suggestions" "enabled (sends search queries to Apple)"
    fi

    # Personalized Ads
    local ads
    ads=$(defaults read com.apple.AdLib allowApplePersonalizedAdvertising 2>/dev/null || echo "unknown")
    if [[ "$ads" == "0" ]]; then
        audit_check PASS "Personalized Ads" "disabled"
        ((pass_count++)) || true
    else
        audit_check INFO "Personalized Ads" "enabled or could not determine"
    fi

    echo ""

    # --- WiFi Security ---
    log_header "--- WiFi Security ---"
    echo ""

    local iface
    iface=$(get_wifi_interface)
    if [[ -n "$iface" ]]; then
        # Check WiFi security type
        local wifi_security
        wifi_security=$(ipconfig getsummary "$iface" 2>/dev/null \
            | awk -F' : ' '/Security/{print $2; exit}' || echo "")
        if [[ -z "$wifi_security" ]]; then
            wifi_security=$(system_profiler SPAirPortDataType 2>/dev/null \
                | awk -F': ' '/Security/{print $2; exit}' || echo "unknown")
        fi

        case "$wifi_security" in
            *WPA3*|*SAE*)
                audit_check PASS "WiFi security" "$wifi_security"
                ((pass_count++)) || true
                ;;
            *WPA2*)
                audit_check PASS "WiFi security" "$wifi_security"
                ((pass_count++)) || true
                ;;
            *WEP*)
                audit_check FAIL "WiFi security" "$wifi_security (WEP is broken, do not use)"
                ((fail_count++)) || true
                ;;
            *None*|*Open*)
                audit_check FAIL "WiFi security" "OPEN network (no encryption, traffic visible to all)"
                ((fail_count++)) || true
                ;;
            *)
                audit_check INFO "WiFi security" "$wifi_security"
                ;;
        esac

        # Private WiFi address
        local private_mac
        private_mac=$(ipconfig getsummary "$iface" 2>/dev/null \
            | awk -F' : ' '/Private MAC/{print $2; exit}' || echo "")
        if [[ "$private_mac" == *"Yes"* || "$private_mac" == *"1"* ]]; then
            audit_check PASS "Private WiFi Address" "enabled (MAC randomization)"
            ((pass_count++)) || true
        elif [[ -n "$private_mac" ]]; then
            audit_check WARN "Private WiFi Address" "disabled (real MAC exposed)"
            ((warn_count++)) || true
        fi

        # DNS servers
        local dns_servers
        dns_servers=$(networksetup -getdnsservers Wi-Fi 2>/dev/null | tr '\n' ', ' | sed 's/,$//')
        if [[ -n "$dns_servers" && "$dns_servers" != *"any DNS"* ]]; then
            audit_check INFO "DNS servers" "$dns_servers"
        else
            audit_check INFO "DNS servers" "ISP default (your ISP sees every domain you visit)"
        fi
    else
        audit_check INFO "WiFi" "no WiFi interface detected"
    fi

    echo ""

    # --- ARP Table (MitM detection) ---
    log_header "--- ARP Table (MitM Detection) ---"
    echo ""

    local arp_dupes
    arp_dupes=$(arp -a 2>/dev/null | awk '{print $4}' | sort | uniq -d | grep -v "incomplete" || true)
    if [[ -z "$arp_dupes" ]]; then
        audit_check PASS "ARP table" "no duplicate MAC addresses (no obvious ARP spoofing)"
        ((pass_count++)) || true
    else
        audit_check FAIL "ARP table" "DUPLICATE MAC addresses detected (possible ARP spoofing/MitM)"
        ((fail_count++)) || true
        echo "  Duplicate MACs:"
        echo "$arp_dupes" | while read -r mac; do
            echo "    $mac -> $(arp -a 2>/dev/null | grep "$mac" | awk '{print $2}')"
        done
    fi

    echo ""

    # --- File Hygiene ---
    log_header "--- File Hygiene ---"
    echo ""

    # .ssh permissions
    if [[ -d "$HOME/.ssh" ]]; then
        local ssh_perms
        ssh_perms=$(stat -f "%Lp" "$HOME/.ssh" 2>/dev/null || echo "unknown")
        if [[ "$ssh_perms" == "700" ]]; then
            audit_check PASS ".ssh directory" "permissions 700"
            ((pass_count++)) || true
        else
            audit_check WARN ".ssh directory" "permissions $ssh_perms (should be 700)"
            ((warn_count++)) || true
        fi

        # Check key file permissions
        local bad_keys=0
        local good_keys=0
        for keyfile in "$HOME/.ssh"/id_*; do
            [[ -f "$keyfile" ]] || continue
            [[ "$keyfile" == *.pub ]] && continue
            local kperms
            kperms=$(stat -f "%Lp" "$keyfile" 2>/dev/null || echo "unknown")
            if [[ "$kperms" != "600" && "$kperms" != "400" ]]; then
                audit_check WARN "SSH key $(basename "$keyfile")" "permissions $kperms (should be 600)"
                ((bad_keys++)) || true
                ((warn_count++)) || true
            else
                ((good_keys++)) || true
            fi
        done
        if [[ $bad_keys -eq 0 && $good_keys -gt 0 ]]; then
            audit_check PASS "SSH key permissions" "all $good_keys private keys have correct permissions"
            ((pass_count++)) || true
        fi
    fi

    # .env files in home (shallow search only, avoid traversing huge dirs)
    local env_count=0
    for d in "$HOME" "$HOME/Desktop" "$HOME/Documents" "$HOME/Projects" "$HOME/Code" "$HOME/dev" "$HOME/src"; do
        [[ -d "$d" ]] || continue
        local found_envs
        found_envs=$(ls "$d"/.env "$d"/*/.env 2>/dev/null | head -10 || true)
        if [[ -n "$found_envs" ]]; then
            env_count=$(( env_count + $(echo "$found_envs" | wc -l | xargs) ))
        fi
    done
    if [[ $env_count -gt 0 ]]; then
        audit_check WARN ".env files found" "$env_count file(s) near home directory (may contain secrets)"
        ((warn_count++)) || true
    fi

    # Git credentials in plaintext
    if [[ -f "$HOME/.git-credentials" ]]; then
        audit_check WARN ".git-credentials" "plaintext credentials file exists"
        ((warn_count++)) || true
    fi

    # .netrc
    if [[ -f "$HOME/.netrc" ]]; then
        local netrc_perms
        netrc_perms=$(stat -f "%Lp" "$HOME/.netrc" 2>/dev/null || echo "unknown")
        if [[ "$netrc_perms" != "600" && "$netrc_perms" != "400" ]]; then
            audit_check WARN ".netrc" "permissions $netrc_perms (should be 600, contains credentials)"
            ((warn_count++)) || true
        else
            audit_check INFO ".netrc" "exists (permissions $netrc_perms)"
        fi
    fi

    echo ""

    # --- Summary ---
    log_header "--- Summary ---"
    echo ""
    log "  ${C_GREEN}PASS: $pass_count${C_RESET}  |  ${C_YELLOW}WARN: $warn_count${C_RESET}  |  ${C_RED}FAIL: $fail_count${C_RESET}"
    echo ""

    if [[ $fail_count -gt 0 ]]; then
        log "  Items marked FAIL need immediate attention."
    fi
    if [[ $warn_count -gt 0 ]]; then
        log "  Items marked WARN are worth reviewing."
    fi
    log "  Items marked INFO are informational (not necessarily bad)."
    echo ""
    log "  This audit is inspired by Lynis (cisofy.com/lynis), mOSL, and"
    log "  drduh's macOS Security Guide. For deeper auditing, consider"
    log "  running Lynis: brew install lynis && sudo lynis audit system"
    echo ""
}

cmd_connections() {
    echo ""
    log_header "=== Active Connections ==="
    echo ""
    log "Shows all established TCP connections with process names."
    log "This tells you who your Mac is talking to right now."
    log_dim "Read-only, no network calls, no changes."
    echo ""

    local conns
    conns=$(lsof -i -nP 2>/dev/null | grep "ESTABLISHED" || true)

    if [[ -z "$conns" ]]; then
        log "No established TCP connections."
        return 0
    fi

    printf "  %-20s %-8s %-40s %s\n" "PROCESS" "PID" "REMOTE" "LOCAL PORT"
    printf "  %0.s-" {1..90}
    echo ""

    local seen=""
    while IFS= read -r line; do
        local cmd pid remote local_part
        cmd=$(echo "$line" | awk '{print $1}')
        pid=$(echo "$line" | awk '{print $2}')

        # Extract the connection endpoints
        local name_field
        name_field=$(echo "$line" | awk '{print $9}')

        # Format: local->remote or remote->local
        if [[ "$name_field" == *"->"* ]]; then
            local_part="${name_field%%->*}"
            remote="${name_field##*->}"
        else
            remote="$name_field"
            local_part=""
        fi

        local local_port="${local_part##*:}"

        # Deduplicate
        local key="${cmd}:${remote}"
        [[ "$seen" == *"$key"* ]] && continue
        seen+=" $key"

        printf "  %-20s %-8s %-40s %s\n" "$cmd" "$pid" "$remote" "$local_port"
    done <<< "$conns"

    echo ""
    local total
    total=$(echo "$seen" | wc -w | xargs)
    log "Total unique connections: $total"
    echo ""
    log "Note: This is a snapshot. Connections change constantly."
    log "Run again to see current state."
    echo ""
}

cmd_persistence() {
    echo ""
    log_header "=== Persistence Check ==="
    echo ""
    log "Lists non-Apple LaunchAgents, LaunchDaemons, login items,"
    log "and cron jobs. These are mechanisms that run code automatically."
    log_dim "Read-only, no changes."
    echo ""

    local found=0

    # User LaunchAgents
    log_header "--- User LaunchAgents (~/$HOME/Library/LaunchAgents) ---"
    echo ""
    if [[ -d "$HOME/Library/LaunchAgents" ]]; then
        local user_agents
        user_agents=$(ls "$HOME/Library/LaunchAgents/"*.plist 2>/dev/null || true)
        if [[ -n "$user_agents" ]]; then
            while IFS= read -r plist; do
                local name
                name=$(basename "$plist" .plist)
                if [[ "$name" == com.apple.* ]]; then
                    continue
                fi
                local program
                program=$(defaults read "$plist" Program 2>/dev/null \
                    || defaults read "$plist" ProgramArguments 2>/dev/null | head -2 | tail -1 | xargs \
                    || echo "(could not read)")
                printf "  %-45s %s\n" "$name" "$program"
                ((found++)) || true
            done <<< "$user_agents"
        fi
    fi
    [[ $found -eq 0 ]] && echo "  (none)"
    echo ""

    # System LaunchAgents
    local sys_found=0
    log_header "--- System LaunchAgents (/Library/LaunchAgents) ---"
    echo ""
    if [[ -d "/Library/LaunchAgents" ]]; then
        local sys_agents
        sys_agents=$(ls /Library/LaunchAgents/*.plist 2>/dev/null || true)
        if [[ -n "$sys_agents" ]]; then
            while IFS= read -r plist; do
                local name
                name=$(basename "$plist" .plist)
                [[ "$name" == com.apple.* ]] && continue
                local program
                program=$(defaults read "$plist" Program 2>/dev/null \
                    || defaults read "$plist" ProgramArguments 2>/dev/null | head -2 | tail -1 | xargs \
                    || echo "(could not read)")
                printf "  %-45s %s\n" "$name" "$program"
                ((sys_found++)) || true
            done <<< "$sys_agents"
        fi
    fi
    [[ $sys_found -eq 0 ]] && echo "  (none)"
    echo ""

    # LaunchDaemons
    local daemon_found=0
    log_header "--- System LaunchDaemons (/Library/LaunchDaemons) ---"
    echo ""
    if [[ -d "/Library/LaunchDaemons" ]]; then
        local daemons
        daemons=$(ls /Library/LaunchDaemons/*.plist 2>/dev/null || true)
        if [[ -n "$daemons" ]]; then
            while IFS= read -r plist; do
                local name
                name=$(basename "$plist" .plist)
                [[ "$name" == com.apple.* ]] && continue
                local program
                program=$(defaults read "$plist" Program 2>/dev/null \
                    || defaults read "$plist" ProgramArguments 2>/dev/null | head -2 | tail -1 | xargs \
                    || echo "(could not read)")
                printf "  %-45s %s\n" "$name" "$program"
                ((daemon_found++)) || true
            done <<< "$daemons"
        fi
    fi
    [[ $daemon_found -eq 0 ]] && echo "  (none)"
    echo ""

    # Login Items
    log_header "--- Login Items ---"
    echo ""
    local login_items
    login_items=$(osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null || echo "")
    if [[ -n "$login_items" && "$login_items" != "" ]]; then
        echo "  $login_items"
    else
        echo "  (none or could not read)"
    fi
    echo ""

    # Cron jobs
    log_header "--- Cron Jobs ---"
    echo ""
    local cron_jobs
    cron_jobs=$(crontab -l 2>/dev/null || true)
    if [[ -n "$cron_jobs" ]]; then
        echo "$cron_jobs" | while IFS= read -r line; do
            echo "  $line"
        done
    else
        echo "  (none)"
    fi
    echo ""

    # Kernel extensions
    log_header "--- Non-Apple Kernel Extensions ---"
    echo ""
    local kexts
    kexts=$(kextstat 2>/dev/null | grep -v "com.apple" | tail -n +2 || true)
    if [[ -n "$kexts" ]]; then
        echo "$kexts" | while IFS= read -r line; do
            local kext_id
            kext_id=$(echo "$line" | awk '{print $6}')
            echo "  $kext_id"
        done
    else
        echo "  (none)"
    fi
    echo ""

    local total=$(( found + sys_found + daemon_found ))
    log "Total non-Apple persistence items: $total"
    log "Review any entries you don't recognize."
    echo ""
}

cmd_permissions() {
    echo ""
    log_header "=== Permissions Audit (TCC) ==="
    echo ""
    log "Shows which apps have been granted sensitive permissions."
    log_dim "Reads from your user TCC database. Read-only, no changes."
    echo ""

    local tcc_db="$HOME/Library/Application Support/com.apple.TCC/TCC.db"

    if [[ ! -f "$tcc_db" ]]; then
        log "TCC database not found. Cannot read permissions."
        return 1
    fi

    # Helper to query TCC
    tcc_query() {
        local service="$1"
        local label="$2"
        local results
        results=$(sqlite3 "$tcc_db" \
            "SELECT client FROM access WHERE service='$service' AND auth_value=2;" 2>/dev/null || true)
        echo ""
        log "  $label:"
        if [[ -n "$results" ]]; then
            echo "$results" | while IFS= read -r app; do
                echo "    - $app"
            done
        else
            echo "    (none)"
        fi
    }

    tcc_query "kTCCServiceScreenCapture" "Screen Recording"
    tcc_query "kTCCServiceAccessibility" "Accessibility"
    tcc_query "kTCCServiceMicrophone" "Microphone"
    tcc_query "kTCCServiceCamera" "Camera"
    tcc_query "kTCCServiceSystemPolicyAllFiles" "Full Disk Access"
    tcc_query "kTCCServiceAppleEvents" "Automation (Apple Events)"

    echo ""
    log "Review any apps you don't recognize."
    log "Revoke permissions in System Settings > Privacy & Security."
    echo ""
}

cmd_purge() {
    log_header "Purging all macshield traces..."
    log ""

    local count=0

    # Logs
    for f in /tmp/macshield.stdout.log /tmp/macshield.stderr.log; do
        if [[ -f "$f" ]]; then
            rm -f "$f"
            log "  Deleted: $f"
            ((count++))
        fi
    done

    # Port scan report
    if [[ -f "$SCAN_REPORT" ]]; then
        rm -f "$SCAN_REPORT"
        log "  Deleted: $SCAN_REPORT"
        ((count++))
    fi

    # Audit report
    if [[ -f "$AUDIT_REPORT" ]]; then
        rm -f "$AUDIT_REPORT"
        log "  Deleted: $AUDIT_REPORT"
        ((count++))
    fi

    # State file
    if [[ -f "$STATE_FILE" ]]; then
        rm -f "$STATE_FILE"
        log "  Deleted: $STATE_FILE"
        ((count++))
    fi

    # Lock file
    if [[ -f "$LOCK_FILE" ]]; then
        rm -f "$LOCK_FILE"
        log "  Deleted: $LOCK_FILE"
        ((count++))
    fi

    if [[ $count -eq 0 ]]; then
        log "  Nothing to purge. Already clean."
    else
        log ""
        log "Purged $count file(s). Zero macshield traces on disk."
        log "macshield itself is still installed and functional."
    fi
}

cmd_version() {
    echo "macshield v${VERSION}"
}

cmd_help() {
    cat <<'HELP'
macshield - Network-aware macOS security hardening

Usage:
  macshield --check          Show current state (no changes)
  macshield --status         Alias for --check
  macshield trust            Add current WiFi network as trusted
  macshield trust --paranoid Remove all trusted networks, always harden
  macshield untrust          Remove current network from trusted list
  macshield harden           Manually harden now
  macshield relax            Manually relax (re-applies on next network change)
  macshield relax --for 2h   Temporarily relax for a duration (2h, 30m, 300s)
  macshield scan             Scan open ports (display only, nothing saved to disk)
  macshield scan --purge 5m  Scan, save report to disk, auto-delete after duration
  macshield purge            Delete all macshield logs, reports, and temp files

Optional security commands (not run by default):
  macshield audit            System security posture check (SIP, FileVault, etc.)
  macshield connections      Show active TCP connections (who your Mac talks to)
  macshield persistence      List non-Apple LaunchAgents, LaunchDaemons, login items
  macshield permissions      Show apps with sensitive permissions (camera, mic, etc.)

  macshield --install        Run the installer
  macshield --uninstall      Run the uninstaller
  macshield --version        Print version
  macshield --help           Print this help

What macshield protects:
  Untrusted network          Trusted network
  -----------------------    -----------------------
  Stealth mode ON            Stealth mode OFF
  Generic hostname           Personal hostname
  NetBIOS disabled           NetBIOS enabled

Trusted networks are stored as HMAC-SHA256 hashes in macOS Keychain.
No plaintext SSIDs are written to disk anywhere.

IMPORTANT: macshield changes your computer name on untrusted networks.
This affects AirDrop, Bluetooth, Terminal prompt, and Sharing preferences.
Your original name is restored on trusted networks.

macshield is NOT a VPN. It secures your local network identity (Layer 2),
reduces potential for malware (with Quad9 DNS), and avoids routing your
DNS through unknown public WiFi infrastructure. It does NOT encrypt
your traffic or make you anonymous.

DISCLAIMER: Provided as-is, without warranty. Modifies system settings
(firewall, hostname, network services). All changes are reversible.
You accept full responsibility. Full docs and limitations:
  https://github.com/qinnovates/macshield

https://github.com/qinnovates/macshield
HELP
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

require_macos

# First-run detection: if no sudoers and no trusted networks, prompt setup
if [[ "${1:-}" != "--trigger" && "${1:-}" != "setup" && "${1:-}" != "--install" && "${1:-}" != "--version" && "${1:-}" != "--uninstall" ]]; then
    if [[ ! -f "/etc/sudoers.d/macshield" ]] && ! security find-generic-password -s "com.macshield.trusted" &>/dev/null; then
        echo ""
        echo -e "${C_BOLD_YELLOW}[macshield]${C_RESET} ${C_YELLOW}Setup not complete.${C_RESET} Run ${C_BOLD}'macshield setup'${C_RESET} for interactive configuration."
        echo ""
    fi
fi

# Handle read-only commands before integrity check (safe without verification)
case "${1:-}" in
    --version) cmd_version; exit 0 ;;
    --help|-h|"") cmd_help; exit 0 ;;
esac

# Verify binary integrity before executing any system-modifying command
verify_integrity

case "${1:-}" in
    --trigger)
        cmd_trigger
        ;;
    --check|--status)
        cmd_check
        ;;
    trust)
        if [[ "${2:-}" == "--paranoid" ]]; then
            cmd_trust_paranoid
        else
            cmd_trust
        fi
        ;;
    untrust)
        cmd_untrust
        ;;
    harden)
        cmd_harden
        ;;
    relax)
        if [[ "${2:-}" == "--for" ]]; then
            [[ -z "${3:-}" ]] && die "Usage: macshield relax --for <duration> (e.g., 2h, 30m)"
            cmd_relax "$3"
        else
            cmd_relax
        fi
        ;;
    scan)
        if [[ "${2:-}" == "--purge" ]]; then
            [[ -z "${3:-}" ]] && die "Usage: macshield scan --purge <duration> (e.g., 5m, 1h)"
            cmd_scan "$3"
        elif [[ "${2:-}" == "--quiet" ]]; then
            cmd_scan "" "--quiet"
        else
            cmd_scan
        fi
        ;;
    audit)
        cmd_audit
        ;;
    connections)
        cmd_connections
        ;;
    persistence)
        cmd_persistence
        ;;
    permissions)
        cmd_permissions
        ;;
    purge)
        cmd_purge
        ;;
    setup|--install)
        cmd_install
        ;;
    --uninstall)
        cmd_uninstall
        ;;
    *)
        die "Unknown command: $1. Run 'macshield --help' for usage."
        ;;
esac
