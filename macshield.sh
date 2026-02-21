#!/usr/bin/env bash
# macshield - Network-aware macOS security hardening
# https://github.com/qinnovates/macshield
# License: Apache 2.0

set -euo pipefail

VERSION="0.1.0"
KEYCHAIN_SERVICE="com.macshield.trusted"
KEYCHAIN_HOSTNAME="com.macshield.hostname"
STATE_FILE="/tmp/macshield.state"
LOCK_FILE="/tmp/macshield.lock"
SETTLE_DELAY=2

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() {
    echo "[macshield] $*"
}

die() {
    echo "[macshield] ERROR: $*" >&2
    exit 1
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
    echo "$1" > "$STATE_FILE"
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
    log "Applying protections:"

    # 1. Stealth mode
    log "  [1/3] Enabling stealth mode (blocks ICMP pings and port scans)"
    log "        Running: sudo socketfilterfw --setstealthmode on"
    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on >/dev/null 2>&1
    log "        Done."

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

    log "  [2/3] Setting hostname to generic \"$generic_display\" (hides identity on local network)"
    log "        Running: sudo scutil --set ComputerName \"$generic_display\""
    sudo /usr/sbin/scutil --set ComputerName "$generic_display"
    log "        Running: sudo scutil --set LocalHostName \"$generic_host\""
    sudo /usr/sbin/scutil --set LocalHostName "$generic_host"
    log "        Running: sudo scutil --set HostName \"$generic_host\""
    sudo /usr/sbin/scutil --set HostName "$generic_host"
    log "        Done."

    # 3. NetBIOS
    log "  [3/3] Disabling NetBIOS (closes ports 137/138, stops name broadcast)"
    log "        Running: sudo launchctl bootout system/com.apple.netbiosd"
    if sudo /bin/launchctl bootout system/com.apple.netbiosd 2>/dev/null; then
        log "        Done."
    else
        log "        Note: NetBIOS daemon was already stopped or is SIP-protected."
    fi

    set_state "hardened"
    log ""
    log "All protections active. Your Mac is hardened."
}

do_relax() {
    local current_state
    current_state=$(get_state)

    if [[ "$current_state" == "relaxed" ]]; then
        log "Already relaxed. No changes needed."
        return 0
    fi

    log ""
    log "Relaxing protections:"

    # 1. Stealth mode off
    log "  [1/3] Disabling stealth mode (AirDrop, Spotify Connect, etc. will work)"
    log "        Running: sudo socketfilterfw --setstealthmode off"
    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off >/dev/null 2>&1
    log "        Done."

    # 2. Restore personal hostname
    local personal_name
    personal_name=$(keychain_get_hostname)
    if [[ -n "$personal_name" ]]; then
        local personal_host="${personal_name// /-}"
        # Remove characters invalid for LocalHostName (only alphanumeric and hyphens)
        personal_host=$(echo "$personal_host" | sed "s/[^a-zA-Z0-9-]//g")

        log "  [2/3] Restoring personal hostname \"$personal_name\""
        log "        Running: sudo scutil --set ComputerName \"$personal_name\""
        sudo /usr/sbin/scutil --set ComputerName "$personal_name"
        log "        Running: sudo scutil --set LocalHostName \"$personal_host\""
        sudo /usr/sbin/scutil --set LocalHostName "$personal_host"
        log "        Running: sudo scutil --set HostName \"$personal_host\""
        sudo /usr/sbin/scutil --set HostName "$personal_host"
        log "        Done."
    else
        log "  [2/3] No personal hostname stored in Keychain. Skipping."
    fi

    # 3. NetBIOS back on
    log "  [3/3] Re-enabling NetBIOS"
    log "        Running: sudo launchctl enable system/com.apple.netbiosd"
    sudo /bin/launchctl enable system/com.apple.netbiosd 2>/dev/null || true
    log "        Running: sudo launchctl kickstart system/com.apple.netbiosd"
    if sudo /bin/launchctl kickstart system/com.apple.netbiosd 2>/dev/null; then
        log "        Done."
    else
        log "        Note: NetBIOS daemon could not be started (may be SIP-protected)."
    fi

    set_state "relaxed"
    log ""
    log "Protections relaxed. Full network functionality restored."
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

    log "Network change detected"

    local ssid
    if ! ssid=$(get_current_ssid); then
        log "No WiFi connection detected. Defaulting to hardened mode."
        do_harden
        return
    fi

    log "Current SSID: (hidden from logs)"
    log "Computing network fingerprint..."

    local hash
    hash=$(compute_hmac "$ssid")

    log "Checking trusted networks in Keychain..."

    if keychain_is_trusted "$hash"; then
        log "Result: TRUSTED network"
        do_relax
    else
        log "Result: UNTRUSTED network"
        do_harden
    fi
}

cmd_check() {
    log "macshield v${VERSION}"
    log ""

    # Current state
    local state
    state=$(get_state)
    log "Current state: $state"

    # WiFi info
    local ssid
    if ssid=$(get_current_ssid); then
        log "WiFi connected: yes"

        local hash
        hash=$(compute_hmac "$ssid")
        if keychain_is_trusted "$hash"; then
            log "Network trust: TRUSTED"
        else
            log "Network trust: UNTRUSTED"
        fi
    else
        log "WiFi connected: no"
    fi

    # Stealth mode
    local stealth
    stealth=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null || echo "unknown")
    log "Stealth mode: $stealth"

    # Hostname
    local hostname
    hostname=$(scutil --get ComputerName 2>/dev/null || echo "unknown")
    log "Hostname: $hostname"

    local generic
    generic=$(get_generic_display_name)
    if [[ "$hostname" == "$generic" ]]; then
        log "Hostname type: generic (hardened)"
    else
        log "Hostname type: personal"
    fi

    # Stored personal hostname
    local stored
    stored=$(keychain_get_hostname)
    if [[ -n "$stored" ]]; then
        log "Stored personal hostname: $stored"
    else
        log "Stored personal hostname: (none)"
    fi

    # LaunchAgent
    if [[ -f "$HOME/Library/LaunchAgents/com.qinnovates.macshield.plist" ]]; then
        log "LaunchAgent: installed"
    else
        log "LaunchAgent: not installed"
    fi

    # Sudoers
    if [[ -f "/etc/sudoers.d/macshield" ]]; then
        log "Sudoers fragment: installed"
    else
        log "Sudoers fragment: not installed"
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
    log "Network added to trusted list."
    log "Fingerprint stored in Keychain (HMAC hash, not SSID)."

    # If currently hardened, relax now
    if [[ "$(get_state)" == "hardened" ]]; then
        log "Relaxing protections for trusted network..."
        do_relax
    fi
}

cmd_trust_paranoid() {
    # Remove all trusted networks
    keychain_clear_all
    log "Paranoid mode: all trusted networks removed."
    log "macshield will treat ALL networks as untrusted."
    log "Use 'macshield relax' to manually relax (expires on disconnect)."
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
    log "Network removed from trusted list."

    # Harden if we're currently relaxed
    if [[ "$(get_state)" == "relaxed" ]]; then
        log "Hardening for untrusted network..."
        do_harden
    fi
}

cmd_relax() {
    local duration="${1:-}"

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
    log "Manually hardening..."
    do_harden
}

cmd_install() {
    exec bash "$(dirname "$0")/install.sh"
}

cmd_uninstall() {
    exec bash "$(dirname "$0")/uninstall.sh"
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

https://github.com/qinnovates/macshield
HELP
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

require_macos

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
    --install)
        cmd_install
        ;;
    --uninstall)
        cmd_uninstall
        ;;
    --version)
        cmd_version
        ;;
    --help|-h|"")
        cmd_help
        ;;
    *)
        die "Unknown command: $1. Run 'macshield --help' for usage."
        ;;
esac
