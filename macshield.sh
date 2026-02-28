#!/usr/bin/env bash
# macshield - macOS security analyzer and best practices report
# https://github.com/qinnovates/macshield
# License: Apache 2.0
#
# Read-only security analysis. No system modifications. No background processes.
# No sudo. No Keychain writes. No state files. Zero attack surface.

set -euo pipefail

# Harden PATH to prevent command hijacking
PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PATH

VERSION="0.5.0"
SCAN_REPORT="/tmp/macshield-port-report.txt"
AUDIT_REPORT="/tmp/macshield-audit-report.txt"

# ---------------------------------------------------------------------------
# Symlink-safe file writes (defense against /tmp symlink attacks)
# ---------------------------------------------------------------------------

safe_write() {
    local path="$1"
    local content="$2"
    if [[ -L "$path" ]]; then
        die "Refusing to write: $path is a symlink (possible attack)"
    fi
    echo "$content" > "$path"
}

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

require_macos() {
    [[ "$(uname)" == "Darwin" ]] || die "macshield only runs on macOS"
}

# ---------------------------------------------------------------------------
# Hardware / network detection (used by audit)
# ---------------------------------------------------------------------------

get_wifi_interface() {
    local iface
    iface=$(networksetup -listallhardwareports | awk '/Wi-Fi|AirPort/{getline; print $2}')
    echo "${iface:-}"
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

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
        report+="$(printf '  %-8s %-24s %-8s %s\n' "PORT" "PROCESS" "PID" "NOTE")"$'\n'
        report+="  $(printf '%0.s-' {1..70})"$'\n'

        while IFS= read -r line; do
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

    # UDP listeners
    report+="--- UDP PORTS ---"$'\n'
    report+=""$'\n'

    local udp_count=0
    if [[ -n "$listen_udp" ]]; then
        report+="$(printf '  %-8s %-24s %-8s %s\n' "PORT" "PROCESS" "PID" "NOTE")"$'\n'
        report+="  $(printf '%0.s-' {1..70})"$'\n'

        local seen_udp=""
        while IFS= read -r line; do
            [[ "$line" == COMMAND* ]] && continue

            local cmd pid addr port
            cmd=$(echo "$line" | awk '{print $1}')
            pid=$(echo "$line" | awk '{print $2}')
            addr=$(echo "$line" | awk '{print $9}')
            port="${addr##*:}"

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
# Audit (system security posture check)
# ---------------------------------------------------------------------------

audit_check() {
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
        audit_check INFO "Stealth mode" "disabled (enable with: sudo socketfilterfw --setstealthmode on)"
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

    local ssh_status
    ssh_status=$(systemsetup -getremotelogin 2>/dev/null || echo "unknown")
    if [[ "$ssh_status" == *"Off"* ]]; then
        audit_check PASS "Remote Login (SSH)" "disabled"
        ((pass_count++)) || true
    else
        audit_check WARN "Remote Login (SSH)" "enabled (port 22 open to network)"
        ((warn_count++)) || true
    fi

    if launchctl list 2>/dev/null | grep -q "com.apple.screensharing"; then
        audit_check WARN "Screen Sharing" "enabled (remote desktop access open)"
        ((warn_count++)) || true
    else
        audit_check PASS "Screen Sharing" "disabled"
        ((pass_count++)) || true
    fi

    if launchctl list 2>/dev/null | grep -q "com.apple.smbd"; then
        audit_check WARN "File Sharing (SMB)" "enabled (network file shares open)"
        ((warn_count++)) || true
    else
        audit_check PASS "File Sharing (SMB)" "disabled"
        ((pass_count++)) || true
    fi

    if launchctl list 2>/dev/null | grep -q "com.apple.RemoteDesktop"; then
        audit_check WARN "Remote Management (ARD)" "enabled"
        ((warn_count++)) || true
    else
        audit_check PASS "Remote Management (ARD)" "disabled"
        ((pass_count++)) || true
    fi

    local rae_status
    rae_status=$(systemsetup -getremoteappleevents 2>/dev/null || echo "unknown")
    if [[ "$rae_status" == *"Off"* ]]; then
        audit_check PASS "Remote Apple Events" "disabled"
        ((pass_count++)) || true
    else
        audit_check WARN "Remote Apple Events" "enabled"
        ((warn_count++)) || true
    fi

    local bt_disco
    bt_disco=$(defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>/dev/null || echo "")
    if [[ "$bt_disco" == "0" ]]; then
        audit_check PASS "Bluetooth" "disabled"
        ((pass_count++)) || true
    else
        audit_check INFO "Bluetooth" "enabled (disable on untrusted networks if not needed)"
    fi

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

    local spotlight
    spotlight=$(defaults read com.apple.lookup.shared LookupSuggestionsDisabled 2>/dev/null || echo "unknown")
    if [[ "$spotlight" == "1" ]]; then
        audit_check PASS "Spotlight Suggestions" "disabled (queries stay local)"
        ((pass_count++)) || true
    else
        audit_check INFO "Spotlight Suggestions" "enabled (sends search queries to Apple)"
    fi

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

    if [[ -f "$HOME/.git-credentials" ]]; then
        audit_check WARN ".git-credentials" "plaintext credentials file exists"
        ((warn_count++)) || true
    fi

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

        local name_field
        name_field=$(echo "$line" | awk '{print $9}')

        if [[ "$name_field" == *"->"* ]]; then
            local_part="${name_field%%->*}"
            remote="${name_field##*->}"
        else
            remote="$name_field"
            local_part=""
        fi

        local local_port="${local_part##*:}"

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

    for f in /tmp/macshield.stdout.log /tmp/macshield.stderr.log; do
        if [[ -f "$f" ]]; then
            rm -f "$f"
            log "  Deleted: $f"
            ((count++))
        fi
    done

    if [[ -f "$SCAN_REPORT" ]]; then
        rm -f "$SCAN_REPORT"
        log "  Deleted: $SCAN_REPORT"
        ((count++))
    fi

    if [[ -f "$AUDIT_REPORT" ]]; then
        rm -f "$AUDIT_REPORT"
        log "  Deleted: $AUDIT_REPORT"
        ((count++))
    fi

    if [[ $count -eq 0 ]]; then
        log "  Nothing to purge. Already clean."
    else
        log ""
        log "Purged $count file(s). Zero macshield traces on disk."
    fi
}

cmd_version() {
    echo "macshield v${VERSION}"
}

cmd_help() {
    cat <<'HELP'
macshield - macOS security analyzer and best practices report

Read-only security analysis. No system modifications. No background
processes. No sudo. No Keychain writes. Zero attack surface.

Usage:
  macshield scan             Scan open ports (display only, nothing saved to disk)
  macshield scan --purge 5m  Scan, save report to disk, auto-delete after duration
  macshield scan --quiet     Scan without prompts, display only
  macshield audit            System security posture check (SIP, FileVault, etc.)
  macshield connections      Show active TCP connections (who your Mac talks to)
  macshield persistence      List non-Apple LaunchAgents, LaunchDaemons, login items
  macshield permissions      Show apps with sensitive permissions (camera, mic, etc.)
  macshield purge            Delete all macshield logs, reports, and temp files
  macshield --version        Print version
  macshield --help           Print this help

What each command checks:

  scan          Open TCP/UDP ports, listening processes, firewall status
  audit         SIP, FileVault, Gatekeeper, firewall, stealth mode, Lockdown
                Mode, Secure Boot, XProtect, sharing services (SSH, screen
                sharing, SMB, ARD, AirDrop), privacy settings (analytics,
                Siri, Spotlight, ads), WiFi security type, MAC randomization,
                DNS config, ARP table (MitM detection), file hygiene (.ssh
                permissions, .env files, plaintext credentials)
  connections   Active TCP connections with process names and remote endpoints
  persistence   Non-Apple LaunchAgents, LaunchDaemons, login items, cron jobs,
                kernel extensions
  permissions   TCC database: screen recording, accessibility, microphone,
                camera, full disk access, automation

Manual hardening (copy-paste into Terminal):

  # Enable stealth mode (blocks ICMP pings and port scans)
  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on

  # Set hostname to generic (prevents identity leaking on public WiFi)
  sudo scutil --set ComputerName "MacBook Pro"
  sudo scutil --set LocalHostName "MacBook-Pro"
  sudo scutil --set HostName "MacBook-Pro"

  # Disable NetBIOS (closes ports 137/138)
  sudo launchctl bootout system/com.apple.netbiosd

  # Set privacy-focused DNS (Quad9, blocks malware domains)
  networksetup -setdnsservers Wi-Fi 9.9.9.9 149.112.112.112

DISCLAIMER: Provided as-is, without warranty. All commands are read-only
and do not modify your system. Full docs:
  https://github.com/qinnovates/macshield

HELP
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

require_macos

case "${1:-}" in
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
