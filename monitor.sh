#!/usr/bin/env bash
# monitor.sh - Sanitized firewall log extractor for Shield Dashboard
# Exports real-time socketfilterfw events to JSON for the UI.
# Status: Alpha. Not production-ready.

set -euo pipefail

UI_DATA_DIR="$(dirname "$0")/ui/public/data"
mkdir -p "$UI_DATA_DIR"
JSON_FILE="$UI_DATA_DIR/firewall_events.json"

# Initialize empty JSON array if not exists
if [[ ! -f "$JSON_FILE" ]]; then
    echo "[]" > "$JSON_FILE"
fi

echo "Shield Dashboard Monitor started..."
echo "Polling macOS log stream for socketfilterfw events..."

# Escape a string for safe JSON embedding
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

# Use log stream to capture Application Firewall events
# Predicate focuses on socketfilterfw blocks/allows
log stream --predicate 'process == "socketfilterfw"' --style json | while read -r line; do
    # Skip non-JSON lines (metadata/headers)
    [[ "$line" != "{"* ]] && continue

    # Extract event data
    TIMESTAMP=$(echo "$line" | grep -o '"timestamp":"[^"]*"' | cut -d'"' -f4 || echo "unknown")
    MESSAGE=$(echo "$line" | grep -o '"eventMessage":"[^"]*"' | cut -d'"' -f4 || echo "unknown")

    # SANITIZATION: Strip specific IPs and hostnames for privacy
    SAFE_MESSAGE=$(echo "$MESSAGE" | sed -E 's/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[IP_REDACTED]/g')

    # Escape for safe JSON embedding
    SAFE_TIMESTAMP=$(json_escape "$TIMESTAMP")
    SAFE_MESSAGE=$(json_escape "$SAFE_MESSAGE")

    # Build event JSON with escaped values
    EVENT_JSON="{\"timestamp\":\"$SAFE_TIMESTAMP\",\"event\":\"$SAFE_MESSAGE\"}"

    # Update the JSON file (bounded to 50 events)
    (
        echo "["
        echo "  $EVENT_JSON,"
        sed '1d;$d' "$JSON_FILE" | head -n 49
        echo "]"
    ) > "${JSON_FILE}.tmp" && mv "${JSON_FILE}.tmp" "$JSON_FILE"

done
