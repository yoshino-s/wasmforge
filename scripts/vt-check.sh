#!/bin/bash
# vt-check.sh — Check VirusTotal results for previously scanned files by hash.
#
# Usage:
#   VT_API_KEY=xxx ./scripts/vt-check.sh file1.exe file2.exe ...
#   VT_API_KEY=xxx ./scripts/vt-check.sh --hash <sha256>
#
# Looks up existing reports without re-uploading. Use vt-scan.sh to upload.

set -euo pipefail

if [ -z "${VT_API_KEY:-}" ]; then
  echo "ERROR: VT_API_KEY not set."
  exit 1
fi

if [ $# -eq 0 ]; then
  echo "Usage: $0 file1.exe [file2.exe ...]"
  echo "       $0 --hash <sha256>"
  exit 1
fi

API="https://www.virustotal.com/api/v3"
RATE_SLEEP=16

check_hash() {
  local HASH="$1"
  local LABEL="$2"

  REPORT=$(curl -s --request GET \
    --url "$API/files/$HASH" \
    --header "x-apikey: $VT_API_KEY")

  ERROR=$(echo "$REPORT" | jq -r '.error.code // empty')
  if [ -n "$ERROR" ]; then
    echo "  NOT FOUND on VT (needs upload)"
    return
  fi

  MALICIOUS=$(echo "$REPORT" | jq '.data.attributes.last_analysis_stats.malicious // 0')
  SUSPICIOUS=$(echo "$REPORT" | jq '.data.attributes.last_analysis_stats.suspicious // 0')
  UNDETECTED=$(echo "$REPORT" | jq '.data.attributes.last_analysis_stats.undetected // 0')
  TOTAL=$((MALICIOUS + SUSPICIOUS + UNDETECTED))

  echo "  Detections: $MALICIOUS/$TOTAL malicious, $SUSPICIOUS suspicious"

  # List detecting engines
  ENGINES=$(echo "$REPORT" | jq -r '
    .data.attributes.last_analysis_results | to_entries[] |
    select(.value.category == "malicious" or .value.category == "suspicious") |
    "    \(.key): \(.value.result)"
  ')

  if [ -z "$ENGINES" ]; then
    echo "    (clean — no detections)"
  else
    echo "$ENGINES"
  fi
}

if [ "$1" = "--hash" ]; then
  shift
  for HASH in "$@"; do
    echo "=== Hash: ${HASH:0:16}... ==="
    check_hash "$HASH" "$HASH"
    sleep "$RATE_SLEEP"
  done
else
  for FILE in "$@"; do
    if [ ! -f "$FILE" ]; then
      echo "SKIP: $FILE (not found)"
      continue
    fi
    BASENAME=$(basename "$FILE")
    SHA256=$(shasum -a 256 "$FILE" | awk '{print $1}')
    echo "=== $BASENAME (${SHA256:0:16}...) ==="
    check_hash "$SHA256" "$BASENAME"
    sleep "$RATE_SLEEP"
  done
fi
