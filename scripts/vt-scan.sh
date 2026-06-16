#!/bin/bash
# vt-scan.sh — Upload files to VirusTotal and poll for detection results.
#
# Usage:
#   VT_API_KEY=xxx ./scripts/vt-scan.sh file1.exe file2.exe ...
#
# Environment:
#   VT_API_KEY  — Required. VirusTotal API v3 key.
#
# Output:
#   Summary table of detections per file.
#   Raw JSON results saved to /tmp/vt-results-<timestamp>/

set -euo pipefail

if [ -z "${VT_API_KEY:-}" ]; then
  echo "ERROR: VT_API_KEY not set."
  echo "  export VT_API_KEY='your-api-key-here'"
  exit 1
fi

if [ $# -eq 0 ]; then
  echo "Usage: $0 file1.exe [file2.exe ...]"
  exit 1
fi

command -v jq >/dev/null 2>&1 || { echo "ERROR: jq required but not found."; exit 1; }

RESULTS_DIR="/tmp/vt-results-$(date +%s)"
mkdir -p "$RESULTS_DIR"
PENDING="$RESULTS_DIR/pending.txt"
COMPLETED="$RESULTS_DIR/completed.txt"
touch "$PENDING" "$COMPLETED"

API="https://www.virustotal.com/api/v3"
RATE_SLEEP=16  # stay safely under 4 req/min

echo "=== VirusTotal Batch Scanner ==="
echo "Results dir: $RESULTS_DIR"
echo ""

# ── Upload phase ──────────────────────────────────────────────
for FILE in "$@"; do
  if [ ! -f "$FILE" ]; then
    echo "SKIP: $FILE (not found)"
    continue
  fi

  BASENAME=$(basename "$FILE")
  FILE_SIZE=$(stat -f%z "$FILE" 2>/dev/null || stat -c%s "$FILE" 2>/dev/null)
  FILE_MB=$(echo "scale=1; $FILE_SIZE / 1048576" | bc)
  SHA256=$(shasum -a 256 "$FILE" | awk '{print $1}')

  echo "Uploading: $BASENAME (${FILE_MB}MB, sha256=${SHA256:0:16}...)"

  # Large files (>32MB) need a special upload URL
  if [ "$FILE_SIZE" -gt 33554432 ]; then
    UPLOAD_URL=$(curl -s --request GET \
      --url "$API/files/upload_url" \
      --header "x-apikey: $VT_API_KEY" | jq -r '.data')
    sleep "$RATE_SLEEP"
  else
    UPLOAD_URL="$API/files"
  fi

  RESPONSE=$(curl -s --request POST \
    --url "$UPLOAD_URL" \
    --header "x-apikey: $VT_API_KEY" \
    --form "file=@$FILE")

  ANALYSIS_ID=$(echo "$RESPONSE" | jq -r '.data.id // empty')
  if [ -z "$ANALYSIS_ID" ]; then
    ERROR=$(echo "$RESPONSE" | jq -r '.error.code // "unknown"')
    echo "  FAILED: $ERROR"
    echo "$BASENAME|FAILED|0|0|Upload error: $ERROR" >> "$COMPLETED"
    sleep "$RATE_SLEEP"
    continue
  fi

  echo "  Analysis ID: ${ANALYSIS_ID:0:32}..."
  echo "$ANALYSIS_ID $SHA256 $BASENAME" >> "$PENDING"
  sleep "$RATE_SLEEP"
done

PENDING_COUNT=$(wc -l < "$PENDING" | tr -d ' ')
if [ "$PENDING_COUNT" -eq 0 ]; then
  echo "No files uploaded successfully."
  exit 1
fi

echo ""
echo "=== Uploaded $PENDING_COUNT files. Waiting for analyses... ==="
echo ""

# ── Poll phase ────────────────────────────────────────────────
# Initial wait — VT typically needs 1-3 minutes
sleep 45

MAX_ATTEMPTS=30  # 30 * 16s = ~8 minutes max per file

while IFS=' ' read -r AID SHA NAME; do
  echo "Checking: $NAME"

  for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
    RESULT=$(curl -s --request GET \
      --url "$API/analyses/$AID" \
      --header "x-apikey: $VT_API_KEY")

    STATUS=$(echo "$RESULT" | jq -r '.data.attributes.status')

    if [ "$STATUS" = "completed" ]; then
      # Save raw JSON
      echo "$RESULT" > "$RESULTS_DIR/$NAME.json"

      MALICIOUS=$(echo "$RESULT" | jq '.data.attributes.stats.malicious // 0')
      SUSPICIOUS=$(echo "$RESULT" | jq '.data.attributes.stats.suspicious // 0')
      UNDETECTED=$(echo "$RESULT" | jq '.data.attributes.stats.undetected // 0')
      TOTAL=$((MALICIOUS + SUSPICIOUS + UNDETECTED))

      # Extract detecting engines
      ENGINES=$(echo "$RESULT" | jq -r '
        .data.attributes.results | to_entries[] |
        select(.value.category == "malicious" or .value.category == "suspicious") |
        "\(.key) \(.value.result)"
      ')

      if [ -z "$ENGINES" ]; then
        ENGINE_STR="(clean)"
      else
        ENGINE_STR=$(echo "$ENGINES" | while read -r eng det; do
          echo "$eng: $det"
        done | paste -sd '; ' -)
      fi

      echo "  $MALICIOUS/$TOTAL malicious, $SUSPICIOUS suspicious"
      echo "$NAME|$MALICIOUS/$TOTAL|$SUSPICIOUS|$UNDETECTED|$ENGINE_STR" >> "$COMPLETED"
      break
    fi

    if [ "$attempt" -eq "$MAX_ATTEMPTS" ]; then
      echo "  TIMEOUT after $MAX_ATTEMPTS attempts"
      echo "$NAME|TIMEOUT|0|0|Analysis did not complete" >> "$COMPLETED"
      break
    fi

    echo "  Status: $STATUS (attempt $attempt/$MAX_ATTEMPTS)"
    sleep "$RATE_SLEEP"
  done

  sleep "$RATE_SLEEP"
done < "$PENDING"

# ── Summary ───────────────────────────────────────────────────
echo ""
echo "=== RESULTS ==="
echo ""
printf "| %-28s | %-7s | %-3s | %-s\n" "File" "Det" "Sus" "Detecting Engines"
printf "| %-28s | %-7s | %-3s | %-s\n" "----------------------------" "-------" "---" "-----------------"

while IFS='|' read -r NAME MAL SUS UND ENGINES; do
  printf "| %-28s | %-7s | %-3s | %s\n" "$NAME" "$MAL" "$SUS" "$ENGINES"
done < "$COMPLETED"

echo ""
echo "Raw JSON: $RESULTS_DIR/"
echo "Done."
