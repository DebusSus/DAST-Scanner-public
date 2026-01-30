set -euo pipefail

API="http://localhost:8080/scan"

# ---- Helper: pretty print JSON response ----
jq_pretty() {
  if command -v jq >/dev/null; then
    jq .
  else
    cat
  fi
}

# ---- 1. Ask for target -------------------------------------------------
echo "=== DAST Scan Launcher ==="
read -rp "Target URL (e.g. https://www.example.com ; http://host.docker.internal): " TARGET
TARGET="$(echo "$TARGET" | xargs)"

if [[ -z "$TARGET" ]]; then
  echo "Error: Target cannot be empty." >&2
  exit 1
fi

if [[ ! "$TARGET" =~ [](http://|https://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$ ]]; then
  echo "Error: Invalid target format. Use https://www.example.com or similar." >&2
  exit 1
fi

# ---- 2. Auto-mode? ----------------------------------------------------
while true; do
  read -rp "Use auto-mode (WhatWeb + default scanners)? [Y/n]: " AUTO
  AUTO="${AUTO:-Y}"
  case "${AUTO,,}" in
    y|yes|"") AUTO_MODE=true; break ;;
    n|no)    AUTO_MODE=false; break ;;
    *) echo "Please answer Y or N." ;;
  esac
done

# ---- 3. If not auto-mode → pick scanners ------------------------------
SCANNERS_JSON=""
if $AUTO_MODE; then
  SCANNERS_JSON='"all"'
else
  echo "Fetching scanner list from API..."
  SCANNER_LIST=$(curl -s "$API/../scanners" | jq_pretty | grep -E '"scanners"' -A 20 || true)

  if [[ -z "$SCANNER_LIST" ]]; then
    echo "Warning: Could not fetch scanner list – falling back to hard-coded list."
    MAPFILE=(whatweb testssl wpscan droopescan joomscan nikto nuclei zap)
  else
    MAPFILE=($(echo "$SCANNER_LIST" | jq -r '.scanners[]'))
  fi

  echo ""
  echo "Available scanners (enter numbers separated by space/comma, e.g. 1 3,5):"
  for i in "${!MAPFILE[@]}"; do
    printf "  %2d) %s\n" $((i+1)) "${MAPFILE[i]}"
  done
  echo ""

  read -rp "Your choice: " CHOICE
  CHOICE="$(echo "$CHOICE" | tr ', ' '\n' | sort -u)"
  SELECTED=()
  for num in $CHOICE; do
    idx=$((num-1))
    if (( idx >= 0 && idx < ${#MAPFILE[@]} )); then
      SELECTED+=("${MAPFILE[idx]}")
    else
      echo "Warning: Ignoring invalid number: $num"
    fi
  done

  if (( ${#SELECTED[@]} == 0 )); then
    echo "Error: No valid scanners selected." >&2
    exit 1
  fi

  SCANNERS_JSON=$(printf '%s\n' "${SELECTED[@]}" | jq -R . | jq -s .)
fi

# ---- 4. Build payload --------------------------------------------------
PAYLOAD=$(cat <<EOF
{
  "target": "$TARGET",
  "scanners": $SCANNERS_JSON
}
EOF
)

# ---- 5. Start scan ----------------------------------------------------
echo ""
echo "Starting scan..."
RESPONSE=$(curl -s -X POST "$API" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

JOB_ID=$(echo "$RESPONSE" | jq -r .job_id)

if [[ -z "$JOB_ID" || "$JOB_ID" == "null" ]]; then
  echo "Error: Failed to start scan."
  echo "$RESPONSE" | jq_pretty
  exit 1
fi

# ---- 6. Show result ----------------------------------------------------
echo ""
echo "Scan started!"
echo "   Job ID : $JOB_ID"
echo ""
echo "To watch live logs, run:"
echo "   curl -s \"http://localhost:8080/scan/$JOB_ID?tail=2000\" | jq ."
echo ""
echo "When the scan finishes, download the report with:"
echo "   curl -O \"http://localhost:8080/reports/$JOB_ID.json\""
echo "   # or markdown:"
echo "   curl \"http://localhost:8080/scan/$JOB_ID?format=md\""

exit 0