#!/bin/sh
# seal.sh — append one seal to a sealed-record (SPEC.md v1).
#
#   seal.sh <record>.seals <private-key>
#
# Hashes the record as it stands, appends a seal line, signs it with
# ssh-keygen -Y, and stamps it with ots if ots is installed (else says so).
# Assumes the seals file already has its header and blank line. Refuses
# to seal if the record has not grown since the last seal (a check is
# not a seal — see SPEC.md, Exclusions).
set -eu
SEALS=$1; KEY=$2
DIR=$(dirname "$SEALS"); cd "$DIR"; SEALS=$(basename "$SEALS")
RECORD=$(sed -n 's/^record: *//p' "$SEALS" | head -1)
[ -n "$RECORD" ] || { echo "no record: header" >&2; exit 2; }
[ -f "$RECORD" ] || { echo "record $RECORD not found" >&2; exit 2; }
LEN=$(wc -c < "$RECORD" | tr -d ' ')
HASH=$(head -c "$LEN" "$RECORD" | sha256sum | cut -d' ' -f1)
LAST=$(grep '^seal ' "$SEALS" | tail -1 || true)
if [ -n "$LAST" ]; then
  N=$(( $(echo "$LAST" | cut -d' ' -f2) + 1 ))
  PREVLEN=$(echo "$LAST" | cut -d' ' -f4)
  [ "$LEN" -gt "$PREVLEN" ] || { echo "record has not grown since seal $((N-1)) ($PREVLEN bytes); not sealing" >&2; exit 3; }
  PREV=$(printf '%s\n' "$LAST" | sha256sum | cut -d' ' -f1)
else
  N=1; PREV=-
fi
AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
LINE="seal $N bytes $LEN sha256 $HASH prev $PREV at $AT"
mkdir -p seals
printf '%s\n' "$LINE" > "seals/$N.line"
ssh-keygen -Y sign -f "$KEY" -n sealed-record-v1 "seals/$N.line" >/dev/null 2>&1
mv "seals/$N.line.sig" "seals/$N.sig"
if command -v ots >/dev/null 2>&1; then
  ots stamp "seals/$N.line" && mv "seals/$N.line.ots" "seals/$N.ots"
else
  echo "ots not installed: seal $N has no timestamp proof (verifier will say 'absent')" >&2
fi
rm "seals/$N.line"
printf '%s\n' "$LINE" >> "$SEALS"
echo "$LINE"
