#!/bin/sh
set -e

# Ordinary traffic through the same censor: system TLS, no tunnel, no uTLS
# preset. It exists so the censor has something to be wrong about. A rule that
# bans these is a rule a real operator would have to withdraw, which is what
# keeps real blocking selective.

ID=1
i=1
while [ "$i" -le "${LEGIT_USERS:-1}" ]; do
  if mkdir "/cfg/legit-slot-$i" 2>/dev/null; then
    ID=$i
    break
  fi
  i=$((i + 1))
done

OUT="/out/legit-$ID.csv"
echo "ts,http_code,ms" > "$OUT"

START=$(date +%s)
END=$((START + ${RUN_SECONDS:-120}))

while [ "$(date +%s)" -lt "$END" ]; do
  R=$(curl -s -o /dev/null -m 8 -k -w '%{http_code} %{time_total}' "$LEGIT_URL" || true)
  CODE=${R%% *}
  [ -z "$CODE" ] && CODE=000
  MS=$(echo "${R##* }" | awk '{printf "%.0f", $1 * 1000}')
  echo "$(date +%s),$CODE,${MS:-0}" >> "$OUT"
  sleep "${LEGIT_EVERY:-1}"
done

echo "done" > "/out/legit-$ID.finished"
