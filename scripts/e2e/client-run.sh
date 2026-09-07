#!/bin/sh
set -e

KEY=$(cat "$WHISP_KEY_FILE")
LOG=/out/client.log
EVENTS=/out/events.csv

/app/whispera-go-client -key "$KEY" -server "$WHISP_SERVER" \
  -socks 0.0.0.0:1081 -no-tun -log-file "$LOG" >/out/client.stdout 2>&1 &
CLIENT_PID=$!

sleep 8

if [ -n "$FILLER_INTERVAL_MS" ]; then
  curl -s -m 3 -X POST -H 'Content-Type: application/json'     -d "{\"filler_idle_ms\":${FILLER_IDLE_MS:-400},\"filler_interval_ms\":$FILLER_INTERVAL_MS,\"filler_min\":${FILLER_MIN:-64},\"filler_max\":${FILLER_MAX:-1200}}"     http://127.0.0.1:10801/camo > /out/camo.json 2>&1 || true
  cat /out/camo.json
fi

echo "ts,probe_ms,http_code,pad_min,pad_max,action" > "$EVENTS"

PAD_MIN=111
PAD_MAX=1111
FAILS=0
START=$(date +%s)
END=$((START + RUN_SECONDS))

while [ "$(date +%s)" -lt "$END" ]; do
  T0=$(date +%s%3N)
  CODE=$(curl -s -o /dev/null -m 8 -x socks5h://127.0.0.1:1081 -w '%{http_code}' "$ORIGIN_URL" || true)
  [ -z "$CODE" ] && CODE=000
  T1=$(date +%s%3N)
  ACTION=""

  if [ "$CODE" = "200" ]; then
    FAILS=0
  else
    FAILS=$((FAILS + 1))
    if [ "$FAILS" -ge 2 ]; then
      PAD_MIN=$(( (PAD_MIN + 700) % 3000 + 32 ))
      PAD_MAX=$((PAD_MIN + 900))
      curl -s -m 3 -X POST -H 'Content-Type: application/json' \
        -d "{\"pad_min\":$PAD_MIN,\"pad_max\":$PAD_MAX}" \
        http://127.0.0.1:10801/camo >/dev/null 2>&1 || true
      ACTION="reshape"
      FAILS=0
    fi
  fi

  echo "$(date +%s),$((T1 - T0)),$CODE,$PAD_MIN,$PAD_MAX,$ACTION" >> "$EVENTS"
  sleep "$PROBE_EVERY"
done

kill $CLIENT_PID 2>/dev/null || true
echo "done" > /out/client.finished
