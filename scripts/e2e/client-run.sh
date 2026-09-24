#!/bin/sh
set -e

# Every replica gets the same hostname shape, so the index cannot be read off
# it. It is claimed instead: mkdir on the shared volume is atomic, and only one
# replica can win a given slot.
ID=1
i=1
while [ "$i" -le "${USERS:-1}" ]; do
  if mkdir "/cfg/slot-$i" 2>/dev/null; then
    ID=$i
    break
  fi
  i=$((i + 1))
done

KEY_FILE="/cfg/key-$ID.txt"
[ -f "$KEY_FILE" ] || KEY_FILE="$WHISP_KEY_FILE"
KEY=$(cat "$KEY_FILE")
LOG="/out/client-$ID.log"
EVENTS="/out/events-$ID.csv"
CONCURRENCY="${CONCURRENCY:-1}"

if [ -n "$WHISPERA_DIAL_TRACE" ]; then
  WHISPERA_DIAL_TRACE="${WHISPERA_DIAL_TRACE%.csv}-$ID.csv"
  export WHISPERA_DIAL_TRACE
fi

/app/whispera-go-client -key "$KEY" -server "$WHISP_SERVER" \
  ${WHISP_FP:+-force-fingerprint $WHISP_FP} \
  ${WHISP_FRAG_COUNT:+-tls-fragment-count $WHISP_FRAG_COUNT} \
  ${WHISP_HELLO_FRAG:+-hello-frag=$WHISP_HELLO_FRAG} \
  -socks 0.0.0.0:1081 -no-tun -log-file "$LOG" >"/out/client-$ID.stdout" 2>&1 &
CLIENT_PID=$!

sleep 8

# The API takes numbers. Shape mode rides on WHISPERA_CHUNK instead.
case "$WHISP_CHUNK" in
  *[!0-9-]*) WHISP_CHUNK="" ;;
esac

if [ -n "$WHISP_CHUNK" ]; then
  CHUNK_MIN=$(echo "$WHISP_CHUNK" | cut -d- -f1)
  CHUNK_MAX=$(echo "$WHISP_CHUNK" | cut -d- -f2)
  if [ "$CHUNK_MAX" = "$WHISP_CHUNK" ]; then CHUNK_MAX=$CHUNK_MIN; fi
  curl -s -m 3 -X POST -H 'Content-Type: application/json' -d "{\"chunk_min\":$CHUNK_MIN,\"chunk_max\":$CHUNK_MAX}" http://127.0.0.1:10801/camo > /out/chunk.json 2>&1 || true
  cat /out/chunk.json
fi

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

if [ "$CONCURRENCY" -gt 1 ]; then
  # Many requests in flight at once, the way a browser and a phone in a pocket
  # both behave. No padding reshape here: that loop reacts to a single stream
  # of outcomes and means nothing when several are racing.
  while [ "$(date +%s)" -lt "$END" ]; do
    n=1
    PIDS=""
    while [ "$n" -le "$CONCURRENCY" ]; do
      (
        # curl times the request itself: busybox date has no %N, so anything
        # measured with the shell here comes out in whole seconds.
        R=$(curl -s -o /dev/null -m 8 -k -x socks5h://127.0.0.1:1081 -w '%{http_code} %{time_total}' "$ORIGIN_URL" || true)
        CODE=${R%% *}
        [ -z "$CODE" ] && CODE=000
        MS=$(echo "${R##* }" | awk '{printf "%.0f", $1 * 1000}')
        echo "$(date +%s),${MS:-0},$CODE,$PAD_MIN,$PAD_MAX," >> "$EVENTS"
      ) &
      PIDS="$PIDS $!"
      n=$((n + 1))
    done
    # Only the requests, never a bare wait: the go-client runs in the
    # background of this same shell and would never be waited out.
    for p in $PIDS; do
      wait "$p" || true
    done
    sleep "$PROBE_EVERY"
  done
  kill $CLIENT_PID 2>/dev/null || true
  echo "done" > "/out/client-$ID.finished"
  exit 0
fi

while [ "$(date +%s)" -lt "$END" ]; do
  R=$(curl -s -o /dev/null -m 8 -k -x socks5h://127.0.0.1:1081 -w '%{http_code} %{time_total}' "$ORIGIN_URL" || true)
  CODE=${R%% *}
  [ -z "$CODE" ] && CODE=000
  MS=$(echo "${R##* }" | awk '{printf "%.0f", $1 * 1000}')
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

  echo "$(date +%s),${MS:-0},$CODE,$PAD_MIN,$PAD_MAX,$ACTION" >> "$EVENTS"
  sleep "$PROBE_EVERY"
done

kill $CLIENT_PID 2>/dev/null || true
echo "done" > "/out/client-$ID.finished"
