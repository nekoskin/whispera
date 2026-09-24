#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

export MSYS_NO_PATHCONV=1
RUN_SECONDS="${RUN_SECONDS:-120}"
CENSOR_ROTATE="${CENSOR_ROTATE:-20s}"
export RUN_SECONDS CENSOR_ROTATE

dc() { docker compose -f compose.yml "$@"; }

RUN_ID="${RUN_ID:-$(date +%H%M%S)}"
export RUN_ID
mkdir -p out/origin cfg
rm -f out/events.csv out/censor.log out/report.md out/client.log out/client.stdout out/camo.json 2>/dev/null || true
rm -f out/events-*.csv out/client-*.log out/client-*.stdout out/client-*.finished 2>/dev/null || true
# The dial trace is opened with O_APPEND, so a stale file makes one run's
# numbers pile onto the next. Clear it with the rest.
rm -f out/dials-*.csv 2>/dev/null || true
# Slots are claimed with mkdir; leftovers would starve the next run.
rm -rf cfg/slot-* cfg/legit-slot-* 2>/dev/null || true
rm -f out/legit-*.csv out/legit-*.finished 2>/dev/null || true
PAYLOAD_BYTES="${PAYLOAD_BYTES:-1048576}"
head -c "$PAYLOAD_BYTES" /dev/urandom > out/origin/payload.bin

if [ ! -f cfg/config.yaml ]; then
  cp ../../config.yaml cfg/config.yaml
fi

echo "== build =="
dc build --quiet

echo "== server =="
# The origin has to be up before the key is made: cloning its certificate
# dials origin:443, and a key created against a dead origin fails the run.
dc up -d server origin
sleep 6

USERS="${USERS:-1}"
export USERS
echo "== keys for $USERS user(s) =="
rm -f cfg/key-*.txt
i=1
while [ "$i" -le "$USERS" ]; do
  dc exec -T server /app/whispera create-key \
    -user "e2e$i" -port 443 -sni origin -self-cert enable -config /cfg/config.yaml \
    | tee "out/create-key-$i.log" | grep -o 'whispera://[A-Za-z0-9._~+/=-]*' | tail -1 > "cfg/key-$i.txt"
  test -s "cfg/key-$i.txt" || { echo "create-key failed for user $i, see out/create-key-$i.log"; exit 1; }
  i=$((i + 1))
done
cp cfg/key-1.txt cfg/key.txt
python - <<'PYKEY'
import base64, glob, io, json, os
addr = os.environ.get("WHISP_SERVER", "censor:8443")
for p in sorted(glob.glob("cfg/key*.txt")):
    k = io.open(p, encoding="utf-8").read().strip().replace("whispera://", "")
    k += "=" * (-len(k) % 4)
    d = json.loads(base64.urlsafe_b64decode(k))
    for f in ("server", "whispera_addr"):
        if f in d:
            d[f] = addr
    raw = base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).decode().rstrip("=")
    io.open(p, "w", encoding="utf-8").write("whispera://" + raw)
print("keys point at", addr)
PYKEY

echo "key: $(cut -c1-40 cfg/key.txt)..."

echo "== censor + $USERS client(s), $RUN_SECONDS s =="
dc up -d censor origin
dc up -d --scale "client=$USERS" client
# Off unless asked for, so runs taken before this existed stay comparable.
LEGIT_USERS="${LEGIT_USERS:-0}"
export LEGIT_USERS
if [ "$LEGIT_USERS" -gt 0 ]; then
  echo "== $LEGIT_USERS legitimate client(s) =="
  dc up -d --scale "legit=$LEGIT_USERS" legit
fi
sleep $((RUN_SECONDS + 20))

echo "== collect =="
# The censor writes out/censor.log itself through tee, so docker's own copy
# goes elsewhere: sending it here truncated the file and left the run with no
# censor log at all.
dc logs censor > out/censor-docker.log 2>&1 || true
dc down -t 5 >/dev/null 2>&1 || true

python report.py out "out/dump-$RUN_ID.pcap"
