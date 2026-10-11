#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
export MSYS_NO_PATHCONV=1
RUN_SECONDS="${RUN_SECONDS:-20}"
export RUN_SECONDS CENSOR_MODE=tlsintls CENSOR_ROTATE=0s RUN_ID=tlsintls
dc() { docker compose -f compose.yml "$@"; }

mkdir -p out/origin cfg
head -c 1048576 /dev/urandom > out/origin/payload.bin
[ -f cfg/config.yaml ] || cp ../../config.yaml cfg/config.yaml

echo "== build =="
dc build --quiet server origin censor client

echo "== server + origin =="
dc up -d server origin
sleep 6

rm -f cfg/key-*.txt cfg/key.txt
dc exec -T server /app/whispera create-key -user t1 -port 443 -sni origin -self-cert enable -config /cfg/config.yaml \
  | grep -o 'whispera://[A-Za-z0-9._~+/=-]*' | tail -1 > cfg/key.txt
test -s cfg/key.txt || { echo "create-key failed"; exit 1; }
python - <<'PYKEY'
import base64, io, json
p = "cfg/key.txt"
k = io.open(p, encoding="utf-8").read().strip().replace("whispera://", "")
k += "=" * (-len(k) % 4)
d = json.loads(base64.urlsafe_b64decode(k))
for f in ("server", "whispera_addr"):
    if f in d:
        d[f] = "censor:8443"
raw = base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).decode().rstrip("=")
io.open(p, "w", encoding="utf-8").write("whispera://" + raw)
PYKEY
cp cfg/key.txt cfg/key-1.txt

phase() {
  label="$1"; reshape="$2"
  dc up -d --force-recreate censor >/dev/null 2>&1
  sleep 2
  : > out/events-1.csv
  rm -rf cfg/slot-*
  export WHISPERA_OPENING_RESHAPE="$reshape"
  dc up -d --force-recreate --no-deps client >/dev/null 2>&1
  sleep "$RUN_SECONDS"
  ok=$(grep -c ',200,' out/events-1.csv 2>/dev/null) || ok=0
  dc rm -sf client >/dev/null 2>&1 || true
  sleep 2
  enc=$(grep -cE 'encap=true|split=true' out/censor.log 2>/dev/null) || enc=0
  tot=$(grep -c 'TLSINTLS' out/censor.log 2>/dev/null) || tot=0
  printf '  %-28s tunnel detected %s/%s connections | %s requests OK\n' "$label" "$enc" "$tot" "$ok"
}

echo
echo "########## TLS-in-TLS detector: does the tunnel leak the inner handshake? ##########"
phase "reshape OFF (old datapath)" "0"
phase "reshape ON  (the fix)"      ""

echo
echo "== teardown =="
dc down -v >/dev/null 2>&1 || true
echo "done"
