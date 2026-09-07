#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

export MSYS_NO_PATHCONV=1
RUN_SECONDS="${RUN_SECONDS:-120}"
CENSOR_ROTATE="${CENSOR_ROTATE:-20s}"
export RUN_SECONDS CENSOR_ROTATE

RUN_ID="${RUN_ID:-$(date +%H%M%S)}"
export RUN_ID
mkdir -p out/origin cfg
rm -f out/events.csv out/censor.log out/report.md out/client.log out/client.stdout out/camo.json 2>/dev/null || true
head -c 1048576 /dev/urandom > out/origin/payload.bin

if [ ! -f cfg/config.yaml ]; then
  cp ../../config.yaml cfg/config.yaml
fi

echo "== build =="
docker compose -f compose.yml build --quiet

echo "== server =="
docker compose -f compose.yml up -d server
sleep 6

echo "== key =="
docker compose -f compose.yml exec -T server /app/whispera create-key \
  -user e2e -port 443 -sni www.example.com -self-cert disable -config /cfg/config.yaml \
  | tee out/create-key.log | grep -o 'whispera://[A-Za-z0-9._~+/=-]*' | tail -1 > cfg/key.txt
test -s cfg/key.txt || { echo "create-key failed, see out/create-key.log"; exit 1; }
python - <<'PYKEY'
import base64, json, io, os
p = "cfg/key.txt"
k = io.open(p, encoding="utf-8").read().strip().replace("whispera://", "")
k += "=" * (-len(k) % 4)
d = json.loads(base64.urlsafe_b64decode(k))
addr = os.environ.get("WHISP_SERVER", "censor:8443")
for f in ("server", "whispera_addr"):
    if f in d:
        d[f] = addr
raw = base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).decode().rstrip("=")
io.open(p, "w", encoding="utf-8").write("whispera://" + raw)
print("key points at", addr)
PYKEY

echo "key: $(cut -c1-40 cfg/key.txt)..."

echo "== censor + client, $RUN_SECONDS s =="
docker compose -f compose.yml up -d censor origin client
sleep $((RUN_SECONDS + 20))

echo "== collect =="
docker compose -f compose.yml logs censor > out/censor.log 2>&1 || true
docker compose -f compose.yml down -t 5 >/dev/null 2>&1 || true

python report.py out "out/dump-$RUN_ID.pcap"
