#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
export MSYS_NO_PATHCONV=1
RUN_SECONDS="${RUN_SECONDS:-30}"
RULES="${RULES:-rules-block-chrome-fp.yaml}"
GENES="${GENES:-i0/r1/p0 i1/r1/p0 i2/r1/p0 i0/r8/p0}"
export RUN_SECONDS
dc() { docker compose -f compose.gfw.yml "$@"; }

mkdir -p out/origin cfg
head -c 1048576 /dev/urandom > out/origin/payload.bin
[ -f cfg/config.yaml ] || cp ../../config.yaml cfg/config.yaml

echo "== build =="
dc build --quiet server gfw client

echo "== server + origin =="
dc up -d server origin
sleep 5

rm -f cfg/key-*.txt cfg/key.txt
echo "== key -> 198.51.100.10:443 =="
dc exec -T server /app/whispera create-key -user gfw1 -port 443 -sni origin -self-cert enable -config /cfg/config.yaml \
  | grep -o 'whispera://[A-Za-z0-9._~+/=-]*' | tail -1 > cfg/key.txt
test -s cfg/key.txt || { echo "create-key failed"; dc logs server | tail; exit 1; }
python - <<'PYKEY'
import base64, io, json
p="cfg/key.txt"
k=io.open(p,encoding="utf-8").read().strip().replace("whispera://","")
k+="="*(-len(k)%4)
d=json.loads(base64.urlsafe_b64decode(k))
for f in ("server","whispera_addr"):
    if f in d: d[f]="198.51.100.10:443"
raw=base64.urlsafe_b64encode(json.dumps(d,separators=(",",":")).encode()).decode().rstrip("=")
io.open(p,"w",encoding="utf-8").write("whispera://"+raw)
PYKEY

echo "== gfw (rules=$RULES) =="
GFW_RULES="$RULES" dc up -d --force-recreate gfw
sleep 3

measure() {
  gene="$1"
  : > out/events-1.csv
  rm -f out/client-1.finished
  WHISPERA_GENEPOOL=1 WHISPERA_GENE="$gene" GFW_RULES="$RULES" \
    dc up -d --force-recreate client
  sleep "$RUN_SECONDS"
  total=$(( $(wc -l < out/events-1.csv) - 1 ))
  [ "$total" -lt 0 ] && total=0
  ok=$(grep -c ',200,' out/events-1.csv) || ok=0
  printf '%-12s %s/%s OK\n' "$gene" "$ok" "$total"
  dc rm -sf client >/dev/null 2>&1 || true
}

echo; echo "########## PATH 2: each gene measured in isolation ##########"
for g in $GENES; do measure "$g"; done

echo; echo "########## PATH 1: in-client search (WHISPERA_GENEPOOL=1) ##########"
: > out/events-1.csv
WHISPERA_GENEPOOL=1 GFW_RULES="$RULES" dc up -d --force-recreate client
sleep "$((RUN_SECONDS * 3))"
echo "--- gene survival tallied from gene_trace:"
grep -hoE 'gene_trace [0-9]+,[^,]+,[01]' out/client-1.stdout out/client-1.log 2>/dev/null \
  | awk '{split($2,a,","); t[a[2]]++; s[a[2]]+=a[3]} END{for(g in t) printf "%-12s %d/%d\n", g, s[g], t[g]}' \
  | sort
dc rm -sf client >/dev/null 2>&1 || true

echo; echo "== teardown =="
dc down -v >/dev/null 2>&1 || true
echo "done"
