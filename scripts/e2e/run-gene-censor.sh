#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
export MSYS_NO_PATHCONV=1
RUN_SECONDS="${RUN_SECONDS:-20}"
export RUN_SECONDS PCAP_SNAP=96 CENSOR_MODE=ja4 CENSOR_ROTATE=0s
dc() { docker compose -f compose.yml "$@"; }

mkdir -p out/origin cfg
rm -f out/censor.log out/events-*.csv out/client-*.log out/client-*.stdout out/client-*.finished 2>/dev/null || true
rm -rf cfg/slot-* 2>/dev/null || true
head -c 1048576 /dev/urandom > out/origin/payload.bin
[ -f cfg/config.yaml ] || cp ../../config.yaml cfg/config.yaml

echo "== build =="
dc build --quiet

echo "== server + origin =="
dc up -d server origin
sleep 6

rm -f cfg/key-*.txt cfg/key.txt
dc exec -T server /app/whispera create-key -user e2e1 -port 443 -sni origin -self-cert enable -config /cfg/config.yaml \
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

censor_up() {
  export CENSOR_BLOCK_JA4B="$1" CENSOR_REASSEMBLE="$2"
  dc up -d --force-recreate censor >/dev/null 2>&1
  sleep 3
  got=$(dc exec -T censor sh -c 'printf %s "$CENSOR_BLOCK_JA4B"' 2>/dev/null)
  if [ "$got" != "$1" ]; then
    echo "  [!] censor block list is [$got], expected [$1]"
  fi
}

measure() {
  gene="$1"
  : > out/events-1.csv
  rm -f out/client-1.finished
  rm -rf cfg/slot-*
  export WHISPERA_GENEPOOL=1 WHISPERA_GENE="$gene"
  dc up -d --force-recreate client >/dev/null 2>&1
  sleep "$RUN_SECONDS"
  total=$(( $(wc -l < out/events-1.csv) - 1 ))
  [ "$total" -lt 0 ] && total=0
  ok=$(grep -c ',200,' out/events-1.csv) || ok=0
  printf '  %-10s %s/%s OK\n' "$gene" "$ok" "$total"
  dc rm -sf client >/dev/null 2>&1 || true
}

learned_ja4b() {
  grep -oE 'ja4 [A-Za-z0-9]+_[A-Za-z0-9]+_[A-Za-z0-9]+' out/censor.log \
    | sed -E 's/.*_([A-Za-z0-9]+)_[A-Za-z0-9]+$/\1/' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}'
}

echo; echo "########## LEARN: JA4_b (cipher hash) of each replicated identity ##########"
declare -a JA4B
for k in 0 1 2; do
  censor_up "" 1
  measure "i$k/r1/p0"
  JA4B[$k]=$(learned_ja4b)
  echo "  ident $k -> ${JA4B[$k]}"
done
if [ -z "${JA4B[0]}" ] || [ "${JA4B[0]}" = "${JA4B[1]}" ] || [ "${JA4B[0]}" = "${JA4B[2]}" ]; then
  echo "identities do not have distinct cipher hashes, blocking one would be meaningless"; dc down -v >/dev/null 2>&1; exit 1
fi

echo; echo "########## CONTROL: censor does NOT reassemble, blocks ident 0 cipher hash ##########"
censor_up "${JA4B[0]}" ""
for g in i0/r1/p0 i0/r8/p0 i1/r1/p0; do measure "$g"; done

echo; echo "########## REASSEMBLE: censor rebuilds the hello, blocks ident 0 cipher hash ##########"
censor_up "${JA4B[0]}" 1
for g in i0/r1/p0 i0/r8/p0 i1/r1/p0 i1/r8/p0 i2/r1/p0 i2/r8/p0; do measure "$g"; done

echo; echo "########## PATH 1: in-client search against the reassembling censor ##########"
: > out/events-1.csv
rm -f out/client-1.stdout out/client-1.log
rm -rf cfg/slot-*
unset WHISPERA_GENE
export WHISPERA_GENEPOOL=1
dc up -d --force-recreate client >/dev/null 2>&1
sleep "$((RUN_SECONDS * 3))"
grep -hoE 'gene_trace [0-9]+,[^,]+,[01]' out/client-1.stdout out/client-1.log 2>/dev/null \
  | awk '{split($2,a,","); t[a[2]]++; s[a[2]]+=a[3]} END{for(g in t) printf "  %-12s %d/%d\n", g, s[g], t[g]}' \
  | sort
dc rm -sf client >/dev/null 2>&1 || true

echo; echo "== teardown =="
dc down -v >/dev/null 2>&1 || true
echo "done"
