#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
export MSYS_NO_PATHCONV=1

# The server's session cap rides on this env; exporting it keeps every `up` call
# seeing the same value, or docker recreates the server (wiping the registered
# user in /etc/whispera/users.json) the moment the client comes up without it.
export MAX_SESS=10

dc() { docker compose -f compose.torrent.yml "$@"; }

mkdir -p out/origin cfg
head -c 1024 /dev/urandom > out/origin/payload.bin
[ -f cfg/config.yaml ] || cp ../../config.yaml cfg/config.yaml

echo "== clean slate =="
dc down -t 3 >/dev/null 2>&1 || true

echo "== build =="
dc build --quiet

echo "== server + origin + sink + censor =="
MAX_SESS=10 dc up -d server origin sink censor
sleep 6

echo "== key pointed at server:443 =="
dc exec -T server /app/whispera create-key \
  -user tor -port 443 -sni origin -self-cert enable -config /cfg/config.yaml \
  | grep -o 'whispera://[A-Za-z0-9._~+/=-]*' | tail -1 > cfg/torrent-key.txt
python - <<'PY'
import base64, io, json
k = io.open("cfg/torrent-key.txt", encoding="utf-8").read().strip().replace("whispera://", "")
k += "=" * (-len(k) % 4)
d = json.loads(base64.urlsafe_b64decode(k))
for f in ("server", "whispera_addr"):
    if f in d:
        d[f] = "censor:8443"
raw = base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).decode().rstrip("=")
io.open("cfg/torrent-key.txt", "w", encoding="utf-8").write("whispera://" + raw)
print("key points at censor:8443")
PY

# create-key registers the user in users.json but the running server loaded an
# empty store at boot; a restart makes it pick the user up. The identity key is
# kept on disk, so the key stays valid across the restart.
echo "== restart server to load the registered user =="
dc restart server >/dev/null 2>&1
sleep 6

# Runs a case: hold COUNT torrent connections, then make one normal request, and
# report whether the normal request got through while torrent filled the cap.
# Holds 15 torrent connections over a MAX_SESS=10 key and reports how many the
# server refused with active_cap. Tagged torrent is exempt, so it never trips the
# cap (0 refusals); untagged, the same 15 count and the cap fires past 10. The
# refusal count is the honest signal — a normal request can ride a pooled
# connection, so its status alone does not prove the cap held.
run_case() {
  tag=$1
  {
    echo "===== case TORRENT_TAG=$tag (server MAX_SESS=10, 15 torrent) ====="
    TAG=$tag dc up -d client
    sleep 10
    echo "baseline (no torrent): $(dc exec -T client curl -s -o /dev/null -m 10 -k -x socks5h://127.0.0.1:1081 -w '%{http_code}' https://origin/payload.bin 2>/dev/null || true)"

    before=$(dc logs server 2>&1 | grep -c "reason=active_cap" || true)
    dc exec -T -e MODE=client -e SOCKS_ADDR=127.0.0.1:1081 -e TARGET=sink:51999 \
      -e COUNT=15 -e HOLD_SECONDS=30 client /app/torrentsim &
    simpid=$!
    sleep 8
    after=$(dc logs server 2>&1 | grep -c "reason=active_cap" || true)
    refusals=$((after - before))
    echo "active_cap refusals this case: $refusals"

    wait "$simpid" 2>/dev/null || true
    dc rm -sf client >/dev/null 2>&1 || true
  } >&2
  echo "$tag:$refusals"
}

on=$(run_case 1 | tail -1)
off=$(run_case 0 | tail -1)

echo ""
echo "===== RESULT (active_cap refusals over a MAX_SESS=10 key, 15 torrent) ====="
echo "tag ON  -> $on   (expect 1:0 — torrent exempt, cap never trips)"
echo "tag OFF -> $off  (expect 0:>0 — same torrent counts, cap fires past 10)"

dc down -t 5 >/dev/null 2>&1 || true

on_ref=${on#1:}
off_ref=${off#0:}
[ "$on_ref" = "0" ] || { echo "FAIL: tagging on still tripped the cap ($on_ref refusals)"; exit 1; }
[ "$off_ref" -gt 0 ] || { echo "FAIL: control never tripped the cap — test did not exercise it"; exit 1; }
echo "PASS: torrent is exempt when tagged ($on_ref refusals) and counts when not ($off_ref refusals)"
