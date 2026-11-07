#!/usr/bin/env bash
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
WEIGHTS="$REPO/core/protocol/policy_weights.go"
TRAINER="$REPO/neural/mutate.py"
PYTHON="${PYTHON:-${WHISPERA_POLICY_PYTHON:-python3}}"

TRACE="${1:-}"
if [ -z "$TRACE" ]; then
  for cand in "$APPDATA/whispera/dials.csv" "$HOME/.config/whispera/dials.csv"; do
    [ -f "$cand" ] && TRACE="$cand" && break
  done
fi
if [ -z "$TRACE" ] || [ ! -f "$TRACE" ]; then
  echo "no dial trace found; pass its path: $0 /path/to/dials.csv" >&2
  exit 1
fi

echo "trace:   $TRACE"
echo "weights: $WEIGHTS"
echo "trainer: $PYTHON $TRAINER"
echo

cd "$REPO"
go run ./scripts/policyfit -trace "$TRACE" -trainer "$TRAINER" -python "$PYTHON" -out "$WEIGHTS" "${@:2}"

if git -c safe.directory="$REPO" diff --quiet -- "$WEIGHTS"; then
  echo
  echo "weights unchanged: the recorded dials did not beat the frozen ones."
else
  echo
  echo "weights repinned. verify, then rebuild:"
  echo "  go test ./core/protocol/ -run TestShippedWeightsAreWhatTheExporterWrites -count=1"
  echo "  (whispera release -> server update -> Whisp MSI)"
fi
