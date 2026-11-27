#!/usr/bin/env bash
# Acceptance test for the sharded/prefiltered scanner.
#
# It scans three extracted image root filesystems in legacy mode (one ruleset,
# one worker) and in parallel shard mode, repeats each run, compares the IOC
# (rule,file,layer) sets exactly, and reports median wall-clock speedup.
#
# Usage:
#   YARAHUNTER_BIN=./YaraHunter RULES_PATH=/path/to/rules \
#     IMAGES="/image1 /image2 /image3" ./itests/acceptance_3_images.sh
#
# The default image paths match the evaluation fixtures used for this task.
set -u

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BIN=${YARAHUNTER_BIN:-"$ROOT/YaraHunter"}
RULES_PATH=${RULES_PATH:-/home/dev/rules}
CONFIG_PATH=${CONFIG_PATH:-"$ROOT/itests/acceptance-config.yaml"}
IMAGES=${IMAGES:-"/home/dev/images/debian /home/dev/images/python /home/dev/images/xmrig"}
RUNS=${RUNS:-3}
WARMUP=${WARMUP:-1}
RULE_SHARDS=${RULE_SHARDS:-4}
WORKERS=${WORKERS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 8)}

if [ ! -x "$BIN" ]; then
  echo "scanner binary not found/executable: $BIN" >&2
  exit 2
fi
for image in $IMAGES; do
  if [ ! -d "$image" ]; then
    echo "image rootfs not found: $image" >&2
    exit 2
  fi
done

STAMP=$(date +%Y%m%d-%H%M%S)
OUT=${OUT_DIR:-"$ROOT/artifacts/acceptance-$STAMP"}
mkdir -p "$OUT"

run_scan() {
  local image=$1
  local mode=$2
  local run=$3
  local name
  name=$(basename "$image")
  local json="$OUT/$name.$mode.$run.json"
  local log="$OUT/$name.$mode.$run.log"
  local args=(
    -local "$image"
    -rules-path "$RULES_PATH"
    -config-path "$CONFIG_PATH"
    -output json
  )
  if [ "$mode" = legacy ]; then
    args+=(-rule-shards 1 -workers-per-scan 1 -prefilter=false)
  elif [ "$mode" = shadow ]; then
    args+=(-rule-shards "$RULE_SHARDS" -workers-per-scan "$WORKERS" -prefilter=true -prefilter-shadow-mode)
  else
    args+=(-rule-shards "$RULE_SHARDS" -workers-per-scan "$WORKERS" -prefilter=true)
  fi

  local start end
  start=$(date +%s%N)
  "$BIN" "${args[@]}" >"$json" 2>"$log"
  local status=$?
  end=$(date +%s%N)
  if [ "$status" -ne 0 ]; then
    echo "scan failed ($name $mode run $run), see $log" >&2
    return "$status"
  fi
  awk -v s="$start" -v e="$end" 'BEGIN { printf "%.6f\n", (e-s)/1000000000 }'
}

normalize() {
  python3 - "$1" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))["IOC"]
keys = sorted(
    (
        item.get("Matched Rule Name", ""),
        item.get("Full File Name", ""),
        item.get("Image Layer ID", ""),
        tuple(sorted((m.get("Offset", 0), m.get("Data", "")) for m in item.get("matches") or [])),
    )
    for item in data
)
print(json.dumps(keys, sort_keys=True))
PY
}

median() {
  python3 - "$@" <<'PY'
import statistics, sys
values = [float(v) for v in sys.argv[1:]]
print(f"{statistics.median(values):.6f}")
PY
}

printf 'image\tlegacy_s\tshard_s\tspeedup\tmatches\tequal\tshadow_misses\tshard_skip_pct\n'
failed=0
for image in $IMAGES; do
  name=$(basename "$image")
  legacy_times=()
  shard_times=()
  if [ "$WARMUP" = "1" ]; then
    # Warm the page cache and shard compiler before the measured runs.
    run_scan "$image" legacy warmup >/dev/null || exit 1
    run_scan "$image" shard warmup >/dev/null || exit 1
  fi
  for run in $(seq 1 "$RUNS"); do
    # Alternate order so page-cache warming does not systematically favour one mode.
    if [ $((run % 2)) -eq 1 ]; then
      t=$(run_scan "$image" legacy "$run") || exit 1
      legacy_times+=("$t")
      t=$(run_scan "$image" shard "$run") || exit 1
      shard_times+=("$t")
    else
      t=$(run_scan "$image" shard "$run") || exit 1
      shard_times+=("$t")
      t=$(run_scan "$image" legacy "$run") || exit 1
      legacy_times+=("$t")
    fi
  done

  shadow_time=$(run_scan "$image" shadow 1) || exit 1
  legacy_norm=$(normalize "$OUT/$name.legacy.1.json")
  shard_norm=$(normalize "$OUT/$name.shard.1.json")
  shadow_norm=$(normalize "$OUT/$name.shadow.1.json")
  matches=$(python3 -c 'import json,sys; print(len(json.loads(sys.argv[1])))' "$legacy_norm")
  equal=False
  if [ "$legacy_norm" = "$shard_norm" ] && [ "$legacy_norm" = "$shadow_norm" ]; then
    equal=True
  else
    failed=1
  fi
  misses=$(grep -o 'shadow_misses=[0-9]*' "$OUT/$name.shadow.1.log" | tail -1 | cut -d= -f2)
  misses=${misses:-unknown}
  scans=$(grep -o 'shard_scans=[0-9]*' "$OUT/$name.shard.1.log" | tail -1 | cut -d= -f2)
  skips=$(grep -o 'shard_skips=[0-9]*' "$OUT/$name.shard.1.log" | tail -1 | cut -d= -f2)
  scans=${scans:-0}
  skips=${skips:-0}
  skip_pct=$(python3 -c "s=$scans+$skips; print('%.1f' % (100.0*$skips/s) if s else '0.0')")
  if [ "$misses" != "0" ]; then
    failed=1
  fi

  legacy_med=$(median "${legacy_times[@]}")
  shard_med=$(median "${shard_times[@]}")
  speedup=$(python3 -c "print('%.2f' % (float('$legacy_med') / float('$shard_med')))")
  python3 - "$name" "$legacy_med" "$shard_med" "$speedup" "$matches" "$equal" "$misses" "$skip_pct" <<'PY'
import sys
name, legacy, shard, speedup, matches, equal, misses, skip_pct = sys.argv[1:]
if float(speedup) <= 1.0 or equal != "True":
    raise SystemExit(1)
print(f"{name}\t{legacy}\t{shard}\t{speedup}x\t{matches}\t{equal}\t{misses}\t{skip_pct}%")
PY
  if [ $? -ne 0 ]; then
    failed=1
  fi
  echo "shadow_wall_s=$shadow_time" >>"$OUT/$name.summary.txt"
done

echo "artifacts: $OUT"
exit "$failed"
