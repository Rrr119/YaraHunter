# Acceptance test

`acceptance_3_images.sh` compares the legacy full scan with the sharded,
prefiltered scan on three image root filesystems.

For each image it:

1. Runs the legacy scanner (`--rule-shards 1`, one worker).
2. Runs the sharded scanner (`--rule-shards 4`, one worker per logical CPU by
   default).
3. Repeats each mode and reports the median wall time.
4. Compares the exact `(rule, file, layer, string matches)` IOC set.
5. Runs once with `--prefilter-shadow-mode` and requires `shadow_misses=0`.

Example:

```bash
YARAHUNTER_BIN=./YaraHunter \
  IMAGES="/images/debian /images/python /images/xmrig" \
  RULES_PATH=/rules \
  ./itests/acceptance_3_images.sh
```

Override `RUNS`, `RULE_SHARDS`, `WORKERS`, `CONFIG_PATH`, or `OUT_DIR` as
needed. The script exits non-zero if any IOC set differs, a shadow miss is
recorded, or a scan is not faster than the legacy run.
