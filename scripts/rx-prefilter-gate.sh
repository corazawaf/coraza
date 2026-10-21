#!/usr/bin/env bash
# Fails when SecRxPreFilter On and Off disagree on a ruleset. See docs/rx-prefilter-gate.md.
#
#   scripts/rx-prefilter-gate.sh --rules <dir with *.conf>        # pattern check only (seconds)
#   scripts/rx-prefilter-gate.sh --rules <dir> --mode full        # pattern check, then the end-to-end replay
#   scripts/rx-prefilter-gate.sh --rules <dir> --mode full --limit 200   # smoke run of the replay
#   scripts/rx-prefilter-gate.sh --rules <dir> --audit-logs <file or dir>   # also replay production requests
#
# Modes:
#   pattern  every @rx pattern of the ruleset, built with and without the prefilter, fed inputs
#            generated from the pattern itself (internal/operators, TestRxPrefilterAgainstLabRuleset)
#   full     pattern, then the CRS regression corpus carried six ways through the bundled CRS and
#            through the ruleset, Off against On (testing/coreruleset, TestRxPreFilterParity;
#            about 10 minutes), then a self-check of the audit-log replay (writes a log with the
#            ruleset and replays it)
#   --audit-logs PATH   in any mode, replays the requests in these JSON audit logs (a file or a
#            directory, *.gz unzipped; the log needs SecAuditLogParts with C to hold the body) through
#            the ruleset, Off against On (TestRxPreFilterAuditReplay). The report has request lines.
#
# Exit status: 0 when Off and On agree everywhere, 1 on any disagreement or when a check could
# not run, 2 on bad usage. Output goes to $OUT (default build/rx-prefilter-gate); summary.txt there
# is the short version and ends with RESULT: PASS or RESULT: FAIL.
#
# Environment:
#   OUT                              output directory
#   CORAZA_PREFILTER_SAMPLES         generated inputs per pattern (default 300)
#   MIN_PATTERNS                     fail if the ruleset yields fewer @rx patterns (default 100), so
#                                    a ruleset that failed to unpack cannot pass by being empty
#   CORAZA_RX_PARITY_REMOVE_IDS      rule ids (commas or spaces) removed from the ruleset in the
#                                    replays: rules whose match is random, which differ between any
#                                    two runs
set -uo pipefail

MODE=pattern
RULES=""
LIMIT=""
AUDIT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --rules)    RULES="${2:-}"; shift 2 ;;
    --audit-logs) AUDIT="${2:-}"; shift 2 ;;
    --mode)     MODE="${2:-}"; shift 2 ;;
    --limit)    LIMIT="${2:-}"; shift 2 ;;
    -h|--help)  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
case "$MODE" in pattern|full) ;; *) echo "--mode must be pattern or full" >&2; exit 2 ;; esac
if [ -z "$RULES" ]; then echo "give --rules <dir with the ruleset's *.conf>" >&2; exit 2; fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
OUT="${OUT:-$ROOT/build/rx-prefilter-gate}"
case "$OUT" in /*) ;; *) OUT="$ROOT/$OUT" ;; esac
SAMPLES="${CORAZA_PREFILTER_SAMPLES:-300}"
MIN_PATTERNS="${MIN_PATTERNS:-100}"
mkdir -p "$OUT"
SUMMARY="$OUT/summary.txt"
: > "$SUMMARY"
say() { echo "$*" | tee -a "$SUMMARY"; }

fail=0

# ---- the ruleset ---------------------------------------------------------------
RULES="$(cd "$RULES" 2>/dev/null && pwd)" || { say "no such directory: $RULES"; say "RESULT: FAIL"; exit 1; }
[ -n "$(ls "$RULES"/*.conf 2>/dev/null)" ] || { say "no *.conf in $RULES"; say "RESULT: FAIL"; exit 1; }
say "ruleset: $RULES   version: $(head -n1 "$RULES/VERSION" 2>/dev/null || echo unknown)   conf files: $(ls "$RULES"/*.conf | wc -l)   SecRule lines: $(cat "$RULES"/*.conf | grep -c '^[[:space:]]*SecRule')"
say "fork:    $(git log -1 --format='%h %s' 2>/dev/null)   $(git describe --tags --always 2>/dev/null)   mode: $MODE"
say "go:      $(go version)"

# ---- 1. every @rx pattern ------------------------------------------------------
say ""
say "== pattern check (every @rx pattern, prefilter on against off)"
CORAZA_PREFILTER_RULES="$RULES" CORAZA_PREFILTER_SAMPLES="$SAMPLES" \
  go test ./internal/operators/ -run '^TestRxPrefilterAgainstLabRuleset$' -count=1 -v -timeout 0 >"$OUT/pattern.log" 2>&1
rc=$?
grep -E 'distinct @rx|compiled|compared' "$OUT/pattern.log" | sed 's/^ *//' | tee -a "$SUMMARY"
PATTERNS="$(sed -n 's/.*: \([0-9][0-9]*\) distinct @rx patterns.*/\1/p' "$OUT/pattern.log" | head -n1)"
if [ "$rc" != 0 ]; then
  say "pattern check FAILED (exit $rc); disagreeing patterns:"
  grep 'prefilter changed' "$OUT/pattern.log" | cut -c1-400 | head -40 | tee -a "$SUMMARY"
  grep -q 'prefilter changed' "$OUT/pattern.log" || tail -n 30 "$OUT/pattern.log" | tee -a "$SUMMARY"
  fail=1
elif [ -z "$PATTERNS" ] || [ "$PATTERNS" -lt "$MIN_PATTERNS" ]; then
  say "pattern check found ${PATTERNS:-no} @rx patterns, fewer than MIN_PATTERNS=$MIN_PATTERNS: the ruleset did not load as expected"
  fail=1
else
  say "pattern check: PASS"
fi

# ---- 2. end to end -------------------------------------------------------------
if [ "$MODE" = full ]; then
  say ""
  say "== end-to-end replay (CRS regression corpus, six carriers, prefilter off against on)"
  CORAZA_RX_PARITY=1 CORAZA_RX_PARITY_RULES="$RULES" CORAZA_RX_PARITY_LIMIT="$LIMIT" \
  CORAZA_RX_PARITY_REPORT="$OUT/replay-report.txt" \
    go test ./testing/coreruleset/ -run '^TestRxPreFilterParity$' -count=1 -v -timeout 0 >"$OUT/replay.log" 2>&1
  rc=$?
  if [ -s "$OUT/replay-report.txt" ]; then
    grep -E '^==|requests run|requests that differ' "$OUT/replay-report.txt" | sed 's/^ *//' | tee -a "$SUMMARY"
  fi
  if [ "$rc" != 0 ]; then
    say "end-to-end replay FAILED (exit $rc); see $OUT/replay-report.txt and replay.log"
    [ -s "$OUT/replay-report.txt" ] || tail -n 30 "$OUT/replay.log" | tee -a "$SUMMARY"
    fail=1
  else
    say "end-to-end replay: PASS"
  fi

  say ""
  say "== audit-log replay self-check (a log written with this ruleset, replayed)"
  rm -f "$OUT/selfcheck-audit.log"
  CORAZA_RX_AUDIT_SELFCHECK=1 CORAZA_RX_PARITY_RULES="$RULES" CORAZA_RX_AUDIT_SELFCHECK_LOG="$OUT/selfcheck-audit.log" \
    go test ./testing/coreruleset/ -run '^TestRxPreFilterAuditReplaySelfCheck$' -count=1 -v -timeout 0 >"$OUT/audit-selfcheck.log" 2>&1
  rc=$?
  grep -E 'corpus requests written|requests with their whole body|not compared with the log|logged rules that did not|requests that differ' "$OUT/audit-selfcheck.log" | sed 's/^ *//' | tee -a "$SUMMARY"
  if [ "$rc" != 0 ]; then
    say "audit-log replay self-check FAILED (exit $rc)"
    grep -E '^\s+prefilter_replay_test.go:[0-9]+:|--- FAIL|panic' "$OUT/audit-selfcheck.log" | head -20 | tee -a "$SUMMARY"
    fail=1
  else
    say "audit-log replay self-check: PASS"
  fi
fi

# ---- 3. production requests from audit logs ------------------------------------
if [ -n "$AUDIT" ]; then
  say ""
  say "== audit-log replay ($AUDIT)"
  CORAZA_RX_AUDIT_LOGS="$AUDIT" CORAZA_RX_PARITY_RULES="$RULES" CORAZA_RX_AUDIT_REPORT="$OUT/audit-replay-report.txt" \
    go test ./testing/coreruleset/ -run '^TestRxPreFilterAuditReplay$' -count=1 -v -timeout 0 >"$OUT/audit-replay.log" 2>&1
  rc=$?
  if [ -s "$OUT/audit-replay-report.txt" ]; then
    grep -E '^audit logs|file\(s\)|^==|requests run|requests that differ|requests with their whole body|not compared with the log|logged rules that did not' "$OUT/audit-replay-report.txt" | sed 's/^ *//' | tee -a "$SUMMARY"
  fi
  if [ "$rc" != 0 ]; then
    say "audit-log replay FAILED (exit $rc); see $OUT/audit-replay-report.txt (it holds request lines: keep it internal) and audit-replay.log"
    [ -s "$OUT/audit-replay-report.txt" ] || tail -n 30 "$OUT/audit-replay.log" | tee -a "$SUMMARY"
    fail=1
  else
    say "audit-log replay: PASS"
  fi
fi

say ""
if [ "$fail" = 0 ]; then say "RESULT: PASS (prefilter on and off agree)"; else say "RESULT: FAIL (do not enable SecRxPreFilter On with this ruleset and fork build)"; fi
echo "full logs in $OUT"
exit "$fail"
