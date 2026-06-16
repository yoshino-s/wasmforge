#!/bin/bash
set -Eeuo pipefail
# run-clr-batch.sh — Run the CLR assembly test N times and collect DIAG output.
# Usage: ./scripts/run-clr-batch.sh [N] [EXE_PATH] [PARALLEL]
#   N defaults to 20
#   EXE_PATH defaults to 'C:\Temp\clr-asm-wf.exe'
#   PARALLEL defaults to 5 (concurrent runs)

N=${1:-20}
EXE=${2:-'C:\Temp\clr-asm-wf.exe'}
PAR=${3:-3}
FLOG="/tmp/clr-batch-$(date +%H%M%S).log"
RDIR=$(mktemp -d)
trap 'rm -rf "$RDIR"' EXIT
export EXE FLOG RDIR

# run_one: execute a single test iteration, write result to $RDIR/$1.result
run_one() {
    local i=$1
    local out
    out=$(labctl exec win11 "$EXE" 2>&1 | head -500) || true
    if echo "$out" | grep -qE "All CLR Assembly Tests Passed|PASS:clr_assembly:dual_load"; then
        echo "PASS" > "$RDIR/$i.result"
    elif echo "$out" | grep -q "FAIL:"; then
        local fp vt
        fp=$(echo "$out" | grep "FAIL:" | head -1 | sed 's/.*clr_assembly:\([^ ]*\).*/\1/')
        vt=$(echo "$out" | grep "DIAG:pEnum:vtable=" | head -1 || true)
        echo "FAIL@$fp $vt" > "$RDIR/$i.result"
        { echo "=== RUN $i ==="; echo "$out"; } >> "$FLOG"
    else
        local laststep diag
        laststep=$(echo "$out" | grep "PASS:clr_assembly:" | tail -1 | sed 's/.*clr_assembly:\([^ ]*\).*/\1/' || true)
        diag=$(echo "$out" | grep "MIRROR-DIAG" | head -1 || true)
        echo "CRASH@${laststep:-unknown} $diag" > "$RDIR/$i.result"
        { echo "=== RUN $i ==="; echo "$out"; } >> "$FLOG"
    fi
}
export -f run_one

# Run N iterations, PAR at a time.
seq 1 $N | xargs -P "$PAR" -I{} bash -c 'run_one {}'

# Collect and display results.
pass=0; fail=0; crash=0
for i in $(seq 1 $N); do
    result=$(cat "$RDIR/$i.result" 2>/dev/null || echo "CRASH@unknown")
    case "$result" in
        PASS)
            pass=$((pass+1)); printf "[%2d] PASS\n" "$i" ;;
        FAIL@*)
            fail=$((fail+1)); printf "[%2d] %s\n" "$i" "$result" ;;
        CRASH@*)
            crash=$((crash+1)); printf "[%2d] %s\n" "$i" "$result" ;;
    esac
done

echo "--- $pass/$N pass, $fail fail, $crash crash ---"
[ $fail -gt 0 ] && echo "Failures saved: $FLOG"
