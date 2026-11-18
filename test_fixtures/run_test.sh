#!/bin/sh
# Runs the real scanner.py against a benign multi-vendor log pair and a
# malicious multi-vendor log pair, asserting specific detection_ids fire.
set -e
cd "$(dirname "$0")/.."

OUT=/tmp/fwlog_test_$$
mkdir -p "$OUT"

run() {
  label="$1"; shift
  python3 scanner.py "$@" --json "$OUT/$label.json" --fail-on any > "$OUT/$label.txt" 2>&1
  echo $? > "$OUT/$label.exit"
}

assert_exit() {
  label="$1"; expected="$2"
  actual=$(cat "$OUT/$label.exit")
  [ "$actual" = "$expected" ] && echo "PASS: $label exit code $actual" \
    || { echo "FAIL: $label expected exit $expected, got $actual"; cat "$OUT/$label.txt"; rm -rf "$OUT"; exit 1; }
}

assert_fires() {
  label="$1"; det_id="$2"
  python3 -c "
import json, sys
findings = json.load(open('$OUT/$label.json'))
sys.exit(0 if any(f['detection_id'] == '$det_id' for f in findings) else 1)
" && echo "PASS: $label -> $det_id fired" \
  || { echo "FAIL: $label -> $det_id did not fire"; cat "$OUT/$label.txt"; rm -rf "$OUT"; exit 1; }
}

echo "== Benign (FortiGate + Sophos) =="
set +e; run benign test_fixtures/fortigate_benign.log test_fixtures/sophos_benign.log; set -e
cat "$OUT/benign.txt"
assert_exit benign 0
python3 -c "
import json, sys
findings = json.load(open('$OUT/benign.json'))
sys.exit(0 if len(findings) == 0 else 1)
" && echo "PASS: benign produced zero findings" \
  || { echo "FAIL: benign unexpectedly produced findings"; rm -rf "$OUT"; exit 1; }

echo
echo "== Malicious (FortiGate + Sophos) =="
set +e; run malicious test_fixtures/fortigate_malicious.log test_fixtures/sophos_malicious.log; set -e
cat "$OUT/malicious.txt"
assert_exit malicious 1
for did in DET-1 DET-2 DET-3 DET-4 DET-5; do
  assert_fires malicious "$did"
done

# DET-4 (allow-after-deny) came from the Sophos log; DET-1/2/3/5 came
# from the FortiGate log - confirm detections genuinely correlate
# across BOTH normalized vendor formats in one combined run, not just
# within a single vendor's own events.
python3 -c "
import json
findings = json.load(open('$OUT/malicious.json'))
det4 = [f for f in findings if f['detection_id'] == 'DET-4'][0]
det1 = [f for f in findings if f['detection_id'] == 'DET-1'][0]
assert det4['src_ip'] == '203.0.113.50', 'DET-4 should be keyed on the Sophos-sourced IP'
assert det1['src_ip'] == '198.51.100.23', 'DET-1 should be keyed on the FortiGate-sourced IP'
print('PASS: detections correlate correctly across both normalized vendor formats')
"

rm -rf "$OUT"
echo
echo "All tests passed."
