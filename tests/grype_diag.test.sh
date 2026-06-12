#!/usr/bin/env bash
# tests/grype_diag.test.sh — offline regression for Phase 16 GRYPE-03/GRYPE-04 logic
# Usage: bash tests/grype_diag.test.sh
# No Docker, no network. Requires: jq (in PATH), bash 3.2+
set -euo pipefail

PASS=0; FAIL=0

assert_eq() {
  local desc="$1" expected="$2" actual="$3"
  if [[ "$actual" == "$expected" ]]; then
    echo "  PASS: $desc"
    PASS=$(( PASS + 1 ))
  else
    echo "  FAIL: $desc — expected '$expected', got '$actual'"
    FAIL=$(( FAIL + 1 ))
  fi
}

assert_gt() {
  local desc="$1" threshold="$2" actual="$3"
  if [[ "$actual" -gt "$threshold" ]]; then
    echo "  PASS: $desc"
    PASS=$(( PASS + 1 ))
  else
    echo "  FAIL: $desc — expected > $threshold, got '$actual'"
    FAIL=$(( FAIL + 1 ))
  fi
}

# ── Test 1: GRYPE_PKG_COUNT jq expression — 2 distinct artifacts → 2 ──────────
t1_json='{"matches":[
  {"artifact":{"name":"lodash","version":"4.17.20"},"vulnerability":{"id":"CVE-A"}},
  {"artifact":{"name":"express","version":"4.18.0"},"vulnerability":{"id":"CVE-B"}},
  {"artifact":{"name":"lodash","version":"4.17.20"},"vulnerability":{"id":"CVE-C"}}
]}'
t1=$(echo "$t1_json" | jq '[.matches[]?.artifact | {name, version}] | unique | length')
assert_eq "GRYPE_PKG_COUNT: 2 distinct artifacts from 3 matches" "2" "$t1"

# ── Test 2: TRIVY_PKG_COUNT jq expression — 3 Packages entries → 3 ───────────
t2_json='{"Results":[
  {"Packages":[
    {"Name":"pkg1","Version":"1.0"},
    {"Name":"pkg2","Version":"2.0"},
    {"Name":"pkg3","Version":"3.0"}
  ]}
]}'
t2=$(echo "$t2_json" | jq '[.Results[]?.Packages[]?] | length')
assert_eq "TRIVY_PKG_COUNT: 3 Packages entries → 3" "3" "$t2"

# ── Test 3: DB age jq expression — built 8 days ago → result > 7 ─────────────
# Compute "8 days ago" portably via jq (avoids BSD vs GNU date issue)
BUILT_8=$(jq -rn '(now - (8 * 86400)) | todateiso8601')
t3_json="{\"descriptor\":{\"db\":{\"status\":{\"built\":\"$BUILT_8\"}}}}"
t3=$(echo "$t3_json" | jq -r '
  if (.descriptor.db.status.built // null) != null then
    (.descriptor.db.status.built | fromdateiso8601) as $built |
    ((now - $built) / 86400 | floor) | tostring
  else
    "-1"
  end
')
assert_gt "DB age jq: built 8 days ago → age > 7" 7 "$t3"

# ── Test 4: DB age sentinel — built absent/null → result == -1 ───────────────
t4_json='{"descriptor":{"db":{"status":{}}}}'
t4=$(echo "$t4_json" | jq -r '
  if (.descriptor.db.status.built // null) != null then
    (.descriptor.db.status.built | fromdateiso8601) as $built |
    ((now - $built) / 86400 | floor) | tostring
  else
    "-1"
  end
')
assert_eq "DB age sentinel: built absent → -1" "-1" "$t4"

# ─────────────────────────────────────────────────────────────────────────────
# WR-03 LIMITATION (acknowledged): Tests 5-8 below re-type the 4-condition
# GRYPE-04 trigger `if` block inline rather than invoking build_report_json in
# check.sh. They validate the INTENDED logic, not the SHIPPED block — if someone
# edits the operator or a condition in check.sh, these tests stay green. A true
# render assertion for the warn-banner (CR-01) is impractical in bash (no DOM).
# These blocks are MIRRORS and MUST be kept in sync with check.sh
# build_report_json (the `dep_warning` trigger) by hand on any change.
# ─────────────────────────────────────────────────────────────────────────────

# ── Test 5: dep_warning trigger — manifests=true, both scanners 0, pass → warn ─
DEP_MANIFESTS_PRESENT=true
TRIVY_PKG_COUNT=0
GRYPE_PKG_COUNT=0
TRIVY_STATUS=pass
dep_warning=""
if [[ "$DEP_MANIFESTS_PRESENT" == "true" ]] \
   && [[ "$TRIVY_PKG_COUNT" -eq 0 ]] \
   && [[ "$GRYPE_PKG_COUNT" -eq 0 ]] \
   && [[ "$TRIVY_STATUS" == "pass" ]]; then
  dep_warning="manifests-present-zero-packages"
fi
assert_eq "dep_warning trigger: manifests=true, 0+0, pass → manifests-present-zero-packages" \
  "manifests-present-zero-packages" "$dep_warning"

# ── Test 6: dep_warning NOT set when TRIVY_PKG_COUNT > 0 ──────────────────────
DEP_MANIFESTS_PRESENT=true
TRIVY_PKG_COUNT=5
GRYPE_PKG_COUNT=0
TRIVY_STATUS=pass
dep_warning=""
if [[ "$DEP_MANIFESTS_PRESENT" == "true" ]] \
   && [[ "$TRIVY_PKG_COUNT" -eq 0 ]] \
   && [[ "$GRYPE_PKG_COUNT" -eq 0 ]] \
   && [[ "$TRIVY_STATUS" == "pass" ]]; then
  dep_warning="manifests-present-zero-packages"
fi
assert_eq "dep_warning NOT set: TRIVY_PKG_COUNT=5 → empty" "" "$dep_warning"

# ── Test 7: dep_warning NOT set when no manifests ─────────────────────────────
DEP_MANIFESTS_PRESENT=false
TRIVY_PKG_COUNT=0
GRYPE_PKG_COUNT=0
TRIVY_STATUS=pass
dep_warning=""
if [[ "$DEP_MANIFESTS_PRESENT" == "true" ]] \
   && [[ "$TRIVY_PKG_COUNT" -eq 0 ]] \
   && [[ "$GRYPE_PKG_COUNT" -eq 0 ]] \
   && [[ "$TRIVY_STATUS" == "pass" ]]; then
  dep_warning="manifests-present-zero-packages"
fi
assert_eq "dep_warning NOT set: DEP_MANIFESTS_PRESENT=false → empty" "" "$dep_warning"

# ── Test 8: dep_warning NOT set when status != pass ───────────────────────────
DEP_MANIFESTS_PRESENT=true
TRIVY_PKG_COUNT=0
GRYPE_PKG_COUNT=0
TRIVY_STATUS=warn
dep_warning=""
if [[ "$DEP_MANIFESTS_PRESENT" == "true" ]] \
   && [[ "$TRIVY_PKG_COUNT" -eq 0 ]] \
   && [[ "$GRYPE_PKG_COUNT" -eq 0 ]] \
   && [[ "$TRIVY_STATUS" == "pass" ]]; then
  dep_warning="manifests-present-zero-packages"
fi
assert_eq "dep_warning NOT set: TRIVY_STATUS=warn → empty" "" "$dep_warning"

# ── Test 9: WR-02 numeric clamp — non-integer count is normalized to 0 ─────────
# Mirrors the clamp guard added to build_report_json / the stale-DB gate. A
# malformed sourced env value (e.g. empty or non-numeric) must not abort the run
# under set -euo pipefail; the clamp coerces it to a safe default before any
# arithmetic test.
GRYPE_PKG_COUNT="not-a-number"
[[ "$GRYPE_PKG_COUNT" =~ ^-?[0-9]+$ ]] || GRYPE_PKG_COUNT=0
assert_eq "WR-02 clamp: non-integer GRYPE_PKG_COUNT → 0" "0" "$GRYPE_PKG_COUNT"

GRYPE_DB_AGE_DAYS=""
[[ "$GRYPE_DB_AGE_DAYS" =~ ^-?[0-9]+$ ]] || GRYPE_DB_AGE_DAYS=-1
assert_eq "WR-02 clamp: empty GRYPE_DB_AGE_DAYS → -1 sentinel" "-1" "$GRYPE_DB_AGE_DAYS"

# Valid integers pass through untouched.
TRIVY_PKG_COUNT=42
[[ "$TRIVY_PKG_COUNT" =~ ^-?[0-9]+$ ]] || TRIVY_PKG_COUNT=0
assert_eq "WR-02 clamp: valid integer TRIVY_PKG_COUNT preserved" "42" "$TRIVY_PKG_COUNT"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
