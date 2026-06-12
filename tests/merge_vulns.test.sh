#!/usr/bin/env bash
# tests/merge_vulns.test.sh — offline regression for scanner.merge.jq
# Usage: bash tests/merge_vulns.test.sh
# No Docker, no network. Requires: jq (in PATH)
set -euo pipefail

PASS=0; FAIL=0
JQ_FILE="$(dirname "$0")/../lib/scanner.merge.jq"
GRYPE_NORM_JQ="$(dirname "$0")/../lib/scanner.grype-normalize.jq"

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

run_merge() {
  local trivy="$1" grype="$2"
  jq -n --argjson trivy "$trivy" --argjson grype "$grype" -f "$JQ_FILE"
}

# ── Test 1: Cross-scanner collapse ──────────────────────────────────────────
t1=$(run_merge \
  '[{"id":"CVE-2023-0001","pkg":"lodash","version":"4.17.20","severity":"HIGH","found_by":"trivy","title":"T","cvss":null,"fix":""}]' \
  '[{"id":"CVE-2023-0001","pkg":"lodash","version":"4.17.20","severity":"MEDIUM","found_by":"grype","title":"G","cvss":null,"fix":""}]')
assert_eq "cross-scanner: output length == 1"  "1"    "$(echo "$t1" | jq 'length')"
assert_eq "cross-scanner: found_by == both"    "both" "$(echo "$t1" | jq -r '.[0].found_by')"

# ── Test 2: Normalization (v-prefix + case) ──────────────────────────────────
t2=$(run_merge \
  '[{"id":"CVE-2023-0002","pkg":"axios","version":"v1.0.0","severity":"HIGH","found_by":"trivy","title":"T","cvss":null,"fix":""}]' \
  '[{"id":"cve-2023-0002","pkg":"axios","version":"1.0.0","severity":"HIGH","found_by":"grype","title":"G","cvss":null,"fix":""}]')
assert_eq "normalization: v-prefix + case-fold collapses" "1"    "$(echo "$t2" | jq 'length')"
assert_eq "normalization: found_by == both"               "both" "$(echo "$t2" | jq -r '.[0].found_by')"

# ── Test 3: Same-scanner dup guard ───────────────────────────────────────────
t3=$(run_merge \
  '[{"id":"CVE-2023-0003","pkg":"react","version":"18.0.0","severity":"HIGH","found_by":"trivy","title":"T1","cvss":null,"fix":""},
    {"id":"CVE-2023-0003","pkg":"react","version":"18.0.0","severity":"LOW","found_by":"trivy","title":"T2","cvss":null,"fix":""}]' \
  '[]')
assert_eq "same-scanner dup: output length == 1"    "1"     "$(echo "$t3" | jq 'length')"
assert_eq "same-scanner dup: found_by != both"      "trivy" "$(echo "$t3" | jq -r '.[0].found_by')"

# ── Test 4: Disjoint + counts ─────────────────────────────────────────────────
t4=$(run_merge \
  '[{"id":"CVE-2023-0010","pkg":"a","version":"1.0","severity":"HIGH","found_by":"trivy","title":"T","cvss":null,"fix":""}]' \
  '[{"id":"GHSA-xxxx-yyyy-zzzz","pkg":"b","version":"2.0","severity":"LOW","found_by":"grype","title":"G","cvss":null,"fix":""}]')
assert_eq "disjoint: total merged == 2"              "2"     "$(echo "$t4" | jq 'length')"
assert_eq "disjoint: trivy-only found_by=trivy"      "trivy" "$(echo "$t4" | jq -r '.[] | select(.id=="CVE-2023-0010") | .found_by')"
assert_eq "disjoint: grype-only found_by=grype"      "grype" "$(echo "$t4" | jq -r '.[] | select(.id=="GHSA-xxxx-yyyy-zzzz") | .found_by')"

# ── Test 5: Severity pick on merge (higher wins) ──────────────────────────────
t5=$(run_merge \
  '[{"id":"CVE-2023-0020","pkg":"pkg","version":"1.0","severity":"MEDIUM","found_by":"trivy","title":"T","cvss":null,"fix":""}]' \
  '[{"id":"CVE-2023-0020","pkg":"pkg","version":"1.0","severity":"CRITICAL","found_by":"grype","title":"G","cvss":null,"fix":""}]')
assert_eq "severity pick: CRITICAL beats MEDIUM"     "CRITICAL" "$(echo "$t5" | jq -r '.[0].severity')"
assert_eq "severity pick: found_by == both"          "both"     "$(echo "$t5" | jq -r '.[0].found_by')"

# ── Test 6: cvss/fix preserved across merge when severity-winner has null (WR-01) ─
# The lower-severity scanner (trivy) carries the real cvss + fix; the
# severity-winner (grype, CRITICAL) has null cvss + empty fix. The merged
# "both" record must retain the non-null cvss and the non-empty fix.
t6=$(run_merge \
  '[{"id":"CVE-2023-0030","pkg":"pkg","version":"1.0","severity":"HIGH","found_by":"trivy","title":"T","cvss":7.5,"fix":"1.2.3"}]' \
  '[{"id":"CVE-2023-0030","pkg":"pkg","version":"1.0","severity":"CRITICAL","found_by":"grype","title":"G","cvss":null,"fix":""}]')
assert_eq "cvss preserved: winner null, other 7.5 → 7.5"  "7.5"   "$(echo "$t6" | jq -r '.[0].cvss')"
assert_eq "fix preserved: winner empty, other 1.2.3"      "1.2.3" "$(echo "$t6" | jq -r '.[0].fix')"
assert_eq "cvss/fix preserve: found_by == both"           "both"  "$(echo "$t6" | jq -r '.[0].found_by')"

# ── Test 7: null id/pkg must not crash the merge (WR-02) ──────────────────────
# A record with null id and null pkg must be canon-keyed without aborting the
# whole program. Output must remain valid JSON containing both records.
t7=$(run_merge \
  '[{"id":null,"pkg":null,"version":"1.0","severity":"HIGH","found_by":"trivy","title":"T","cvss":null,"fix":""}]' \
  '[{"id":"CVE-2023-0040","pkg":"ok","version":"2.0","severity":"LOW","found_by":"grype","title":"G","cvss":null,"fix":""}]')
assert_eq "null id/pkg: output is valid JSON array"  "array" "$(echo "$t7" | jq -r 'type')"
assert_eq "null id/pkg: merge does not drop records" "2"     "$(echo "$t7" | jq 'length')"

# ── Test 8: grype normalization — GHSA→CVE aliasing + no-Primary-cvss crash ───
# Runs the SHARED lib/scanner.grype-normalize.jq (same file check.sh loads), so
# the test can never drift from production. Guards three bugs:
#  (a) crash: when no cvss entry is type=="Primary", a drifting `.` in the cvss
#      `//` fallback raised "Cannot index array with string vulnerability" and
#      silently dropped ALL grype findings.
#  (b) aliasing: a grype GHSA finding must adopt its related CVE as the id so it
#      dedups against the same Trivy CVE; a GHSA with no CVE alias keeps GHSA.
#  (c) WR-01: only a well-formed CVE id may be adopted — a malformed alias like
#      "CVENOTREAL-1" must NOT become the canonical id.
normalize_grype() {
  jq -f "$GRYPE_NORM_JQ"
}
# grype fixture: GHSA primary + related CVE, cvss has NO Primary entry (crash
# trigger); plus a github-action GHSA with no CVE alias.
gfix='{"matches":[
  {"vulnerability":{"id":"GHSA-mf9v-mfxr-j63j","severity":"High","cvss":[{"type":"Secondary","metrics":{"baseScore":7.5}}]},
   "relatedVulnerabilities":[{"id":"CVE-2026-44432"}],
   "artifact":{"name":"urllib3","version":"2.6.3"}},
  {"vulnerability":{"id":"GHSA-cxww-7g56-2vh6","severity":"High","cvss":[]},
   "relatedVulnerabilities":[],
   "artifact":{"name":"actions/download-artifact","version":"v4"}}
]}'
t8=$(echo "$gfix" | normalize_grype)
assert_eq "grype-norm: no crash, both rows kept"          "2"               "$(echo "$t8" | jq 'length')"
assert_eq "grype-norm: GHSA with related CVE → CVE id"    "CVE-2026-44432"  "$(echo "$t8" | jq -r '.[0].id')"
assert_eq "grype-norm: cvss survives no-Primary fallback" "7.5"             "$(echo "$t8" | jq -r '.[0].cvss')"
assert_eq "grype-norm: GHSA without CVE alias keeps GHSA" "GHSA-cxww-7g56-2vh6" "$(echo "$t8" | jq -r '.[1].id')"

# ── Test 9: end-to-end — aliased grype collapses with Trivy CVE into 'both' ────
t9=$(run_merge \
  '[{"id":"CVE-2026-44432","pkg":"urllib3","version":"2.6.3","severity":"HIGH","found_by":"trivy","title":"T","cvss":7.5,"fix":"2.7.0"}]' \
  "$(echo "$gfix" | normalize_grype | jq '[.[0]]')")
assert_eq "e2e alias: trivy CVE + grype GHSA→CVE == 1 row" "1"    "$(echo "$t9" | jq 'length')"
assert_eq "e2e alias: found_by == both"                    "both" "$(echo "$t9" | jq -r '.[0].found_by')"

# ── Test 10: WR-01 — malformed CVE-prefixed alias must NOT be adopted ─────────
# `startswith("CVE")` would wrongly adopt "CVENOTREAL-1" as the canonical id and
# mis-key the record. The anchored regex keeps the GHSA primary instead.
t10=$(echo '{"matches":[
  {"vulnerability":{"id":"GHSA-aaaa-bbbb-cccc","severity":"High","cvss":[]},
   "relatedVulnerabilities":[{"id":"CVENOTREAL-1"},{"id":"GHSA-dup"}],
   "artifact":{"name":"pkgx","version":"1.0"}}
]}' | normalize_grype)
assert_eq "WR-01: malformed CVE alias rejected, keeps GHSA primary" "GHSA-aaaa-bbbb-cccc" "$(echo "$t10" | jq -r '.[0].id')"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "Results: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
