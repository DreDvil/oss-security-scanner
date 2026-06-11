# scanner.grype-normalize.jq
# Normalizes a Grype JSON document (`grype --output json`) into the common vuln
# schema consumed by scanner.merge.jq. Input: the grype document. Output: array.
#
# Loaded via `jq -f` from both check.sh (merge_vulns) and
# tests/merge_vulns.test.sh so the production path and its regression tests
# share ONE source of truth (no hand-copied drift).
#
# Two correctness guarantees baked in:
#  1. Crash-safety: each match is bound to $m so the `.` context cannot drift
#     into the array literal inside the cvss `//` fallback. A drifting `.`
#     previously raised "Cannot index array with string vulnerability" whenever
#     no cvss entry was type=="Primary" (i.e. essentially every GHSA advisory),
#     and the swallowed error dropped ALL grype findings.
#  2. GHSA->CVE aliasing: the canonical id prefers a real CVE drawn from the
#     primary id or grype's relatedVulnerabilities, so a grype GHSA finding
#     dedups against the same Trivy CVE in scanner.merge.jq (which keys on
#     id+pkg+version). The `test("^CVE-...")` anchor rejects malformed ids like
#     "CVENOTREAL-1" so only a well-formed CVE is ever adopted. Falls back to
#     the primary id when there is no CVE alias (e.g. a github-action GHSA).
[
  .matches[]? as $m |
  {
    id: (( ( [ $m.vulnerability.id ] + [ $m.relatedVulnerabilities[]?.id ] )
           | map(select(type == "string" and test("^CVE-[0-9]{4}-[0-9]+$"))) | first )
         // $m.vulnerability.id),
    pkg: $m.artifact.name,
    version: ($m.artifact.version // ""),
    fix: "",
    severity: ($m.vulnerability.severity // "UNKNOWN" | ascii_upcase),
    title: ($m.vulnerability.description // "N/A"),
    found_by: "grype",
    cvss: (( [ $m.vulnerability.cvss[]? | select(.type == "Primary") | .metrics.baseScore ] | first
             // ($m.vulnerability.cvss[0]?.metrics.baseScore) // null ) | tonumber? // null)
  }
]
