# scanner.merge.jq
# Inputs: $trivy (array), $grype (array) — both normalized to common schema.
# Output: deduplicated array, sorted by severity descending.
#
# Canonical key: id uppercased, pkg lowercased+trimmed, version v-stripped+lowercased+trimmed.
# found_by: derived from SET of distinct scanner names in the group.

def sev_rank:
  if . == "CRITICAL"   then 5
  elif . == "HIGH"     then 4
  elif . == "MEDIUM"   then 3
  elif . == "LOW"      then 2
  elif . == "NEGLIGIBLE" then 1
  else 0 end;

def canon_key:
  {
    id:  ((.id // "")      | ascii_upcase   | ltrimstr(" ") | rtrimstr(" ")),
    pkg: ((.pkg // "")     | ascii_downcase | ltrimstr(" ") | rtrimstr(" ")),
    ver: ((.version // "") | ascii_downcase | ltrimstr("v") | ltrimstr(" ") | rtrimstr(" "))
  };

($trivy + $grype)
| map(. + {_key: canon_key})
| group_by(._key)
| map(
    . as $grp |
    (map(.found_by) | unique | sort) as $scanners |
    (if ($scanners | length) > 1 then "both" else $scanners[0] end) as $fb |
    (sort_by(.severity | sev_rank) | last) as $win |
    $win + {
      found_by: $fb,
      cvss: ([$grp[].cvss] | map(select(. != null)) | first // null),
      fix:  ([$grp[].fix]  | map(select(. != null and . != "")) | first // "")
    } | del(._key)
  )
| sort_by(.severity | sev_rank) | reverse
