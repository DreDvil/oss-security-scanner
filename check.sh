#!/usr/bin/env bash
# =============================================================================
# check.sh — Open Source Software Security Scanner
# Checks: VirusTotal · Semgrep · Trivy
# Requirements: docker, git, curl, jq
# =============================================================================
set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()      { echo -e "${GREEN}[ OK ]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[FAIL]${NC} $*"; }
log_section() { echo -e "\n${BOLD}${CYAN}━━━ $* ━━━${NC}\n"; }

# ── Docker image versions ─────────────────────────────────────────────────────
SEMGREP_IMAGE="semgrep/semgrep:latest"
TRIVY_IMAGE="aquasec/trivy:latest"
VT_IMAGE_LOCAL="vt-cli:local"      # built locally from Dockerfile.vt

# ── Global state ──────────────────────────────────────────────────────────────
TARGET=""
TARGET_REF=""    # specific tag/branch to scan (empty = default branch HEAD)
WORK_DIR=""
REPORT_DIR=""
VT_API_KEY="${VT_API_KEY:-}"

# Result variables (set by each scanner)
SEMGREP_STATUS="skipped"; SEMGREP_FINDINGS=0; SEMGREP_ERRORS=0
TRIVY_STATUS="skipped";   TRIVY_CRITICAL=0; TRIVY_HIGH=0; TRIVY_MEDIUM=0; TRIVY_LOW=0; TRIVY_SECRETS=0
VT_STATUS="skipped";      VT_MALICIOUS=0;   VT_TOTAL=0

# ── Usage ─────────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
${BOLD}Usage:${NC}
  $(basename "$0") <github_url> [options]

${BOLD}Examples:${NC}
  $(basename "$0") https://github.com/cli/cli
  $(basename "$0") https://github.com/cli/cli --release v2.45.0
  VT_API_KEY=xxx $(basename "$0") https://github.com/sigstore/cosign --release v2.2.4
  $(basename "$0") https://github.com/golang/go --no-vt

${BOLD}Options:${NC}
  --release TAG   Scan a specific release tag or branch (default: HEAD)
  --no-semgrep    Skip Semgrep scan
  --no-trivy      Skip Trivy scan
  --no-vt         Skip VirusTotal scan
  --vt-key KEY    VirusTotal API key (overrides VT_API_KEY env)

${BOLD}Environment:${NC}
  VT_API_KEY      VirusTotal API key (free tier: 4 req/min)
EOF
  exit 1
}

# ── Dependency check ──────────────────────────────────────────────────────────
check_deps() {
  local missing=0
  for cmd in docker git curl jq; do
    if ! command -v "$cmd" &>/dev/null; then
      log_error "Missing required dependency: $cmd"
      missing=1
    fi
  done
  [[ $missing -eq 1 ]] && exit 1

  if ! docker info &>/dev/null; then
    log_error "Docker daemon is not running"
    exit 1
  fi
}

# ── Setup directories ─────────────────────────────────────────────────────────
setup_workdir() {
  WORK_DIR=$(mktemp -d /tmp/check_oss_XXXXXX)
  local safe_name safe_ref=""
  safe_name=$(echo "$TARGET" | sed 's|https://github.com/||g; s|[^a-zA-Z0-9._-]|_|g' | cut -c1-50)
  [[ -n "$TARGET_REF" ]] && safe_ref="_$(echo "$TARGET_REF" | sed 's|[^a-zA-Z0-9._-]|_|g' | cut -c1-20)"
  REPORT_DIR="$(pwd)/reports/$(date +%Y%m%d_%H%M%S)_${safe_name}${safe_ref}"
  mkdir -p "$REPORT_DIR"
  log_info "Working directory : $WORK_DIR"
  log_info "Report directory  : $REPORT_DIR"
}

cleanup() {
  [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]] && rm -rf "$WORK_DIR"
}

# ── Parse GitHub URL → owner/repo ─────────────────────────────────────────────
parse_github_url() {
  # Accepts: https://github.com/owner/repo or https://github.com/owner/repo.git
  local url="$1"
  url="${url%.git}"
  url="${url%/}"
  echo "${url#https://github.com/}"   # → owner/repo
}

# ── Clone repository ──────────────────────────────────────────────────────────
clone_repo() {
  if [[ -n "$TARGET_REF" ]]; then
    log_info "Cloning $TARGET @ ${TARGET_REF} …"
    git clone --depth 1 --branch "$TARGET_REF" --quiet "$TARGET" "$WORK_DIR/source" 2>&1 || {
      log_error "Failed to clone repository at ref '${TARGET_REF}' — check tag/branch name"
      exit 1
    }
    log_ok "Cloned tag/branch: ${TARGET_REF}"
  else
    log_info "Cloning $TARGET (default branch) …"
    git clone --depth 1 --quiet "$TARGET" "$WORK_DIR/source" 2>&1 || {
      log_error "Failed to clone repository"
      exit 1
    }
    log_ok "Cloned HEAD of default branch"
  fi
}

# ── Semgrep ───────────────────────────────────────────────────────────────────
run_semgrep() {
  log_section "Semgrep — Static Code Analysis"

  local out="$REPORT_DIR/semgrep.json"

  local semgrep_log="$REPORT_DIR/semgrep.log"

  # semgrep exits 1 when findings exist — that is expected
  # NOTE: --quiet removed because it suppresses JSON stdout in semgrep ≥1.x
  # Try cloud ruleset first; suppress stderr noise during the attempt
  docker run --rm \
    -v "$WORK_DIR/source:/src:ro" \
    "$SEMGREP_IMAGE" \
    semgrep scan \
      --config=auto \
      --json \
      --metrics=off \
      --exclude 'Dockerfile*' \
      --exclude '*.dockerfile' \
      /src > "$out" 2>"$semgrep_log" || true

  # If JSON output is empty or invalid, fall back to bundled p/default ruleset
  # (--config=auto downloads rules from semgrep.dev; may fail in air-gapped/rate-limited envs)
  if [[ ! -s "$out" ]] || ! jq -e '.results' "$out" &>/dev/null; then
    log_info "Falling back to bundled p/default ruleset"
    docker run --rm \
      -v "$WORK_DIR/source:/src:ro" \
      "$SEMGREP_IMAGE" \
      semgrep scan \
        --config=p/default \
        --json \
        --metrics=off \
        --exclude 'Dockerfile*' \
        --exclude '*.dockerfile' \
        /src > "$out" 2>>"$semgrep_log" || true
  fi

  if [[ ! -s "$out" ]] || ! jq -e '.results' "$out" &>/dev/null; then
    log_warn "Semgrep produced no usable output — see semgrep.log"
    SEMGREP_STATUS="error"
    return
  fi

  SEMGREP_FINDINGS=$(jq '[.results[]] | length' "$out" 2>/dev/null || echo 0)
  SEMGREP_ERRORS=$(jq '[.errors[]] | length' "$out" 2>/dev/null || echo 0)

  if [[ "$SEMGREP_FINDINGS" -eq 0 ]]; then
    log_ok "No findings"
    SEMGREP_STATUS="pass"
  else
    log_warn "$SEMGREP_FINDINGS finding(s)"
    # Print top findings
    jq -r '.results[:10][] | "  [\(.extra.severity // "?")] \(.check_id): \(.path):\(.start.line)"' \
      "$out" 2>/dev/null || true
    SEMGREP_STATUS="warn"
  fi
}

# ── Trivy ─────────────────────────────────────────────────────────────────────
run_trivy() {
  log_section "Trivy — Dependency & Secret Scan"

  local out="$REPORT_DIR/trivy_fs.json"

  docker run --rm \
    -v "$WORK_DIR/source:/target:ro" \
    -v "$REPORT_DIR:/reports" \
    "$TRIVY_IMAGE" \
    fs \
      --format json \
      --output /reports/trivy_fs.json \
      --scanners vuln,secret,misconfig \
      --quiet \
      /target 2>/dev/null || true

  if [[ ! -s "$out" ]]; then
    log_warn "Trivy produced no output"
    TRIVY_STATUS="error"
    return
  fi

  TRIVY_CRITICAL=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' "$out" 2>/dev/null || echo 0)
  TRIVY_HIGH=$(jq     '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")]     | length' "$out" 2>/dev/null || echo 0)
  TRIVY_MEDIUM=$(jq   '[.Results[]?.Vulnerabilities[]? | select(.Severity=="MEDIUM")]   | length' "$out" 2>/dev/null || echo 0)
  TRIVY_LOW=$(jq      '[.Results[]?.Vulnerabilities[]? | select(.Severity=="LOW")]      | length' "$out" 2>/dev/null || echo 0)
  TRIVY_SECRETS=$(jq  '[.Results[]?.Secrets[]?]                                         | length' "$out" 2>/dev/null || echo 0)

  echo -e "  Vulnerabilities — ${RED}CRITICAL: $TRIVY_CRITICAL${NC}  ${YELLOW}HIGH: $TRIVY_HIGH${NC}  MEDIUM: $TRIVY_MEDIUM  LOW: $TRIVY_LOW"
  echo -e "  Secrets detected: $TRIVY_SECRETS"

  if [[ "$TRIVY_CRITICAL" -gt 0 || "$TRIVY_SECRETS" -gt 0 ]]; then
    TRIVY_STATUS="fail"
    if [[ "$TRIVY_CRITICAL" -gt 0 ]]; then
      log_error "Critical vulnerabilities:"
      jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL") |
        "  [\(.VulnerabilityID)] \(.PkgName)@\(.InstalledVersion // "?"): \(.Title // "N/A")"' \
        "$out" 2>/dev/null | head -10 || true
    fi
    if [[ "$TRIVY_SECRETS" -gt 0 ]]; then
      log_error "Secrets found in source code!"
      jq -r '.Results[]?.Secrets[]? | "  [\(.Severity)] \(.Title): \(.Match // "")"' \
        "$out" 2>/dev/null | head -5 || true
    fi
  elif [[ "$TRIVY_HIGH" -gt 0 ]]; then
    TRIVY_STATUS="warn"
    log_warn "High vulnerabilities found"
  else
    TRIVY_STATUS="pass"
    log_ok "No critical issues"
  fi
}

# ── VirusTotal (vt-cli) ───────────────────────────────────────────────────────

# Build the vt-cli Docker image from Dockerfile.vt if not already present.
ensure_vt_image() {
  if docker image inspect "$VT_IMAGE_LOCAL" &>/dev/null 2>&1; then
    log_info "vt-cli image already built: $VT_IMAGE_LOCAL"
    return
  fi

  local dockerfile
  dockerfile="$(dirname "$0")/Dockerfile.vt"
  if [[ ! -f "$dockerfile" ]]; then
    log_error "Dockerfile.vt not found at $dockerfile"
    VT_STATUS="error"
    return 1
  fi

  log_info "Building vt-cli image (first run, ~1–2 min)…"
  docker build -t "$VT_IMAGE_LOCAL" -f "$dockerfile" "$(dirname "$0")" \
    2>&1 | grep -E 'Step|error|Error|=>|DONE' || true
  log_ok "vt-cli image built: $VT_IMAGE_LOCAL"
}

# Helper: extract numeric value of <field> from vt-cli last_analysis_stats block
_vt_stat() {
  local field="$1"
  awk -v f="$field" '
    /last_analysis_stats:/   { in_stats=1; next }
    in_stats && /^[^ \t]/    { in_stats=0 }
    in_stats && $0 ~ (f ":") { gsub(/[^0-9]/, "", $NF); print $NF+0; exit }
  '
}

run_virustotal() {
  log_section "VirusTotal — Malware Scan (vt-cli)"

  if [[ -z "$VT_API_KEY" ]]; then
    log_warn "VT_API_KEY not set — skipping (add to .env or use --vt-key)"
    return
  fi

  ensure_vt_image || return

  # Create source archive
  log_info "Creating source archive…"
  local archive="$WORK_DIR/source.tar.gz"
  tar -czf "$archive" -C "$WORK_DIR" source 2>/dev/null

  local size
  size=$(wc -c < "$archive")
  log_info "Archive size: $(( size / 1024 / 1024 )) MB"

  if [[ "$size" -gt 671088640 ]]; then
    log_warn "Archive > 650 MB — skipping VT upload"
    VT_STATUS="skipped_too_large"
    return
  fi

  # Calculate SHA256 and check cache first
  local sha256
  sha256=$(sha256sum "$archive" | awk '{print $1}')
  log_info "SHA256: $sha256"

  local vt_out
  # vt-cli reads the key from -k/--apikey flag (NOT VT_API_KEY env var)
  vt_out=$(docker run --rm \
    "$VT_IMAGE_LOCAL" \
    -k "$VT_API_KEY" file "$sha256" 2>&1 || true)

  if echo "$vt_out" | grep -qiE 'NotFoundError|not found|404'; then
    # Not in VT database — upload and wait for results
    log_info "Not in VT database — uploading and scanning (--wait)…"
    vt_out=$(docker run --rm \
      -v "$WORK_DIR:/work:ro" \
      "$VT_IMAGE_LOCAL" \
      -k "$VT_API_KEY" scan file --wait /work/source.tar.gz 2>&1 || true)
    log_info "Analysis complete"
  elif echo "$vt_out" | grep -qiE 'API key|apikey|invalid|forbidden|401|403'; then
    log_error "VirusTotal API key error: $(echo "$vt_out" | head -1)"
    VT_STATUS="error"
    return
  else
    log_ok "Found in VirusTotal cache"
  fi

  # Save raw output (includes full vt-cli YAML-like response)
  echo "$vt_out" > "$REPORT_DIR/virustotal.txt"

  # Parse stats from vt-cli YAML-like output (section-aware via _vt_stat helper above)
  VT_MALICIOUS=$(echo "$vt_out" | _vt_stat "malicious");        VT_MALICIOUS="${VT_MALICIOUS:-0}"
  local vt_harmless="" vt_suspicious="" vt_undetected="" vt_timeout="" vt_unsupp="" vt_failure="" vt_ctimeout=""
  vt_harmless=$(   echo "$vt_out" | _vt_stat "harmless");        vt_harmless="${vt_harmless:-0}"
  vt_suspicious=$( echo "$vt_out" | _vt_stat "suspicious");      vt_suspicious="${vt_suspicious:-0}"
  vt_undetected=$( echo "$vt_out" | _vt_stat "undetected");      vt_undetected="${vt_undetected:-0}"
  vt_timeout=$(    echo "$vt_out" | _vt_stat "timeout");         vt_timeout="${vt_timeout:-0}"
  vt_unsupp=$(     echo "$vt_out" | _vt_stat "type-unsupported"); vt_unsupp="${vt_unsupp:-0}"
  vt_failure=$(    echo "$vt_out" | _vt_stat "failure");         vt_failure="${vt_failure:-0}"
  vt_ctimeout=$(   echo "$vt_out" | _vt_stat "confirmed-timeout"); vt_ctimeout="${vt_ctimeout:-0}"
  VT_TOTAL=$(( VT_MALICIOUS + vt_harmless + vt_suspicious + vt_undetected + vt_timeout + vt_unsupp + vt_failure + vt_ctimeout ))

  if [[ "$VT_MALICIOUS" -eq 0 ]]; then
    log_ok "Clean — $VT_MALICIOUS/$VT_TOTAL engines flagged"
    VT_STATUS="pass"
  else
    log_error "MALWARE DETECTED: $VT_MALICIOUS/$VT_TOTAL engines flagged"
    VT_STATUS="fail"
  fi
}

# ── HTML Report ───────────────────────────────────────────────────────────────
status_badge() {
  # status_badge <status> → HTML span (for report)
  case "$1" in
    pass)             echo '<span class="badge pass">PASS</span>' ;;
    warn)             echo '<span class="badge warn">WARN</span>' ;;
    fail)             echo '<span class="badge fail">FAIL</span>' ;;
    skipped*|no_*)    echo '<span class="badge skip">SKIP</span>' ;;
    error)            echo '<span class="badge warn">ERROR</span>' ;;
    *)                echo '<span class="badge skip">N/A</span>' ;;
  esac
}

term_badge() {
  # term_badge <status> → ANSI-colored text (for terminal output)
  case "$1" in
    pass)          echo -e "${GREEN}[PASS]${NC}" ;;
    warn)          echo -e "${YELLOW}[WARN]${NC}" ;;
    fail)          echo -e "${RED}[FAIL]${NC}" ;;
    skipped*|no_*) echo -e "\033[0;90m[SKIP]${NC}" ;;
    error)         echo -e "${YELLOW}[ERR ]${NC}" ;;
    *)             echo -e "\033[0;90m[ -- ]${NC}" ;;
  esac
}

overall_status() {
  local s="PASS"
  [[ "$SEMGREP_STATUS" == "fail" || "$TRIVY_STATUS" == "fail" || "$VT_STATUS" == "fail" ]] && s="FAIL"
  [[ "$s" != "FAIL" ]] && {
    [[ "$SEMGREP_STATUS" == "warn" || "$TRIVY_STATUS" == "warn" || "$VT_STATUS" == "warn" ]] && s="WARN"
  }
  echo "$s"
}

semgrep_rows_html() {
  [[ ! -s "$REPORT_DIR/semgrep.json" ]] && return
  jq -r '.results[:50][] |
    "<tr>
      <td class=\"sev-\(.extra.severity | ascii_downcase)\">\(.extra.severity // "?")</td>
      <td><code>\(.check_id)</code></td>
      <td>\(.path):\(.start.line)</td>
      <td>\(.extra.message | gsub("<";"&lt;") | gsub(">";"&gt;") | .[0:120])</td>
    </tr>"' "$REPORT_DIR/semgrep.json" 2>/dev/null || true
}

trivy_rows_html() {
  [[ ! -s "$REPORT_DIR/trivy_fs.json" ]] && return
  jq -r '.Results[]? | .Vulnerabilities[]? |
    "<tr>
      <td class=\"sev-\(.Severity | ascii_downcase)\">\(.Severity)</td>
      <td><code>\(.VulnerabilityID)</code></td>
      <td>\(.PkgName) \(.InstalledVersion // "")</td>
      <td>\(.FixedVersion // "—")</td>
      <td>\(.Title // "N/A" | gsub("<";"&lt;") | gsub(">";"&gt;") | .[0:100])</td>
    </tr>"' "$REPORT_DIR/trivy_fs.json" 2>/dev/null | head -200 || true
}

trivy_secrets_html() {
  [[ ! -s "$REPORT_DIR/trivy_fs.json" ]] && return
  jq -r '.Results[]? | .Secrets[]? |
    "<tr>
      <td class=\"sev-\(.Severity | ascii_downcase)\">\(.Severity)</td>
      <td>\(.Title | gsub("<";"&lt;"))</td>
      <td><code>\(.Match | gsub("<";"&lt;") | .[0:80])</code></td>
    </tr>"' "$REPORT_DIR/trivy_fs.json" 2>/dev/null || true
}

vt_stats_html() {
  [[ ! -s "$REPORT_DIR/virustotal.txt" ]] && echo "<p>No data</p>" && return
  # Parse key: value lines from vt-cli text output
  local fields="malicious suspicious harmless undetected timeout failure type-unsupported confirmed-timeout"
  for field in $fields; do
    local val
    val=$(awk "/^[[:space:]]*${field}:/{print \$2+0; exit}" "$REPORT_DIR/virustotal.txt" 2>/dev/null || echo "")
    [[ -z "$val" ]] && continue
    local cls=""
    [[ "$field" == "malicious"  && "$val" -gt 0 ]] && cls=' style="color:var(--fail);font-weight:700"'
    [[ "$field" == "suspicious" && "$val" -gt 0 ]] && cls=' style="color:var(--warn);font-weight:600"'
    echo "<tr><td${cls}>${field}</td><td${cls}>${val}</td></tr>"
  done
}

generate_report() {
  local overall
  overall=$(overall_status)
  local gh_repo
  gh_repo=$(parse_github_url "$TARGET")

  local overall_class verdict_desc
  case "$overall" in
    PASS)
      overall_class="pass"
      verdict_desc="All scanners passed — no critical issues detected"
      ;;
    WARN)
      overall_class="warn"
      verdict_desc="One or more scanners found non-critical issues that require review"
      ;;
    *)
      overall_class="fail"
      verdict_desc="Critical issues detected — malware, critical CVEs, or secrets found"
      ;;
  esac

  local semgrep_badge trivy_badge vt_badge
  semgrep_badge=$(status_badge "$SEMGREP_STATUS")
  trivy_badge=$(status_badge "$TRIVY_STATUS")
  vt_badge=$(status_badge "$VT_STATUS")

  cat > "$REPORT_DIR/report.html" <<HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Scan — ${gh_repo}</title>
<style>
  :root {
    --pass:#22c55e; --warn:#f59e0b; --fail:#ef4444; --skip:#64748b;
    --bg:#080d18; --surface:#0f172a; --surface2:#162032;
    --border:#1e2d45; --text:#e2e8f0; --muted:#64748b; --code:#7dd3fc;
    --r:12px;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
       background:var(--bg);color:var(--text);font-size:14px;min-height:100vh}
  a{color:var(--code);text-decoration:none}
  a:hover{text-decoration:underline}

  /* ── Page wrapper ── */
  .page{max-width:980px;margin:0 auto;padding:2.5rem 1.5rem}

  /* ── Hero ── */
  .hero{
    background:var(--surface);border:1px solid var(--border);border-radius:var(--r);
    padding:2.5rem 2rem 2rem;text-align:center;margin-bottom:1.75rem;
  }
  .hero h1{font-size:1.55rem;font-weight:800;letter-spacing:-0.4px;margin-bottom:1.5rem}

  /* ── Hero info blocks (Target / Ref / Date) ── */
  .hero-info{display:flex;justify-content:center;gap:0.75rem;flex-wrap:wrap;margin-bottom:1.5rem}
  .info-block{
    background:var(--surface2);border:1px solid var(--border);border-radius:8px;
    padding:0.55rem 1.2rem;text-align:center;min-width:160px;
  }
  .info-label{font-size:0.63rem;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:0.3rem}
  .info-val{font-size:0.88rem;font-weight:600;color:var(--text)}
  .info-val a{color:var(--code)}
  .info-val code{font-size:0.85rem}

  /* ── Verdict block ── */
  .verdict-block{
    display:inline-flex;align-items:center;gap:1.1rem;
    padding:0.8rem 2rem;border-radius:10px;margin-top:0.25rem;
  }
  .verdict-block.verdict-pass{background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.28)}
  .verdict-block.verdict-warn{background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.28)}
  .verdict-block.verdict-fail{background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.28)}
  .verdict-label{font-size:1.05rem;font-weight:800;letter-spacing:1.5px}
  .verdict-block.verdict-pass .verdict-label{color:var(--pass)}
  .verdict-block.verdict-warn .verdict-label{color:var(--warn)}
  .verdict-block.verdict-fail .verdict-label{color:var(--fail)}
  .verdict-sep{width:1px;height:1.6rem;background:var(--border)}
  .verdict-desc{font-size:0.82rem;color:var(--muted);text-align:left;max-width:360px}

  /* ── Metric strip ── */
  .metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1.75rem}
  .metric{
    background:var(--surface);border:1px solid var(--border);border-radius:var(--r);
    padding:1.4rem 1rem;text-align:center;
  }
  .metric-label{font-size:0.68rem;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:0.6rem}
  .metric-num{font-size:2.4rem;font-weight:800;line-height:1;margin-bottom:0.35rem}
  .metric-num.green{color:var(--pass)}
  .metric-num.yellow{color:var(--warn)}
  .metric-num.red{color:var(--fail)}
  .metric-sub{font-size:0.75rem;color:var(--muted);margin-bottom:0.7rem}

  /* ── Badges ── */
  .badge{
    display:inline-flex;align-items:center;gap:4px;
    padding:3px 10px;border-radius:5px;font-size:0.68rem;font-weight:700;letter-spacing:0.6px;
  }
  .badge.pass{background:rgba(34,197,94,.12);color:var(--pass);border:1px solid rgba(34,197,94,.25)}
  .badge.warn{background:rgba(245,158,11,.12);color:var(--warn);border:1px solid rgba(245,158,11,.25)}
  .badge.fail{background:rgba(239,68,68,.12);color:var(--fail);border:1px solid rgba(239,68,68,.25)}
  .badge.skip{background:rgba(100,116,139,.12);color:var(--skip);border:1px solid rgba(100,116,139,.25)}

  /* ── Module ── */
  .module{
    background:var(--surface);border:1px solid var(--border);
    border-radius:var(--r);margin-bottom:1.25rem;overflow:hidden;
  }
  .mod-head{
    display:flex;align-items:center;justify-content:space-between;
    padding:0.85rem 1.4rem;background:var(--surface2);
    border-bottom:1px solid var(--border);
  }
  .mod-title{font-size:0.9rem;font-weight:700;display:flex;align-items:center;gap:0.5rem}
  .mod-icon{font-size:1rem}
  .mod-body{padding:1.25rem 1.4rem}

  /* ── Tables ── */
  table{width:100%;border-collapse:collapse;font-size:0.83rem}
  th{
    background:var(--surface2);color:var(--muted);text-align:left;
    padding:0.5rem 0.75rem;font-weight:600;
    border-bottom:2px solid var(--border);
    font-size:0.7rem;text-transform:uppercase;letter-spacing:0.5px;
  }
  td{padding:0.45rem 0.75rem;border-bottom:1px solid var(--border);vertical-align:top}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:var(--surface2)}
  code{color:var(--code);font-size:0.8rem;font-family:"SF Mono",Menlo,monospace}

  /* ── Severity ── */
  .sev-critical{color:var(--fail);font-weight:700}
  .sev-high{color:#f97316;font-weight:600}
  .sev-medium{color:var(--warn)}
  .sev-low{color:var(--muted)}
  .sev-error{color:var(--fail);font-weight:700}
  .sev-warning{color:var(--warn)}
  .sev-info{color:#60a5fa}

  /* ── Accordion ── */
  details{margin-bottom:0.6rem}
  summary{
    cursor:pointer;padding:0.55rem 0;font-weight:600;font-size:0.88rem;
    list-style:none;display:flex;align-items:center;gap:0.5rem;user-select:none;
  }
  summary::-webkit-details-marker{display:none}
  summary::before{content:"▶";font-size:0.6rem;color:var(--muted);transition:transform .18s;flex-shrink:0}
  details[open] summary::before{transform:rotate(90deg)}

  /* ── Status messages ── */
  .msg{padding:0.6rem 0;font-size:0.88rem}
  .msg.ok{color:var(--pass)}
  .msg.warn{color:var(--warn)}
  .msg.muted{color:var(--muted);font-style:italic}

  /* ── Raw link ── */
  .raw-link{display:block;margin-top:0.75rem;font-size:0.78rem;color:var(--muted)}
  .raw-link a{color:var(--muted)}
  .raw-link a:hover{color:var(--code)}

  /* ── Footer ── */
  footer{
    text-align:center;padding:1.5rem 0;
    color:var(--muted);font-size:0.78rem;
    border-top:1px solid var(--border);margin-top:0.5rem;
  }

  @media(max-width:600px){
    .metrics{grid-template-columns:1fr}
    .hero-info{flex-direction:column;align-items:center}
    .verdict-block{flex-direction:column;gap:0.5rem;text-align:center}
    .verdict-sep{display:none}
    .verdict-desc{text-align:center}
  }
</style>
</head>
<body>
<div class="page">

<!-- ── Hero ── -->
<div class="hero">
  <h1>🔍 Security Scan Report</h1>

  <!-- Info blocks -->
  <div class="hero-info">
    <div class="info-block">
      <div class="info-label">Target</div>
      <div class="info-val"><a href="${TARGET}" target="_blank">${gh_repo}</a></div>
    </div>
    <div class="info-block">
      <div class="info-label">Ref</div>
      <div class="info-val"><code>$([ -n "$TARGET_REF" ] && echo "${TARGET_REF}" || echo "HEAD")</code></div>
    </div>
    <div class="info-block">
      <div class="info-label">Date</div>
      <div class="info-val">$(date -u "+%Y-%m-%d %H:%M UTC")</div>
    </div>
  </div>

  <!-- Verdict block -->
  <div class="verdict-block verdict-${overall_class}">
    <div class="verdict-label">${overall}</div>
    <div class="verdict-sep"></div>
    <div class="verdict-desc">${verdict_desc}</div>
  </div>
</div>

<!-- ── Metrics ── -->
<div class="metrics">
  <div class="metric">
    <div class="metric-label">VirusTotal</div>
    <div class="metric-num $([ "$VT_MALICIOUS" -gt 0 ] && echo red || echo green)">${VT_MALICIOUS}</div>
    <div class="metric-sub">malicious / ${VT_TOTAL} engines</div>
    ${vt_badge}
  </div>
  <div class="metric">
    <div class="metric-label">Semgrep</div>
    <div class="metric-num $([ "$SEMGREP_FINDINGS" -gt 0 ] && echo yellow || echo green)">${SEMGREP_FINDINGS}</div>
    <div class="metric-sub">code findings</div>
    ${semgrep_badge}
  </div>
  <div class="metric">
    <div class="metric-label">Trivy</div>
    <div class="metric-num $([ "$TRIVY_CRITICAL" -gt 0 ] && echo red || [ "$TRIVY_HIGH" -gt 0 ] && echo yellow || echo green)">${TRIVY_CRITICAL} / ${TRIVY_HIGH}</div>
    <div class="metric-sub">critical / high &nbsp;·&nbsp; +${TRIVY_MEDIUM} med &nbsp;${TRIVY_LOW} low</div>
    ${trivy_badge}
  </div>
</div>

<!-- ══════════════════════════════════════
     MODULE: VirusTotal
     ══════════════════════════════════════ -->
<div class="module">
  <div class="mod-head">
    <div class="mod-title"><span class="mod-icon">🦠</span> VirusTotal <span style="color:var(--muted);font-weight:400;font-size:0.78rem">(vt-cli)</span></div>
    ${vt_badge}
  </div>
  <div class="mod-body">
    $([ "$VT_STATUS" == "skipped" ]           && echo '<p class="msg muted">Skipped — set <code>VT_API_KEY</code> in <code>.env</code> or use <code>--vt-key</code></p>' || true)
    $([ "$VT_STATUS" == "skipped_too_large" ] && echo '<p class="msg muted">Skipped — archive &gt; 650 MB</p>' || true)
    $([ "$VT_STATUS" == "error" ]             && echo '<p class="msg warn">Error — check API key or rebuild vt-cli image</p>' || true)
    $([ -s "$REPORT_DIR/virustotal.txt" ] && echo "
    <table>
      <thead><tr><th>Category</th><th>Count</th></tr></thead>
      <tbody>$(vt_stats_html)</tbody>
    </table>" || true)
    <div class="raw-link">📄 <a href="virustotal.txt" target="_blank">Raw vt-cli output</a></div>
  </div>
</div>

<!-- ══════════════════════════════════════
     MODULE: Semgrep
     ══════════════════════════════════════ -->
<div class="module">
  <div class="mod-head">
    <div class="mod-title"><span class="mod-icon">🔎</span> Semgrep — Static Analysis</div>
    ${semgrep_badge}
  </div>
  <div class="mod-body">
    $([ "$SEMGREP_STATUS" == "pass"  ] && echo '<p class="msg ok">✓ No findings</p>' || true)
    $([ "$SEMGREP_STATUS" == "error" ] && echo '<p class="msg warn">Scanner error — check Docker logs</p>' || true)
    $([ "$SEMGREP_FINDINGS" -gt 0 ] && echo "
    <details open>
      <summary>${SEMGREP_FINDINGS} finding(s) — showing up to 50</summary>
      <table>
        <thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Message</th></tr></thead>
        <tbody>$(semgrep_rows_html)</tbody>
      </table>
    </details>" || true)
    <div class="raw-link">📄 <a href="semgrep.json" target="_blank">Raw JSON</a></div>
  </div>
</div>

<!-- ══════════════════════════════════════
     MODULE: Trivy
     ══════════════════════════════════════ -->
<div class="module">
  <div class="mod-head">
    <div class="mod-title"><span class="mod-icon">🛡️</span> Trivy — Dependencies &amp; Secrets</div>
    ${trivy_badge}
  </div>
  <div class="mod-body">
    $([ "$TRIVY_STATUS" == "pass"  ] && echo '<p class="msg ok">✓ No critical issues</p>' || true)
    $([ "$TRIVY_STATUS" == "error" ] && echo '<p class="msg warn">Scanner error — check Docker logs</p>' || true)

    $([ "$(( TRIVY_CRITICAL + TRIVY_HIGH + TRIVY_MEDIUM + TRIVY_LOW ))" -gt 0 ] && echo "
    <details open>
      <summary>Vulnerabilities — ${TRIVY_CRITICAL} critical &nbsp;/&nbsp; ${TRIVY_HIGH} high &nbsp;/&nbsp; ${TRIVY_MEDIUM} medium &nbsp;/&nbsp; ${TRIVY_LOW} low</summary>
      <table>
        <thead><tr><th>Severity</th><th>CVE</th><th>Package</th><th>Fix</th><th>Title</th></tr></thead>
        <tbody>$(trivy_rows_html)</tbody>
      </table>
    </details>" || true)

    $([ "$TRIVY_SECRETS" -gt 0 ] && echo "
    <details open>
      <summary>⚠ ${TRIVY_SECRETS} secret(s) detected in source</summary>
      <table>
        <thead><tr><th>Severity</th><th>Type</th><th>Match</th></tr></thead>
        <tbody>$(trivy_secrets_html)</tbody>
      </table>
    </details>" || true)

    <div class="raw-link">📄 <a href="trivy_fs.json" target="_blank">Raw JSON</a></div>
  </div>
</div>

<footer>check.sh &nbsp;·&nbsp; $(date -u "+%Y-%m-%d %H:%M UTC")</footer>

</div><!-- /page -->
</body>
</html>
HTMLEOF

  log_ok "HTML report: file://$REPORT_DIR/report.html"
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
  TARGET="${1:-}"
  [[ -z "$TARGET" ]] && usage
  shift

  # Validate target looks like a GitHub URL
  if [[ "$TARGET" != https://github.com/* ]]; then
    log_error "Target must be a GitHub URL (https://github.com/owner/repo)"
    exit 1
  fi

  # 1. Load .env (lowest precedence: environment file)
  local env_file
  env_file="$(dirname "$0")/.env"
  if [[ -f "$env_file" ]]; then
    # shellcheck source=/dev/null
    source "$env_file"
    log_info "Loaded $env_file"
  fi

  # 2. Parse CLI flags (highest precedence — override .env)
  local RUN_SEMGREP=true RUN_TRIVY=true RUN_VT=true
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --release)     TARGET_REF="$2"; shift ;;
      --no-semgrep)  RUN_SEMGREP=false ;;
      --no-trivy)    RUN_TRIVY=false ;;
      --no-vt)       RUN_VT=false ;;
      --vt-key)      VT_API_KEY="$2"; shift ;;
      *) log_warn "Unknown option: $1" ;;
    esac
    shift
  done

  echo -e "${BOLD}${CYAN}"
  echo "╔══════════════════════════════════════════════╗"
  echo "║   OSS Security Scanner                       ║"
  echo "║   VirusTotal · Semgrep · Trivy               ║"
  echo "╚══════════════════════════════════════════════╝"
  echo -e "${NC}"
  log_info "Target : $TARGET"
  [[ -n "$TARGET_REF" ]] && log_info "Ref    : $TARGET_REF" || log_info "Ref    : HEAD (default branch)"
  [[ -z "$VT_API_KEY" ]] && log_warn "VT_API_KEY not set — VirusTotal scan will be skipped"

  check_deps
  setup_workdir
  # Always generate HTML report on exit — even if a scanner crashes
  trap 'generate_report 2>/dev/null || true; cleanup' EXIT

  clone_repo

  [[ "$RUN_SEMGREP" == true ]] && run_semgrep || true
  [[ "$RUN_TRIVY"   == true ]] && run_trivy   || true
  [[ "$RUN_VT"      == true ]] && run_virustotal || true

  generate_report

  local overall
  overall=$(overall_status)
  echo ""
  log_section "FINAL RESULT: $overall"
  echo -e "  VirusTotal  : $(term_badge "$VT_STATUS")  malicious=$VT_MALICIOUS/$VT_TOTAL"
  echo -e "  Semgrep     : $(term_badge "$SEMGREP_STATUS")  findings=$SEMGREP_FINDINGS"
  echo -e "  Trivy       : $(term_badge "$TRIVY_STATUS")  critical=$TRIVY_CRITICAL  high=$TRIVY_HIGH  secrets=$TRIVY_SECRETS"
  echo ""
  echo -e "  ${BOLD}Report:${NC} file://$REPORT_DIR/report.html"
  echo ""
}

main "$@"
