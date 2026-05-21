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
HADOLINT_IMAGE="hadolint/hadolint:latest"
VT_IMAGE_LOCAL="vt-cli:local"      # built locally from Dockerfile.vt

# ── Global state ──────────────────────────────────────────────────────────────
TARGET=""
TARGET_REF=""    # specific tag/branch to scan (empty = default branch HEAD)
WORK_DIR=""
REPORT_DIR=""
VT_CFG_DIR=""
VT_API_KEY="${VT_API_KEY:-}"
LANG_REPORT="${LANG_REPORT:-en}"     # Report language: en | ru
PDF_IMAGE_LOCAL="weasyprint-pdf:local"  # built locally from Dockerfile.pdf

REPORT_GENERATED=false
PDF_GENERATED=false
GENERATE_PDF=false

# Result variables (set by each scanner)
SEMGREP_STATUS="skipped";   SEMGREP_FINDINGS=0;  SEMGREP_ERRORS=0
TRIVY_STATUS="skipped";     TRIVY_CRITICAL=0;    TRIVY_HIGH=0; TRIVY_MEDIUM=0; TRIVY_LOW=0; TRIVY_SECRETS=0
VT_STATUS="skipped";        VT_MALICIOUS=0;      VT_TOTAL=0
HADOLINT_STATUS="skipped";  HADOLINT_ERRORS=0;   HADOLINT_WARNINGS=0; HADOLINT_TOTAL=0; HADOLINT_FILES=0

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
  --no-hadolint   Skip Hadolint Dockerfile scan
  --pdf           Also generate PDF report (requires Docker + Dockerfile.pdf)
  --vt-key KEY    VirusTotal API key (overrides VT_API_KEY env)
  --lang LANG     Report language: en (default) or ru

${BOLD}Environment:${NC}
  VT_API_KEY      VirusTotal API key (free tier: 4 req/min)
  LANG_REPORT     Report language (en or ru)
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
  [[ -n "$WORK_DIR"   && -d "$WORK_DIR"   ]] && rm -rf "$WORK_DIR"
  [[ -n "$VT_CFG_DIR" && -d "$VT_CFG_DIR" ]] && rm -rf "$VT_CFG_DIR"
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
  local clone_timeout=300
  local ec=0
  if [[ -n "$TARGET_REF" ]]; then
    log_info "Cloning $TARGET @ ${TARGET_REF} (timeout ${clone_timeout}s)…"
    timeout "$clone_timeout" git clone --depth 1 --branch "$TARGET_REF" --quiet "$TARGET" "$WORK_DIR/source" 2>&1 || ec=$?
    if [[ $ec -ne 0 ]]; then
      [[ $ec -eq 124 ]] && log_error "git clone timed out after ${clone_timeout}s" \
                        || log_error "Failed to clone repository at ref '${TARGET_REF}' — check tag/branch name"
      exit 1
    fi
    log_ok "Cloned tag/branch: ${TARGET_REF}"
  else
    log_info "Cloning $TARGET (default branch, timeout ${clone_timeout}s)…"
    timeout "$clone_timeout" git clone --depth 1 --quiet "$TARGET" "$WORK_DIR/source" 2>&1 || ec=$?
    if [[ $ec -ne 0 ]]; then
      [[ $ec -eq 124 ]] && log_error "git clone timed out after ${clone_timeout}s" \
                        || log_error "Failed to clone repository"
      exit 1
    fi
    log_ok "Cloned HEAD of default branch"
  fi
}

# ── Semgrep: auto-detect languages → select rulesets ─────────────────────────
_semgrep_configs() {
  local src="$WORK_DIR/source"

  # ── Core security (always, language-agnostic) ──
  local cfg="p/security-audit p/owasp-top-ten p/cwe-top-25 p/secrets p/trailofbits"

  # ── JavaScript / TypeScript / Node.js ──
  if [[ -f "$src/package.json" ]] || \
     find "$src" -maxdepth 4 \( -name "*.js" -o -name "*.ts" -o -name "*.jsx" -o -name "*.tsx" \) \
       -not -path "*/node_modules/*" 2>/dev/null | grep -q .; then
    cfg="$cfg p/javascript p/typescript p/nodejs p/eslint-plugin-security p/jwt"
    if [[ -f "$src/package.json" ]]; then
      grep -qE '"react"|"next"|"preact"' "$src/package.json" 2>/dev/null && cfg="$cfg p/react"
      grep -q '"express"'               "$src/package.json" 2>/dev/null && cfg="$cfg p/express"
    fi
    log_info "  → detected: JavaScript / TypeScript / Node.js" >&2
  fi

  # ── Python ──
  if [[ -f "$src/requirements.txt" ]] || [[ -f "$src/setup.py" ]] || \
     [[ -f "$src/pyproject.toml" ]] || \
     find "$src" -maxdepth 4 -name "*.py" -not -path "*/.venv/*" 2>/dev/null | grep -q .; then
    cfg="$cfg p/python"
    [[ -f "$src/manage.py" ]] && cfg="$cfg p/django" && log_info "  → detected: Django" >&2
    { [[ -f "$src/requirements.txt" ]] && grep -qi "flask" "$src/requirements.txt" 2>/dev/null; } \
      && cfg="$cfg p/flask" && log_info "  → detected: Flask" >&2
    log_info "  → detected: Python" >&2
  fi

  # ── Go ──
  if [[ -f "$src/go.mod" ]] || \
     find "$src" -maxdepth 3 -name "*.go" 2>/dev/null | grep -q .; then
    cfg="$cfg p/golang"
    log_info "  → detected: Go" >&2
  fi

  # ── Java / Kotlin ──
  if [[ -f "$src/pom.xml" ]] || [[ -f "$src/build.gradle" ]] || [[ -f "$src/build.gradle.kts" ]]; then
    cfg="$cfg p/java"
    find "$src" -maxdepth 4 -name "*.kt" 2>/dev/null | grep -q . && cfg="$cfg p/kotlin"
    log_info "  → detected: Java / Kotlin" >&2
  fi

  # ── Ruby ──
  if [[ -f "$src/Gemfile" ]] || \
     find "$src" -maxdepth 3 -name "*.rb" 2>/dev/null | grep -q .; then
    cfg="$cfg p/ruby"
    log_info "  → detected: Ruby" >&2
  fi

  # ── PHP ──
  if [[ -f "$src/composer.json" ]] || \
     find "$src" -maxdepth 3 -name "*.php" 2>/dev/null | grep -q .; then
    cfg="$cfg p/php"
    log_info "  → detected: PHP" >&2
  fi

  # ── Rust ──
  if [[ -f "$src/Cargo.toml" ]]; then
    cfg="$cfg p/rust"
    log_info "  → detected: Rust" >&2
  fi

  # ── C / C++ ──
  if find "$src" -maxdepth 4 \( -name "*.c" -o -name "*.cpp" -o -name "*.h" -o -name "*.cc" \) \
       2>/dev/null | grep -q .; then
    cfg="$cfg p/c"
    log_info "  → detected: C / C++" >&2
  fi

  # ── Terraform ──
  if find "$src" -maxdepth 5 -name "*.tf" 2>/dev/null | grep -q .; then
    cfg="$cfg p/terraform"
    log_info "  → detected: Terraform" >&2
  fi

  # ── Kubernetes manifests ──
  if find "$src" -maxdepth 5 \( -name "*.yaml" -o -name "*.yml" \) \
       -exec grep -lq "^apiVersion:" {} + 2>/dev/null; then
    cfg="$cfg p/kubernetes"
    log_info "  → detected: Kubernetes" >&2
  fi

  echo "$cfg"
}

# ── Semgrep ───────────────────────────────────────────────────────────────────
run_semgrep() {
  log_section "Semgrep — Static Code Analysis"

  local out="$REPORT_DIR/semgrep.json"
  local semgrep_log="$REPORT_DIR/semgrep.log"

  local semgrep_timeout=900  # 15 min — large codebases can take a while

  # Level 1: --config=auto (cloud rules from semgrep.dev).
  # NOTE: auto-config is incompatible with --metrics=off — omit that flag here.
  log_info "Trying semgrep auto-config (cloud rules, timeout ${semgrep_timeout}s)…"
  timeout "$semgrep_timeout" docker run --rm \
    -v "$WORK_DIR/source:/src:ro" \
    "$SEMGREP_IMAGE" \
    semgrep scan \
      --config=auto \
      --json \
      --exclude 'Dockerfile*' \
      --exclude '*.dockerfile' \
      /src > "$out" 2>"$semgrep_log" || true

  # Level 2: auto failed → smart multi-ruleset based on detected languages.
  # These rulesets are downloaded from semgrep.dev; may fail when offline.
  if [[ ! -s "$out" ]] || ! jq -e '.results' "$out" &>/dev/null; then
    log_info "Auto-config unavailable — detecting project languages…"
    local cfgs
    cfgs=$(_semgrep_configs)
    local config_args=""
    for c in $cfgs; do
      config_args="$config_args --config=$c"
    done
    log_info "Running with rulesets: $cfgs"
    # shellcheck disable=SC2086
    timeout "$semgrep_timeout" docker run --rm \
      -v "$WORK_DIR/source:/src:ro" \
      "$SEMGREP_IMAGE" \
      semgrep scan \
        $config_args \
        --json \
        --metrics=off \
        --exclude 'Dockerfile*' \
        --exclude '*.dockerfile' \
        /src > "$out" 2>>"$semgrep_log" || true
  fi

  # Level 3: p/default fallback — run when previous levels produced no valid output
  # OR found 0 findings (network rules may have silently loaded 0 rules on timeout).
  local l3_out="$REPORT_DIR/semgrep_default.json"
  local run_l3=false
  if [[ ! -s "$out" ]] || ! jq -e '.results' "$out" &>/dev/null; then
    log_info "Levels 1-2 produced no output — trying p/default fallback…"
    run_l3=true
  elif [[ "$(jq '[.results[]] | length' "$out" 2>/dev/null || echo 0)" -eq 0 ]]; then
    log_info "Level 2 found 0 findings — also running p/default to verify"
    run_l3=true
  fi

  if [[ "$run_l3" == true ]]; then
    timeout "$semgrep_timeout" docker run --rm \
      -v "$WORK_DIR/source:/src:ro" \
      "$SEMGREP_IMAGE" \
      semgrep scan \
        --config=p/default \
        --json \
        --metrics=off \
        --exclude 'Dockerfile*' \
        --exclude '*.dockerfile' \
        /src > "$l3_out" 2>>"$semgrep_log" || true

    if [[ -s "$l3_out" ]] && jq -e '.results' "$l3_out" &>/dev/null; then
      if [[ -s "$out" ]] && jq -e '.results' "$out" &>/dev/null; then
        jq -s '{ results: (.[0].results + .[1].results | unique_by([.check_id, .path, .start.line])), errors: (.[0].errors + .[1].errors) }' \
          "$out" "$l3_out" > "$out.merged" && mv "$out.merged" "$out"
      else
        mv "$l3_out" "$out"
      fi
    fi
  fi

  if [[ ! -s "$out" ]] || ! jq -e '.results' "$out" &>/dev/null; then
    # Check if the failure is due to network issues (semgrep.dev unreachable)
    if grep -q "Read timed out\|ConnectionError\|semgrep.dev" "$semgrep_log" 2>/dev/null; then
      log_warn "Semgrep failed: semgrep.dev unreachable (network timeout). Scan skipped."
      SEMGREP_STATUS="error"
    else
      log_warn "Semgrep produced no usable output — see semgrep.log"
      SEMGREP_STATUS="error"
    fi
    return
  fi

  SEMGREP_FINDINGS=$(jq '[.results[]] | length' "$out" 2>/dev/null || echo 0)
  SEMGREP_ERRORS=$(jq '[.errors[]] | length' "$out" 2>/dev/null || echo 0)

  if [[ "$SEMGREP_FINDINGS" -eq 0 ]]; then
    log_ok "No findings"
    SEMGREP_STATUS="pass"
  else
    log_warn "$SEMGREP_FINDINGS finding(s) — top 10:"
    # Print top findings (severity is semgrep's own classification, not a script error)
    jq -r '.results[:10][] |
      "  · \(.extra.severity | if . == "ERROR" then "HIGH" elif . == "WARNING" then "MEDIUM" else . end)\t\(.check_id | split(".") | last)\t\(.path | split("/") | last):\(.start.line)"' \
      "$out" 2>/dev/null | column -t -s $'\t' || true
    SEMGREP_STATUS="warn"
  fi
}

# ── Trivy ─────────────────────────────────────────────────────────────────────
run_trivy() {
  log_section "Trivy — Dependency & Secret Scan"

  local out="$REPORT_DIR/trivy_fs.json"
  local trivy_timeout=600  # 10 min

  log_info "Running Trivy (timeout ${trivy_timeout}s)…"
  local ec=0
  timeout "$trivy_timeout" docker run --rm \
    -v "$WORK_DIR/source:/target:ro" \
    -v "$REPORT_DIR:/reports" \
    "$TRIVY_IMAGE" \
    fs \
      --format json \
      --output /reports/trivy_fs.json \
      --scanners vuln,secret,misconfig \
      --quiet \
      /target 2>/dev/null || ec=$?
  if [[ $ec -ne 0 ]]; then
    if [[ $ec -eq 124 ]]; then
      log_warn "Trivy timed out after ${trivy_timeout}s"
    else
      log_warn "Trivy exited with code $ec"
    fi
  fi

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
  if ! docker image inspect "$VT_IMAGE_LOCAL" &>/dev/null; then
    log_error "vt-cli image build failed — VT scan skipped"
    VT_STATUS="error"
    return 1
  fi
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

  # SEC-3: write API key to a temp config file so it never appears in `ps aux`
  local vt_out
  VT_CFG_DIR=$(mktemp -d /tmp/vt_cfg_XXXXXX)
  chmod 700 "$VT_CFG_DIR"
  printf 'apikey = "%s"\n' "$VT_API_KEY" > "$VT_CFG_DIR/vt.toml"
  chmod 600 "$VT_CFG_DIR/vt.toml"

  vt_out=$(docker run --rm \
    -v "$VT_CFG_DIR/vt.toml:/root/.vt.toml:ro" \
    "$VT_IMAGE_LOCAL" \
    file "$sha256" 2>&1 || true)

  if echo "$vt_out" | grep -qiE 'NotFoundError|not found|404'; then
    # Not in VT database — upload and wait for results
    log_info "Not in VT database — uploading and scanning (--wait)…"
    local vt_upload_timeout=300
    local vt_upload_ec=0
    timeout "$vt_upload_timeout" docker run --rm \
      -v "$WORK_DIR:/work:ro" \
      -v "$VT_CFG_DIR/vt.toml:/root/.vt.toml:ro" \
      "$VT_IMAGE_LOCAL" \
      scan file --wait /work/source.tar.gz >/dev/null 2>&1 || vt_upload_ec=$?
    if [[ $vt_upload_ec -ne 0 ]]; then
      log_warn "VT upload/wait failed (ec=$vt_upload_ec) — skipping VT"
      rm -rf "$VT_CFG_DIR"; VT_CFG_DIR=""
      VT_STATUS="error"
      return
    fi
    log_info "Upload complete — fetching analysis results…"
    vt_out=$(docker run --rm \
      -v "$VT_CFG_DIR/vt.toml:/root/.vt.toml:ro" \
      "$VT_IMAGE_LOCAL" \
      file "$sha256" 2>&1 || true)
    # Re-validate post-upload fetch — same checks as initial fetch
    if echo "$vt_out" | grep -qiE 'NotFoundError|not found|404|API key|apikey|invalid|forbidden|401|403'; then
      log_error "VirusTotal post-upload fetch failed: $(echo "$vt_out" | head -1)"
      rm -rf "$VT_CFG_DIR"; VT_CFG_DIR=""
      VT_STATUS="error"
      return
    fi
  elif echo "$vt_out" | grep -qiE 'API key|apikey|invalid|forbidden|401|403'; then
    log_error "VirusTotal API key error: $(echo "$vt_out" | head -1)"
    rm -rf "$VT_CFG_DIR"; VT_CFG_DIR=""
    VT_STATUS="error"
    return
  else
    log_ok "Found in VirusTotal cache"
  fi

  # Remove temp config dir (key no longer needed)
  rm -rf "$VT_CFG_DIR"; VT_CFG_DIR=""

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
  [[ "$SEMGREP_STATUS" == "fail" || "$TRIVY_STATUS" == "fail" || "$VT_STATUS" == "fail" || "$HADOLINT_STATUS" == "fail" ]] && s="FAIL"
  [[ "$s" != "FAIL" ]] && {
    [[ "$SEMGREP_STATUS" == "warn" || "$TRIVY_STATUS" == "warn" || "$VT_STATUS" == "warn" || "$HADOLINT_STATUS" == "warn" ]] && s="WARN"
  }
  echo "$s"
}

semgrep_rows_html() {
  # $1 = gh_repo (owner/repo), $2 = ref (tag or HEAD)
  [[ ! -s "$REPORT_DIR/semgrep.json" ]] && return
  local base="https://github.com/${1}/blob/${2}"
  jq -r --arg base "$base" '
    # Map semgrep internal severities to human-readable labels (ERROR is not a script error)
    def sev_label: if . == "ERROR" then "HIGH" elif . == "WARNING" then "MEDIUM" else . end;
    def sev_css:   ascii_downcase | if . == "error" then "high" elif . == "warning" then "medium" else . end;
    .results[:50] | to_entries[] | .key as $i | .value |
    "<tr>
      <td class=\"num\">\($i + 1)</td>
      <td class=\"sev-\(.extra.severity | sev_css)\">\(.extra.severity | sev_label)</td>
      <td><code class=\"rule-id\">\(.check_id)</code></td>
      <td class=\"loc-cell\"><a href=\"\($base)/\(.path | ltrimstr("/src/") | gsub("&";"&amp;") | gsub("<";"&lt;") | gsub(">";"&gt;") | gsub("\"";"&quot;"))#L\(.start.line)\" target=\"_blank\" rel=\"noopener noreferrer\" class=\"loc-link\">\(.path | ltrimstr("/src/") | gsub("&";"&amp;") | gsub("<";"&lt;") | gsub(">";"&gt;")):\(.start.line)</a></td>
      <td class=\"desc-cell\">\(.extra.message | gsub("<";"&lt;") | gsub(">";"&gt;"))</td>
    </tr>"' "$REPORT_DIR/semgrep.json" 2>/dev/null || true
}

trivy_rows_html() {
  [[ ! -s "$REPORT_DIR/trivy_fs.json" ]] && return
  jq -r '.Results[]? | .Vulnerabilities[]? |
    "<tr>
      <td class=\"sev-\(.Severity | ascii_downcase)\">\(.Severity)</td>
      <td class=\"col-cve\"><a href=\"\(if .VulnerabilityID | startswith("GHSA-") then "https://github.com/advisories/" else "https://nvd.nist.gov/vuln/detail/" end)\(.VulnerabilityID)\" target=\"_blank\" rel=\"noopener noreferrer\" class=\"cve-link\"><code>\(.VulnerabilityID)</code></a></td>
      <td>\(.PkgName) \(.InstalledVersion // "")</td>
      <td>\(.FixedVersion // "—")</td>
      <td class=\"desc-cell\">\(.Title // "N/A" | gsub("<";"&lt;") | gsub(">";"&gt;"))</td>
    </tr>"' "$REPORT_DIR/trivy_fs.json" 2>/dev/null | head -200 || true
}

trivy_secrets_html() {
  # $1 = gh_repo (owner/repo), $2 = ref (tag or HEAD)
  [[ ! -s "$REPORT_DIR/trivy_fs.json" ]] && return
  local base="https://github.com/${1}/blob/${2}"
  jq -r --arg base "$base" '
    .Results[]? | . as $r | .Secrets[]? |
    "<tr>
      <td class=\"sev-\(.Severity | ascii_downcase)\">\(.Severity)</td>
      <td>\(.Title | gsub("&";"&amp;") | gsub("<";"&lt;") | gsub(">";"&gt;"))</td>
      <td class=\"loc-cell\"><a href=\"\($base)/\($r.Target | gsub("&";"&amp;") | gsub("<";"&lt;") | gsub(">";"&gt;") | gsub("\"";"&quot;"))\" target=\"_blank\" rel=\"noopener noreferrer\" class=\"loc-link\">\($r.Target | gsub("&";"&amp;") | gsub("<";"&lt;") | gsub(">";"&gt;"))</a></td>
      <td class=\"desc-cell\"><code>\(.Match | gsub("&";"&amp;") | gsub("<";"&lt;") | gsub(">";"&gt;") | .[0:120])</code></td>
    </tr>"' "$REPORT_DIR/trivy_fs.json" 2>/dev/null || true
}

# ── Hadolint ──────────────────────────────────────────────────────────────────
run_hadolint() {
  log_section "Hadolint — Dockerfile Analysis"

  local out="$REPORT_DIR/hadolint.json"

  # Find all Dockerfiles (excluding .git)
  local df_list
  df_list=$(find "$WORK_DIR/source" -maxdepth 6 \
    \( -name "Dockerfile" -o -name "Dockerfile.*" -o -name "*.dockerfile" \) \
    -not -path "*/.git/*" 2>/dev/null | sort)

  if [[ -z "$df_list" ]]; then
    log_info "No Dockerfiles found — skipping"
    HADOLINT_STATUS="skipped_no_docker"
    return
  fi

  HADOLINT_FILES=$(echo "$df_list" | wc -l | tr -d ' ')
  log_info "Found $HADOLINT_FILES Dockerfile(s)"

  # Build /src-relative path list for the Docker container
  local src_paths=()
  while IFS= read -r df; do
    src_paths+=("/src${df#$WORK_DIR/source}")
  done <<< "$df_list"

  docker run --rm \
    -v "$WORK_DIR/source:/src:ro" \
    "$HADOLINT_IMAGE" \
    hadolint --format json "${src_paths[@]}" > "$out" 2>/dev/null || true

  # hadolint exits 1 on findings; ensure valid JSON
  if [[ ! -s "$out" ]] || ! jq -e '.' "$out" &>/dev/null 2>&1; then
    echo "[]" > "$out"
  fi

  HADOLINT_ERRORS=$(  jq '[.[] | select(.level == "error")]   | length' "$out" 2>/dev/null || echo 0)
  HADOLINT_WARNINGS=$(jq '[.[] | select(.level == "warning")] | length' "$out" 2>/dev/null || echo 0)
  HADOLINT_TOTAL=$(   jq 'length'                              "$out" 2>/dev/null || echo 0)

  echo -e "  Errors: ${RED}${HADOLINT_ERRORS}${NC}  Warnings: ${YELLOW}${HADOLINT_WARNINGS}${NC}  Info: $(( HADOLINT_TOTAL - HADOLINT_ERRORS - HADOLINT_WARNINGS ))"

  # Top errors to terminal
  if [[ "$HADOLINT_ERRORS" -gt 0 ]]; then
    jq -r '[ .[] | select(.level=="error") ] [:5][] |
      "  · \(.code)  \(.message | .[0:80])"' "$out" 2>/dev/null || true
  fi

  if [[ "$HADOLINT_ERRORS" -gt 0 ]]; then
    log_warn "$HADOLINT_ERRORS Dockerfile error(s) detected"
    HADOLINT_STATUS="fail"
  elif [[ "$HADOLINT_WARNINGS" -gt 0 ]]; then
    log_warn "$HADOLINT_WARNINGS Dockerfile warning(s)"
    HADOLINT_STATUS="warn"
  elif [[ "$HADOLINT_TOTAL" -eq 0 ]]; then
    log_ok "No issues found"
    HADOLINT_STATUS="pass"
  else
    log_ok "Only informational findings"
    HADOLINT_STATUS="pass"
  fi
}

hadolint_rows_html() {
  [[ ! -s "$REPORT_DIR/hadolint.json" ]] && return
  local base="https://github.com/${1}/blob/${2}"
  jq -r --arg base "$base" '
    to_entries[] | .key as $i | .value |
    "<tr>
      <td class=\"num\">\($i + 1)</td>
      <td class=\"sev-\(if .level=="error" then "error" elif .level=="warning" then "warning" else "info" end)\">\(.level | ascii_upcase)</td>
      <td><code class=\"rule-id\">\(.code)</code></td>
      <td class=\"loc-cell\"><a href=\"\($base)/\(.file | ltrimstr("/src/") | gsub("&";"&amp;") | gsub("<";"&lt;") | gsub(">";"&gt;") | gsub("\"";"&quot;"))#L\(.line)\" target=\"_blank\" rel=\"noopener noreferrer\" class=\"loc-link\">\(.file | ltrimstr("/src/") | gsub("&";"&amp;") | gsub("<";"&lt;") | gsub(">";"&gt;")):\(.line)</a></td>
      <td class=\"desc-cell\">\(.message | gsub("<";"&lt;") | gsub(">";"&gt;"))</td>
    </tr>"' "$REPORT_DIR/hadolint.json" 2>/dev/null | head -200 || true
}

vt_meta_html() {
  local f="$REPORT_DIR/virustotal.txt"
  [[ ! -s "$f" ]] && return
  local sha256 md5 sha1 size type_desc meaningful_name rep times_sub unique_src first_sub last_scan
  sha256=$(         awk '/^[[:space:]]+sha256:/{gsub(/"/, "", $2); print $2; exit}' "$f")
  md5=$(            awk '/^[[:space:]]+md5:/{gsub(/"/, "", $2); print $2; exit}' "$f")
  sha1=$(           awk '/^[[:space:]]+sha1:/{gsub(/"/, "", $2); print $2; exit}' "$f")
  size=$(           awk '/^[[:space:]]+size:/{print $2+0; exit}' "$f")
  type_desc=$(      awk '/^[[:space:]]+type_description:/{$1=""; sub(/^[[:space:]]+/,""); print; exit}' "$f")
  meaningful_name=$(awk '/^[[:space:]]+meaningful_name:/{$1=""; sub(/^[[:space:]]+/,""); print; exit}' "$f")
  type_desc=$(echo "$type_desc" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
  meaningful_name=$(echo "$meaningful_name" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
  rep=$(            awk '/^[[:space:]]+reputation:/{print $2; exit}' "$f")
  times_sub=$(      awk '/^[[:space:]]+times_submitted:/{print $2; exit}' "$f")
  unique_src=$(     awk '/^[[:space:]]+unique_sources:/{print $2; exit}' "$f")
  first_sub=$(      awk '/^[[:space:]]+first_submission_date:/{print $2; exit}' "$f")
  last_scan=$(      awk '/^[[:space:]]+last_analysis_date:/{print $2; exit}' "$f")

  # Format size
  local size_fmt="—"
  if [[ -n "$size" && "$size" -gt 0 ]] 2>/dev/null; then
    if   [[ "$size" -gt 1073741824 ]]; then size_fmt="$(( size/1024/1024/1024 )) GB"
    elif [[ "$size" -gt 1048576    ]]; then size_fmt="$(( size/1024/1024 )) MB"
    else                                    size_fmt="$(( size/1024 )) KB"
    fi
    size_fmt="$size_fmt &nbsp;<span class='vt-sub'>(${size} bytes)</span>"
  fi

  # Format epoch → human date (macOS: date -r / Linux: date -d @)
  local first_sub_fmt last_scan_fmt
  first_sub_fmt=$(date -r "$first_sub" "+%Y-%m-%d %H:%M" 2>/dev/null || \
                  date -d "@$first_sub" "+%Y-%m-%d %H:%M" 2>/dev/null || echo "${first_sub:-—}")
  last_scan_fmt=$(date  -r "$last_scan"  "+%Y-%m-%d %H:%M" 2>/dev/null || \
                  date -d "@$last_scan"  "+%Y-%m-%d %H:%M" 2>/dev/null || echo "${last_scan:-—}")

  # Reputation coloring
  local rep_cls="" rep_val="${rep:-—}"
  if [[ -n "$rep" ]] 2>/dev/null; then
    [[ "$rep" -lt 0 ]] && rep_cls=' class="sev-critical"'
    [[ "$rep" -gt 0 ]] && rep_cls=' class="sev-info"'
  fi

  cat <<VT_META_EOF
<div class="vt-meta">
  <div class="vt-meta-row"><span class="vt-mk">SHA-256</span><code class="vt-hash">${sha256:-—}</code></div>
  <div class="vt-meta-row"><span class="vt-mk">MD5</span><code class="vt-hash">${md5:-—}</code></div>
  <div class="vt-meta-row"><span class="vt-mk">SHA-1</span><code class="vt-hash">${sha1:-—}</code></div>
  <div class="vt-meta-row"><span class="vt-mk">File type</span><span>${type_desc:-—}</span></div>
  <div class="vt-meta-row"><span class="vt-mk">File size</span><span>${size_fmt}</span></div>
  <div class="vt-meta-row"><span class="vt-mk">Name (VT)</span><span>${meaningful_name:-—}</span></div>
  <div class="vt-meta-row"><span class="vt-mk">Reputation</span><span${rep_cls}>${rep_val}</span></div>
  <div class="vt-meta-row"><span class="vt-mk">Times submitted</span><span>${times_sub:-—} &nbsp;<span class='vt-sub'>(${unique_src:-?} unique source(s))</span></span></div>
  <div class="vt-meta-row"><span class="vt-mk">First seen</span><span>${first_sub_fmt:-—}</span></div>
  <div class="vt-meta-row"><span class="vt-mk">Last scan</span><span>${last_scan_fmt:-—}</span></div>
</div>
VT_META_EOF
}

vt_engines_html() {
  # Show only malicious/suspicious engines as grid items.
  # Engine name is read from the 4-space YAML map key ("    Antiy-AVL:"),
  # NOT from the engine_name: attribute — more robust across vt-cli versions.
  local f="$REPORT_DIR/virustotal.txt"
  [[ ! -s "$f" ]] && return
  awk '
    /last_analysis_results:/  { in_r=1; next }
    in_r && /^  [^ \t]/       { in_r=0 }         # sibling 2-space key → leave block
    in_r && /^    [^ \t]/ {                       # 4-space engine header (e.g. "    Antiy-AVL:")
      eng=$0
      gsub(/^[[:space:]]+|:[[:space:]]*$/, "", eng)
      gsub(/"/, "", eng)
      cat=""; res=""
      next
    }
    in_r && /category:/ { cat=$2; gsub(/"/, "", cat) }
    in_r && /result:/ {
      res=""
      if (NF>1 && $2!="null" && $2!="") {
        for(i=2;i<=NF;i++) res=res (res==""?"":" ") $i
        gsub(/"/, "", res)
      }
      if (eng!="" && (cat=="malicious" || cat=="suspicious")) {
        verdict = (cat=="malicious") ? (res==""?"Malicious":res) : (res==""?"Suspicious":res)
        cls     = (cat=="malicious") ? "malicious" : "suspicious"
        gsub(/&/, "\\&amp;", eng);     gsub(/</, "\\&lt;", eng);     gsub(/>/, "\\&gt;", eng)
        gsub(/&/, "\\&amp;", verdict); gsub(/</, "\\&lt;", verdict); gsub(/>/, "\\&gt;", verdict)
        print "<div class=\"vt-eng\" data-cat=\""cat"\"><span class=\"vt-eng-name\">"eng"</span><span class=\"vt-eng-verdict vt-v-"cls"\">"verdict"</span></div>"
      }
      cat=""; res=""
    }
  ' "$f"
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

# ── Translations ──────────────────────────────────────────────────────────────
setup_lang() {
  if [[ "$LANG_REPORT" == "ru" ]]; then
    T_REPORT_TITLE="Отчёт о безопасности"
    T_LABEL_TARGET="Репозиторий"
    T_LABEL_REF="Версия"
    T_LABEL_DATE="Дата"
    T_VT_LABEL="VirusTotal"
    T_VT_MALICIOUS_SUB="вредоносных / ${VT_TOTAL} движков"
    T_SEMGREP_LABEL="Semgrep"
    T_SEMGREP_SUB="проблем в коде"
    T_TRIVY_LABEL="Trivy"
    T_TRIVY_SUB="критических / высоких"
    T_TRIVY_MED="ср"
    T_TRIVY_LOW="низ"
    T_VT_MODULE_TITLE="VirusTotal"
    T_SEMGREP_MODULE_TITLE="Semgrep — Статический анализ"
    T_TRIVY_MODULE_TITLE="Trivy — Зависимости и секреты"
    T_VT_SKIPPED="Пропущено — укажите <code>VT_API_KEY</code> в <code>.env</code> или через <code>--vt-key</code>"
    T_VT_TOO_LARGE="Пропущено — архив &gt; 650 МБ"
    T_VT_ERROR="Ошибка — проверьте API-ключ или пересоберите образ vt-cli"
    T_VT_TH_CATEGORY="Категория"
    T_VT_TH_COUNT="Кол-во"
    T_VT_RAW="Сырой вывод vt-cli"
    T_SEMGREP_CLEAN="✓ Проблем не найдено"
    T_SEMGREP_ERROR="Semgrep недоступен — semgrep.dev не отвечает (таймаут). Проверьте интернет-соединение и повторите сканирование."
    T_SEMGREP_FINDINGS_LABEL="найдено (показаны первые 50)"
    T_SEMGREP_TH_SEV="Серьёзность"
    T_SEMGREP_TH_RULE="Правило"
    T_SEMGREP_TH_LOC="Расположение"
    T_SEMGREP_TH_MSG="Описание"
    T_TRIVY_CLEAN="✓ Критических проблем не найдено"
    T_TRIVY_ERROR="Ошибка сканера — проверьте логи Docker"
    T_TRIVY_VULN_LABEL="Уязвимости"
    T_TRIVY_TH_SEV="Серьёзность"
    T_TRIVY_TH_CVE="CVE"
    T_TRIVY_TH_PKG="Пакет"
    T_TRIVY_TH_FIX="Исправление"
    T_TRIVY_TH_TITLE="Название"
    T_TRIVY_SECRETS_LABEL="секрет(ов) обнаружено в исходниках"
    T_TRIVY_TH_TYPE="Тип"
    T_TRIVY_TH_FILE="Файл"
    T_TRIVY_TH_MATCH="Совпадение"
    T_RAW_JSON="Сырые данные JSON"
    T_VERDICT_PASS="Все проверки пройдены — критических угроз не обнаружено"
    T_VERDICT_WARN="Обнаружены некритические проблемы, требующие проверки"
    T_VERDICT_FAIL="Обнаружены критические угрозы — вредоносный код, критические CVE или секреты"
    T_HADOLINT_LABEL="Hadolint"
    T_HADOLINT_METRIC_SUB="ошибок / предупреждений"
    T_HADOLINT_MODULE_TITLE="Hadolint — Анализ Dockerfile"
    T_HADOLINT_CLEAN="✓ Dockerfile-файлы в порядке"
    T_HADOLINT_SKIPPED="Dockerfile-файлы не найдены"
    T_HADOLINT_TH_SEV="Уровень"
    T_HADOLINT_TH_RULE="Правило"
    T_HADOLINT_TH_LOC="Расположение"
    T_HADOLINT_TH_MSG="Описание"
    T_HADOLINT_FINDINGS_LABEL="замечаний"
    T_HADOLINT_FILES_LABEL="файлов проверено"
    T_FOOTER_GENERATED="Сформировано"
  else
    T_REPORT_TITLE="Security Scan Report"
    T_LABEL_TARGET="Target"
    T_LABEL_REF="Ref"
    T_LABEL_DATE="Date"
    T_VT_LABEL="VirusTotal"
    T_VT_MALICIOUS_SUB="malicious / ${VT_TOTAL} engines"
    T_SEMGREP_LABEL="Semgrep"
    T_SEMGREP_SUB="code findings"
    T_TRIVY_LABEL="Trivy"
    T_TRIVY_SUB="critical / high"
    T_TRIVY_MED="med"
    T_TRIVY_LOW="low"
    T_VT_MODULE_TITLE="VirusTotal"
    T_SEMGREP_MODULE_TITLE="Semgrep — Static Analysis"
    T_TRIVY_MODULE_TITLE="Trivy — Dependencies &amp; Secrets"
    T_VT_SKIPPED="Skipped — set <code>VT_API_KEY</code> in <code>.env</code> or use <code>--vt-key</code>"
    T_VT_TOO_LARGE="Skipped — archive &gt; 650 MB"
    T_VT_ERROR="Error — check API key or rebuild vt-cli image"
    T_VT_TH_CATEGORY="Category"
    T_VT_TH_COUNT="Count"
    T_VT_RAW="Raw vt-cli output"
    T_SEMGREP_CLEAN="✓ No findings"
    T_SEMGREP_ERROR="Semgrep unavailable — semgrep.dev unreachable (network timeout). Check your internet connection and retry."
    T_SEMGREP_FINDINGS_LABEL="finding(s) — showing up to 50"
    T_SEMGREP_TH_SEV="Severity"
    T_SEMGREP_TH_RULE="Rule"
    T_SEMGREP_TH_LOC="Location"
    T_SEMGREP_TH_MSG="Message"
    T_TRIVY_CLEAN="✓ No critical issues"
    T_TRIVY_ERROR="Scanner error — check Docker logs"
    T_TRIVY_VULN_LABEL="Vulnerabilities"
    T_TRIVY_TH_SEV="Severity"
    T_TRIVY_TH_CVE="CVE"
    T_TRIVY_TH_PKG="Package"
    T_TRIVY_TH_FIX="Fix"
    T_TRIVY_TH_TITLE="Title"
    T_TRIVY_SECRETS_LABEL="secret(s) detected in source"
    T_TRIVY_TH_TYPE="Type"
    T_TRIVY_TH_FILE="File"
    T_TRIVY_TH_MATCH="Match"
    T_RAW_JSON="Raw JSON"
    T_VERDICT_PASS="All scanners passed — no critical issues detected"
    T_VERDICT_WARN="One or more scanners found non-critical issues that require review"
    T_VERDICT_FAIL="Critical issues detected — malware, critical CVEs, or secrets found"
    T_HADOLINT_LABEL="Hadolint"
    T_HADOLINT_METRIC_SUB="errors / warnings"
    T_HADOLINT_MODULE_TITLE="Hadolint — Dockerfile Analysis"
    T_HADOLINT_CLEAN="✓ No Dockerfile issues"
    T_HADOLINT_SKIPPED="No Dockerfiles found in repository"
    T_HADOLINT_TH_SEV="Level"
    T_HADOLINT_TH_RULE="Rule"
    T_HADOLINT_TH_LOC="Location"
    T_HADOLINT_TH_MSG="Message"
    T_HADOLINT_FINDINGS_LABEL="finding(s)"
    T_HADOLINT_FILES_LABEL="file(s) scanned"
    T_FOOTER_GENERATED="Generated"
  fi
}

# ── PDF Report ─────────────────────────────────────────────────────────────────
ensure_pdf_image() {
  if docker image inspect "$PDF_IMAGE_LOCAL" &>/dev/null 2>&1; then
    return
  fi
  local dockerfile
  dockerfile="$(dirname "$0")/Dockerfile.pdf"
  if [[ ! -f "$dockerfile" ]]; then
    log_warn "Dockerfile.pdf not found — skipping PDF"
    return 1
  fi
  log_info "Building WeasyPrint image (first run, ~2–3 min)…"
  docker build -t "$PDF_IMAGE_LOCAL" -f "$dockerfile" "$(dirname "$0")" \
    2>&1 | grep -E 'Step|error|Error|=>|DONE' || true
  if ! docker image inspect "$PDF_IMAGE_LOCAL" &>/dev/null; then
    log_warn "WeasyPrint image build failed — see output above"
    return 1
  fi
  log_ok "WeasyPrint image built: $PDF_IMAGE_LOCAL"
}

generate_pdf() {
  [[ "$PDF_GENERATED" == true ]] && return
  PDF_GENERATED=true
  local pdf_file="$REPORT_DIR/report.pdf"
  log_info "Generating PDF report…"
  ensure_pdf_image || return
  docker run --rm \
    -v "$REPORT_DIR:/data" \
    "$PDF_IMAGE_LOCAL" \
    /data/report.html \
    /data/report.pdf 2>/dev/null || {
      log_warn "PDF generation failed — check WeasyPrint image"
      return
    }
  [[ -f "$pdf_file" ]] && log_ok "PDF report : file://$pdf_file"
}

generate_report() {
  [[ "$REPORT_GENERATED" == true ]] && return
  REPORT_GENERATED=true
  local overall
  overall=$(overall_status)
  local gh_repo
  gh_repo=$(parse_github_url "$TARGET")

  setup_lang

  local overall_class verdict_desc=""
  case "$overall" in
    PASS) overall_class="pass"; verdict_desc="$T_VERDICT_PASS" ;;
    WARN) overall_class="warn"; verdict_desc="$T_VERDICT_WARN" ;;
    *)    overall_class="fail" ;;
  esac

  # For FAIL: build a specific one-sentence summary from actual findings
  if [[ "$overall" == "FAIL" ]]; then
    local _parts=""
    if [[ "$VT_STATUS" == "fail" ]]; then
      if [[ "$LANG_REPORT" == "ru" ]]; then
        _parts="VirusTotal: $VT_MALICIOUS из $VT_TOTAL движков пометили файл как вредоносный"
      else
        _parts="VirusTotal flagged $VT_MALICIOUS/$VT_TOTAL engines as malicious"
      fi
    fi
    if [[ "$TRIVY_CRITICAL" -gt 0 ]]; then
      local _tri
      if [[ "$LANG_REPORT" == "ru" ]]; then
        _tri="Trivy: $TRIVY_CRITICAL критических CVE"
      else
        _tri="Trivy: $TRIVY_CRITICAL critical CVE(s)"
      fi
      _parts="${_parts:+${_parts}; }${_tri}"
    fi
    if [[ "$TRIVY_SECRETS" -gt 0 ]]; then
      local _sec
      if [[ "$LANG_REPORT" == "ru" ]]; then
        _sec="$TRIVY_SECRETS секрет(ов) обнаружено в исходном коде"
      else
        _sec="$TRIVY_SECRETS secret(s) found in source code"
      fi
      _parts="${_parts:+${_parts}; }${_sec}"
    fi
    verdict_desc="${_parts:-$T_VERDICT_FAIL}"
  fi

  local semgrep_badge trivy_badge vt_badge hadolint_badge
  semgrep_badge=$(status_badge "$SEMGREP_STATUS")
  trivy_badge=$(status_badge "$TRIVY_STATUS")
  vt_badge=$(status_badge "$VT_STATUS")
  hadolint_badge=$(status_badge "$HADOLINT_STATUS")

  # Pre-compute Hadolint INFO count for status bar
  local hadolint_info=$(( HADOLINT_TOTAL - HADOLINT_ERRORS - HADOLINT_WARNINGS ))

  # Pre-compute VT engines block (adds empty-state message when 0 engines flagged)
  local vt_engines_block=""
  if [[ -s "$REPORT_DIR/virustotal.txt" ]]; then
    local _engines _empty_msg="" _open_attr=""
    _engines=$(vt_engines_html)
    [[ -z "$_engines" && "$VT_TOTAL" -gt 0 ]] && _empty_msg="<p class=\"msg ok\" style=\"margin-top:0.5rem\">No engines flagged this file as malicious or suspicious.</p>"
    [[ "$VT_MALICIOUS" -gt 0 ]] && _open_attr=" open"
    vt_engines_block="
    <details${_open_attr}>
      <summary>🔬 Security vendors' analysis — ${VT_MALICIOUS} / ${VT_TOTAL} engines detected</summary>
      <div class='vt-engine-grid'>${_engines}</div>
      ${_empty_msg}
    </details>"
  fi

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
    --sev-high:#f97316; --sev-info:#60a5fa; --loc-hover:#93c5fd;
    --r:12px;
    --fs-xs:0.7rem; --fs-sm:0.8rem; --fs-body:0.85rem;
    --fs-lg:1.4rem; --fs-hero:2.4rem;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
       background:var(--bg);color:var(--text);font-size:14px;min-height:100vh}
  a{color:var(--code);text-decoration:none}
  a:hover{text-decoration:underline}

  /* ── Page wrapper ── */
  .page{max-width:960px;margin:0 auto;padding:2rem 1.5rem}

  /* ── Hero ── */
  .hero{
    background:var(--surface);border:1px solid var(--border);border-radius:var(--r);
    padding:1.75rem 1.5rem 1.5rem;text-align:center;margin-bottom:1.25rem;
  }
  .hero h1{font-size:var(--fs-lg);font-weight:800;letter-spacing:-0.4px;margin-bottom:1.25rem}

  /* ── Hero info blocks (Target / Ref / Date) ── */
  .hero-info{display:flex;justify-content:center;gap:0.75rem;flex-wrap:wrap;margin-bottom:1.1rem}
  .info-block{
    background:var(--surface2);border:1px solid var(--border);border-radius:8px;
    padding:0.6rem 1.25rem;text-align:center;min-width:150px;
  }
  .info-label{font-size:var(--fs-xs);text-transform:uppercase;letter-spacing:0.8px;color:var(--muted);margin-bottom:0.35rem}
  .info-val{font-size:1rem;font-weight:600;color:var(--text)}
  .info-val a{color:var(--code)}
  .info-val code{font-size:1rem}

  /* ── Verdict block ── */
  .verdict-block{
    display:inline-flex;align-items:center;gap:0.9rem;
    padding:0.6rem 1.4rem;border-radius:8px;margin-top:0;
  }
  .verdict-block.verdict-pass{background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.28)}
  .verdict-block.verdict-warn{background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.28)}
  .verdict-block.verdict-fail{background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.28)}
  .verdict-label{font-size:1rem;font-weight:800;letter-spacing:1.5px}
  .verdict-block.verdict-pass .verdict-label{color:var(--pass)}
  .verdict-block.verdict-warn .verdict-label{color:var(--warn)}
  .verdict-block.verdict-fail .verdict-label{color:var(--fail)}
  .verdict-sep{width:1px;height:1.3rem;background:var(--border)}
  .verdict-desc{font-size:var(--fs-body);color:var(--muted);text-align:left}

  /* ── Metric strip ── */
  .metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:1.75rem}
  .metric{
    background:var(--surface);border:1px solid var(--border);border-radius:var(--r);
    padding:1.4rem 1rem;text-align:center;
  }
  .metric-label{font-size:var(--fs-xs);text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:0.6rem}
  .metric-num{font-size:var(--fs-hero);font-weight:800;line-height:1;margin-bottom:0.35rem}
  .metric-num.green{color:var(--pass)}
  .metric-num.yellow{color:var(--warn)}
  .metric-num.red{color:var(--fail)}
  .metric-sub{font-size:var(--fs-sm);color:var(--muted);margin-bottom:0.7rem}

  /* ── Badges ── */
  .badge{
    display:inline-flex;align-items:center;gap:0.28rem;
    padding:3px 10px;border-radius:5px;font-size:var(--fs-xs);font-weight:700;letter-spacing:0.6px;
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
  .mod-title{font-size:1rem;font-weight:700;display:flex;align-items:center;gap:0.5rem}
  .mod-icon{font-size:1rem}
  .mod-body{padding:1.25rem 1.5rem}

  /* ── Tables ── */
  table{width:100%;border-collapse:collapse;font-size:var(--fs-sm)}
  th{
    background:var(--surface2);color:var(--muted);text-align:left;
    padding:0.5rem 0.75rem;font-weight:600;
    border-bottom:2px solid var(--border);
    font-size:var(--fs-xs);text-transform:uppercase;letter-spacing:0.5px;
  }
  td{padding:0.3rem 0.7rem;border-bottom:1px solid var(--border);vertical-align:top;overflow-wrap:break-word;word-break:break-word}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:var(--surface2)}
  code{color:var(--code);font-size:var(--fs-sm);font-family:"SF Mono",Menlo,monospace}

  /* ── Row number column ── */
  .num{width:38px;text-align:center !important;color:var(--muted);font-size:var(--fs-sm);font-variant-numeric:tabular-nums}

  /* ── Rule ID (grey, not a link) ── */
  .rule-id{color:var(--muted)}

  /* ── Location link (blue, clearly clickable) ── */
  .loc-cell{white-space:normal;word-break:break-all;max-width:220px}
  .loc-link{color:var(--sev-info);font-family:"SF Mono",Menlo,monospace;font-size:var(--fs-sm)}
  .loc-link:hover{color:var(--loc-hover);text-decoration:underline}
  .cve-link{color:inherit;text-decoration:none}
  .cve-link:hover code{text-decoration:underline;color:var(--loc-hover)}

  /* ── Description cell ── */
  .desc-cell{white-space:normal;word-break:break-word}

  /* ── Code in table cells must wrap (rule IDs, paths) ── */
  td code{word-break:break-all}

  /* ── Fixed-layout table (Semgrep) ── */
  .tbl-fixed{table-layout:fixed}
  .col-num{width:38px}
  .col-sev{width:11%}
  .col-cve{width:165px;white-space:nowrap}
  .col-cve code{white-space:nowrap}
  .col-pkg{width:22%}
  .col-fix{width:11%}
  .col-rule{width:22%}
  .col-loc{width:22%}
  /* col-desc gets remaining space automatically */
  th{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

  /* ── Severity ── */
  .sev-critical{color:var(--fail);font-weight:700}
  .sev-high{color:var(--sev-high);font-weight:600}
  .sev-medium{color:var(--warn)}
  .sev-low{color:var(--muted)}
  .sev-error{color:var(--fail);font-weight:700}
  .sev-warning{color:var(--warn)}
  .sev-info{color:var(--sev-info)}

  /* ── Accordion ── */
  details{margin-bottom:0.6rem}
  summary{
    cursor:pointer;padding:0.55rem 0;font-weight:600;font-size:var(--fs-body);
    list-style:none;display:flex;align-items:center;gap:0.5rem;user-select:none;
  }
  summary::-webkit-details-marker{display:none}
  summary::before{content:"▶";font-size:var(--fs-xs);color:var(--muted);transition:transform .18s;flex-shrink:0}
  details[open] summary::before{transform:rotate(90deg)}

  /* ── Status messages ── */
  .msg{padding:0.6rem 0;font-size:var(--fs-body)}
  .msg.ok{color:var(--pass)}
  .msg.warn{color:var(--warn)}
  .msg.muted{color:var(--muted);font-style:italic}

  /* ── VT metadata ── */
  .vt-meta{margin-bottom:1.25rem;border:1px solid var(--border);border-radius:8px;overflow:hidden}
  .vt-meta-row{display:flex;gap:1rem;padding:0.4rem 0.9rem;border-bottom:1px solid var(--border);align-items:baseline;font-size:var(--fs-sm)}
  .vt-meta-row:last-child{border-bottom:none}
  .vt-meta-row:nth-child(odd){background:rgba(255,255,255,.015)}
  .vt-mk{font-size:var(--fs-xs);text-transform:uppercase;letter-spacing:0.6px;color:var(--muted);min-width:130px;flex-shrink:0;padding-top:1px}
  .vt-hash{word-break:break-all;font-size:var(--fs-sm);color:var(--code)}
  .vt-sub{color:var(--muted);font-size:var(--fs-sm)}

  /* ── VT engine grid (Security vendors' analysis) ── */
  .vt-engine-grid{display:grid;grid-template-columns:1fr 1fr;gap:0.3rem;margin-top:0.6rem}
  .vt-eng{display:flex;justify-content:space-between;align-items:center;padding:0.3rem 0.7rem;background:var(--surface2);border-radius:4px;font-size:var(--fs-sm);border:1px solid transparent}
  .vt-eng[data-cat="malicious"]{background:rgba(239,68,68,.08);border-color:rgba(239,68,68,.28)}
  .vt-eng[data-cat="suspicious"]{background:rgba(245,158,11,.07);border-color:rgba(245,158,11,.28)}
  .vt-eng-name{color:var(--text);font-size:var(--fs-sm);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .vt-eng-verdict{font-size:var(--fs-xs);font-weight:600;padding:1px 7px;border-radius:3px;white-space:nowrap;margin-left:0.5rem;flex-shrink:0}
  .vt-v-malicious{color:var(--fail);background:rgba(239,68,68,.18)}
  .vt-v-suspicious{color:var(--warn);background:rgba(245,158,11,.18)}
  .vt-v-harmless{color:var(--pass);background:rgba(34,197,94,.1)}
  .vt-v-undetected{color:var(--muted)}
  .vt-v-timeout,.vt-v-unsupported{color:var(--muted);font-style:italic;font-size:var(--fs-xs)}

  /* ── Raw link ── */
  .raw-link{display:block;margin-top:0.75rem;font-size:var(--fs-sm);color:var(--muted)}
  .raw-link a{color:var(--muted)}
  .raw-link a:hover{color:var(--code)}

  /* ── Footer ── */
  footer{
    text-align:center;padding:1.5rem 0;
    color:var(--muted);font-size:var(--fs-sm);
    border-top:1px solid var(--border);margin-top:0.5rem;
  }

  /* ── Keyboard focus ── */
  a:focus-visible,summary:focus-visible{outline:2px solid var(--code);outline-offset:2px;border-radius:2px}

  /* ── Table horizontal scroll ── */
  .tbl-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch}

  @media(max-width:700px){
    .metrics{grid-template-columns:repeat(2,1fr)}
    .vt-engine-grid{grid-template-columns:1fr}
  }
  @media(max-width:600px){
    .hero-info{flex-direction:column;align-items:center}
    .verdict-block{flex-direction:column;gap:0.5rem;text-align:center}
    .verdict-sep{display:none}
    .verdict-desc{text-align:center}
  }
  @media(max-width:560px){
    .metrics{grid-template-columns:repeat(2,1fr)}
    .tbl-fixed{font-size:0.75rem}
    .col-loc{width:18%}
  }
  @media(max-width:480px){
    .metrics{grid-template-columns:1fr}
  }
</style>
</head>
<body>
<div class="page">

<!-- ── Hero ── -->
<div class="hero">
  <h1>🔍 ${T_REPORT_TITLE}</h1>

  <!-- Info blocks -->
  <div class="hero-info">
    <div class="info-block">
      <div class="info-label">${T_LABEL_TARGET}</div>
      <div class="info-val"><a href="${TARGET}" target="_blank" rel="noopener noreferrer">${gh_repo}</a></div>
    </div>
    <div class="info-block">
      <div class="info-label">${T_LABEL_REF}</div>
      <div class="info-val"><code>$([ -n "$TARGET_REF" ] && echo "${TARGET_REF}" || echo "HEAD")</code></div>
    </div>
    <div class="info-block">
      <div class="info-label">${T_LABEL_DATE}</div>
      <div class="info-val">$(date "+%Y-%m-%d %H:%M %Z")</div>
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
    <div class="metric-label">${T_VT_LABEL}</div>
    <div class="metric-num $([ "$VT_MALICIOUS" -gt 0 ] && echo red || echo green)">${VT_MALICIOUS}</div>
    <div class="metric-sub">${T_VT_MALICIOUS_SUB}</div>
    ${vt_badge}
  </div>
  <div class="metric">
    <div class="metric-label">${T_SEMGREP_LABEL}</div>
    <div class="metric-num $([ "$SEMGREP_FINDINGS" -gt 0 ] && echo yellow || echo green)">${SEMGREP_FINDINGS}</div>
    <div class="metric-sub">${T_SEMGREP_SUB}</div>
    ${semgrep_badge}
  </div>
  <div class="metric">
    <div class="metric-label">${T_TRIVY_LABEL}</div>
    <div class="metric-num $([ "$TRIVY_CRITICAL" -gt 0 ] && echo red || [ "$TRIVY_HIGH" -gt 0 ] && echo yellow || echo green)">${TRIVY_CRITICAL} / ${TRIVY_HIGH}</div>
    <div class="metric-sub">${T_TRIVY_SUB} &nbsp;·&nbsp; +${TRIVY_MEDIUM} ${T_TRIVY_MED} &nbsp;${TRIVY_LOW} ${T_TRIVY_LOW}</div>
    ${trivy_badge}
  </div>
  <div class="metric">
    <div class="metric-label">${T_HADOLINT_LABEL}</div>
    <div class="metric-num $([ "$HADOLINT_ERRORS" -gt 0 ] && echo red || [ "$HADOLINT_WARNINGS" -gt 0 ] && echo yellow || echo green)">$([ "$HADOLINT_STATUS" == "skipped_no_docker" ] && echo "—" || echo "${HADOLINT_ERRORS} / ${HADOLINT_WARNINGS}")</div>
    <div class="metric-sub">$([ "$HADOLINT_STATUS" == "skipped_no_docker" ] && echo "no Dockerfiles" || echo "${HADOLINT_FILES} files &nbsp;·&nbsp; ${T_HADOLINT_METRIC_SUB}")</div>
    ${hadolint_badge}
  </div>
</div>

<!-- ══════════════════════════════════════
     MODULE: VirusTotal
     ══════════════════════════════════════ -->
<div class="module">
  <div class="mod-head">
    <div class="mod-title"><span class="mod-icon">🦠</span> ${T_VT_MODULE_TITLE} <span style="color:var(--muted);font-weight:400;font-size:var(--fs-sm)">(vt-cli)</span></div>
    ${vt_badge}
  </div>
  <div class="mod-body">
    $([ "$VT_STATUS" == "skipped" ]           && echo "<p class=\"msg muted\">${T_VT_SKIPPED}</p>" || true)
    $([ "$VT_STATUS" == "skipped_too_large" ] && echo "<p class=\"msg muted\">${T_VT_TOO_LARGE}</p>" || true)
    $([ "$VT_STATUS" == "error" ]             && echo "<p class=\"msg warn\">${T_VT_ERROR}</p>" || true)
    $([ -s "$REPORT_DIR/virustotal.txt" ] && echo "$(vt_meta_html)" || true)
    $([ -s "$REPORT_DIR/virustotal.txt" ] && echo "
    <details open>
      <summary>Detection categories</summary>
      <div class='tbl-wrap'><table>
        <thead><tr><th>${T_VT_TH_CATEGORY}</th><th>${T_VT_TH_COUNT}</th></tr></thead>
        <tbody>$(vt_stats_html)</tbody>
      </table></div>
    </details>" || true)
    ${vt_engines_block}
    <div class="raw-link">📄 <a href="virustotal.txt" target="_blank" rel="noopener noreferrer">${T_VT_RAW}</a></div>
  </div>
</div>

<!-- ══════════════════════════════════════
     MODULE: Semgrep
     ══════════════════════════════════════ -->
<div class="module">
  <div class="mod-head">
    <div class="mod-title"><span class="mod-icon">🔎</span> ${T_SEMGREP_MODULE_TITLE}</div>
    ${semgrep_badge}
  </div>
  <div class="mod-body">
    $([ "$SEMGREP_STATUS" == "pass"  ] && echo "<p class=\"msg ok\">${T_SEMGREP_CLEAN}</p>" || true)
    $([ "$SEMGREP_STATUS" == "error" ] && echo "<p class=\"msg warn\">${T_SEMGREP_ERROR}</p>" || true)
    $([ "$SEMGREP_FINDINGS" -gt 0 ] && echo "
    <details open>
      <summary>${SEMGREP_FINDINGS} ${T_SEMGREP_FINDINGS_LABEL}</summary>
      <div class='tbl-wrap'><table class=\"tbl-fixed\">
        <colgroup><col class=\"col-num\"><col class=\"col-sev\"><col class=\"col-rule\"><col class=\"col-loc\"><col></colgroup>
        <thead><tr><th class=\"num\">#</th><th>${T_SEMGREP_TH_SEV}</th><th>${T_SEMGREP_TH_RULE}</th><th>${T_SEMGREP_TH_LOC}</th><th>${T_SEMGREP_TH_MSG}</th></tr></thead>
        <tbody>$(semgrep_rows_html "$gh_repo" "$([ -n "$TARGET_REF" ] && echo "$TARGET_REF" || echo "HEAD")")</tbody>
      </table></div>
    </details>" || true)
    <div class="raw-link">📄 <a href="semgrep.json" target="_blank" rel="noopener noreferrer">${T_RAW_JSON}</a></div>
  </div>
</div>

<!-- ══════════════════════════════════════
     MODULE: Trivy
     ══════════════════════════════════════ -->
<div class="module">
  <div class="mod-head">
    <div class="mod-title"><span class="mod-icon">🛡️</span> ${T_TRIVY_MODULE_TITLE}</div>
    ${trivy_badge}
  </div>
  <div class="mod-body">
    $([ "$TRIVY_STATUS" == "pass"  ] && echo "<p class=\"msg ok\">${T_TRIVY_CLEAN}</p>" || true)
    $([ "$TRIVY_STATUS" == "error" ] && echo "<p class=\"msg warn\">${T_TRIVY_ERROR}</p>" || true)

    $([ "$(( TRIVY_CRITICAL + TRIVY_HIGH + TRIVY_MEDIUM + TRIVY_LOW ))" -gt 0 ] && echo "
    <details open>
      <summary>${T_TRIVY_VULN_LABEL} — ${TRIVY_CRITICAL} critical &nbsp;/&nbsp; ${TRIVY_HIGH} high &nbsp;/&nbsp; ${TRIVY_MEDIUM} medium &nbsp;/&nbsp; ${TRIVY_LOW} low</summary>
      <div class='tbl-wrap'><table class=\"tbl-fixed\">
        <colgroup><col class=\"col-sev\"><col class=\"col-cve\"><col class=\"col-pkg\"><col class=\"col-fix\"><col></colgroup>
        <thead><tr><th>${T_TRIVY_TH_SEV}</th><th>${T_TRIVY_TH_CVE}</th><th>${T_TRIVY_TH_PKG}</th><th>${T_TRIVY_TH_FIX}</th><th>${T_TRIVY_TH_TITLE}</th></tr></thead>
        <tbody>$(trivy_rows_html)</tbody>
      </table></div>
    </details>" || true)

    $([ "$TRIVY_SECRETS" -gt 0 ] && echo "
    <details open>
      <summary>⚠ ${TRIVY_SECRETS} ${T_TRIVY_SECRETS_LABEL}</summary>
      <div class='tbl-wrap'><table>
        <thead><tr><th>${T_TRIVY_TH_SEV}</th><th>${T_TRIVY_TH_TYPE}</th><th>${T_TRIVY_TH_FILE}</th><th>${T_TRIVY_TH_MATCH}</th></tr></thead>
        <tbody>$(trivy_secrets_html "$gh_repo" "$([ -n "$TARGET_REF" ] && echo "$TARGET_REF" || echo "HEAD")")</tbody>
      </table></div>
    </details>" || true)

    <div class="raw-link">📄 <a href="trivy_fs.json" target="_blank" rel="noopener noreferrer">${T_RAW_JSON}</a></div>
  </div>
</div>

<!-- ══════════════════════════════════════
     MODULE: Hadolint
     ══════════════════════════════════════ -->
<div class="module">
  <div class="mod-head">
    <div class="mod-title"><span class="mod-icon">🐳</span> ${T_HADOLINT_MODULE_TITLE}</div>
    ${hadolint_badge}
  </div>
  <div class="mod-body">
    $([ "$HADOLINT_STATUS" == "skipped_no_docker" ] && echo "<p class=\"msg muted\">${T_HADOLINT_SKIPPED}</p>" || true)
    $([ "$HADOLINT_STATUS" == "pass" ]              && echo "<p class=\"msg ok\">${T_HADOLINT_CLEAN}</p>" || true)
    $([ "$HADOLINT_FILES" -gt 0 ] && echo "<p class=\"msg muted\">${HADOLINT_FILES} ${T_HADOLINT_FILES_LABEL} &nbsp;·&nbsp; ${HADOLINT_ERRORS} errors &nbsp;·&nbsp; ${HADOLINT_WARNINGS} warnings$([ "${hadolint_info:-0}" -gt 0 ] && echo " &nbsp;·&nbsp; ${hadolint_info} info")</p>" || true)
    $([ "$HADOLINT_TOTAL" -gt 0 ] && echo "
    <details open>
      <summary>${HADOLINT_TOTAL} ${T_HADOLINT_FINDINGS_LABEL}</summary>
      <div class='tbl-wrap'><table class='tbl-fixed'>
        <colgroup><col class='col-num'><col class='col-sev'><col style='width:9%'><col class='col-loc'><col></colgroup>
        <thead><tr><th class='num'>#</th><th>${T_HADOLINT_TH_SEV}</th><th>${T_HADOLINT_TH_RULE}</th><th>${T_HADOLINT_TH_LOC}</th><th>${T_HADOLINT_TH_MSG}</th></tr></thead>
        <tbody>$(hadolint_rows_html "$gh_repo" "$([ -n "$TARGET_REF" ] && echo "$TARGET_REF" || echo "HEAD")")</tbody>
      </table></div>
    </details>" || true)
    $([ -s "$REPORT_DIR/hadolint.json" ] && echo "<div class='raw-link'>📄 <a href='hadolint.json' target='_blank' rel='noopener noreferrer'>${T_RAW_JSON}</a></div>" || true)
  </div>
</div>

<footer>check.sh &nbsp;·&nbsp; ${T_FOOTER_GENERATED} $(date "+%Y-%m-%d %H:%M %Z")</footer>

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

  # Strict validation: only allow well-formed GitHub repo URLs
  if ! [[ "$TARGET" =~ ^https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+(\.git)?/?$ ]]; then
    log_error "Invalid GitHub URL. Expected: https://github.com/owner/repo"
    exit 1
  fi

  # 1. Load .env safely — parse KEY=VALUE lines only, never execute arbitrary code
  local env_file
  env_file="$(dirname "$0")/.env"
  if [[ -f "$env_file" ]]; then
    while IFS='=' read -r key value; do
      # Accept only UPPER_CASE env var names; skip comments and blank lines
      [[ "$key" =~ ^[A-Z_][A-Z0-9_]*$ ]] || continue
      [[ -n "$value" ]] || continue
      # Strip optional surrounding quotes from value
      value="${value%\"}"
      value="${value#\"}"
      value="${value%\'}"
      value="${value#\'}"
      export "$key=$value"
    done < <(grep -E '^[A-Z_][A-Z0-9_]*=' "$env_file" | grep -v '^#')
    log_info "Loaded $env_file"
  fi

  # 2. Parse CLI flags (highest precedence — override .env)
  GENERATE_PDF=false
  local RUN_SEMGREP=true RUN_TRIVY=true RUN_VT=true RUN_HADOLINT=true
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --release)
        [[ $# -lt 2 ]] && { log_error "--release requires a value"; exit 1; }
        if ! [[ "$2" =~ ^[A-Za-z0-9._/-]+$ ]]; then
          log_error "Invalid --release value: '$2' (allowed: a-z A-Z 0-9 . _ / -)"
          exit 1
        fi
        TARGET_REF="$2"; shift ;;
      --no-semgrep)   RUN_SEMGREP=false ;;
      --no-trivy)     RUN_TRIVY=false ;;
      --no-vt)        RUN_VT=false ;;
      --no-hadolint)  RUN_HADOLINT=false ;;
      --pdf)          GENERATE_PDF=true ;;
      --vt-key)
        [[ $# -lt 2 ]] && { log_error "--vt-key requires a value"; exit 1; }
        VT_API_KEY="$2"; shift ;;
      --lang)
        [[ $# -lt 2 ]] && { log_error "--lang requires a value"; exit 1; }
        LANG_REPORT="$2"; shift ;;
      *) log_warn "Unknown option: $1" ;;
    esac
    shift
  done

  echo -e "${BOLD}${CYAN}"
  echo "╔══════════════════════════════════════════════════╗"
  echo "║   OSS Security Scanner                         ║"
  echo "║   VirusTotal · Semgrep · Trivy · Hadolint      ║"
  echo "╚══════════════════════════════════════════════════╝"
  echo -e "${NC}"
  log_info "Target : $TARGET"
  [[ -n "$TARGET_REF" ]] && log_info "Ref    : $TARGET_REF" || log_info "Ref    : HEAD (default branch)"
  [[ -z "$VT_API_KEY" ]] && log_warn "VT_API_KEY not set — VirusTotal scan will be skipped"

  check_deps
  setup_workdir
  # Always generate HTML report on exit — even if a scanner crashes
  trap 'generate_report 2>/dev/null || true; [[ "$GENERATE_PDF" == true ]] && generate_pdf 2>/dev/null || true; cleanup' EXIT

  clone_repo

  [[ "$RUN_SEMGREP"   == true ]] && run_semgrep     || true
  [[ "$RUN_TRIVY"     == true ]] && run_trivy       || true
  [[ "$RUN_VT"        == true ]] && run_virustotal  || true
  [[ "$RUN_HADOLINT"  == true ]] && run_hadolint    || true

  generate_report
  [[ "$GENERATE_PDF" == true ]] && generate_pdf

  local overall
  overall=$(overall_status)
  echo ""
  log_section "FINAL RESULT: $overall"
  echo -e "  VirusTotal  : $(term_badge "$VT_STATUS")  malicious=$VT_MALICIOUS/$VT_TOTAL"
  echo -e "  Semgrep     : $(term_badge "$SEMGREP_STATUS")  findings=$SEMGREP_FINDINGS  errors=$SEMGREP_ERRORS"
  echo -e "  Trivy       : $(term_badge "$TRIVY_STATUS")  critical=$TRIVY_CRITICAL  high=$TRIVY_HIGH  secrets=$TRIVY_SECRETS"
  echo -e "  Hadolint    : $(term_badge "$HADOLINT_STATUS")  files=$HADOLINT_FILES  errors=$HADOLINT_ERRORS  warnings=$HADOLINT_WARNINGS"
  echo ""
  echo -e "  ${BOLD}HTML:${NC} file://$REPORT_DIR/report.html"
  [[ "$GENERATE_PDF" == true && -f "$REPORT_DIR/report.pdf" ]] && echo -e "  ${BOLD}PDF :${NC} file://$REPORT_DIR/report.pdf"
  echo ""
}

main "$@"
