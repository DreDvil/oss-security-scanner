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
GRYPE_IMAGE="anchore/grype:latest"
VT_IMAGE_LOCAL="vt-cli:local"      # built locally from Dockerfile.vt

# ── Global state ──────────────────────────────────────────────────────────────
TARGET=""
TARGET_REF=""    # specific tag/branch to scan (empty = default branch HEAD)
WORK_DIR=""
REPORT_DIR=""
RAW_DIR=""
LOG_DIR=""
VT_CFG_DIR=""
VT_API_KEY="${VT_API_KEY:-}"
LANG_REPORT="${LANG_REPORT:-en}"     # Report language: en | ru
PDF_IMAGE_LOCAL="weasyprint-pdf:local"  # built locally from Dockerfile.pdf

REPORT_GENERATED=false
PDF_GENERATED=false
GENERATE_PDF=false
OUTPUT_FORMAT=""

# Result variables (set by each scanner)
SEMGREP_STATUS="skipped";   SEMGREP_FINDINGS=0;  SEMGREP_ERRORS=0;  SEMGREP_HIDDEN=0;  SEMGREP_AUDIT_FINDINGS=0;  SEMGREP_VISIBLE=0;  SEMGREP_MIN_SEV="medium";  SEMGREP_UNIQUE_RULES=0
TRIVY_STATUS="skipped";     TRIVY_CRITICAL=0;    TRIVY_HIGH=0; TRIVY_MEDIUM=0; TRIVY_LOW=0; TRIVY_SECRETS=0
VT_STATUS="skipped";        VT_MALICIOUS=0;      VT_TOTAL=0
HADOLINT_STATUS="skipped";  HADOLINT_ERRORS=0;   HADOLINT_WARNINGS=0; HADOLINT_TOTAL=0; HADOLINT_FILES=0
GRYPE_STATUS="skipped";   GRYPE_CRITICAL=0;    GRYPE_HIGH=0; GRYPE_MEDIUM=0; GRYPE_LOW=0
GRYPE_PKG_COUNT=0; GRYPE_DB_AGE_DAYS=-1; DEP_MANIFESTS_PRESENT=false
TRIVY_PKG_COUNT=0
MERGED_CRITICAL=0; MERGED_HIGH=0; MERGED_MEDIUM=0; MERGED_LOW=0
TOTAL_TRIVY=0; TOTAL_GRYPE=0; TOTAL_MERGED=0
SEMGREP_HIGH_VISIBLE=0; SEMGREP_MEDIUM_VISIBLE=0; RISK_SCORE=0
COMPARE_DIR=""
PID_SEMGREP="" PID_TRIVY="" PID_GRYPE="" PID_VT="" PID_HADOLINT=""
# Diff result globals (populated by compare_findings())
DIFF_CVE_NEW=""; DIFF_CVE_CLOSED=""; DIFF_CVE_PERSISTENT=""
DIFF_SEMGREP_NEW=""; DIFF_SEMGREP_CLOSED=""; DIFF_SEMGREP_PERSISTENT=""
DIFF_HADOLINT_NEW=""; DIFF_HADOLINT_CLOSED=""; DIFF_HADOLINT_PERSISTENT=""
VT_DIFF_PREV=0; VT_DIFF_CURR=0
# Config globals (populated by read_scanner_config())
CFG_SEMGREP_EXCLUDES=()
CFG_CVE_IGNORE=()
CFG_SEMGREP_RULE_IGNORES=()
CFG_MIN_SEVERITY=""
SEMGREP_MIN_SEV_SET_BY_CLI=false
FORCE_SCAN=false
CACHE_HIT=false

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
  --no-grype      Skip Grype scan
  --pdf           Also generate PDF report (requires Docker + Dockerfile.pdf)
  --vt-key KEY    VirusTotal API key (overrides VT_API_KEY env)
  --lang LANG     Report language: en (default) or ru
  --semgrep-min-severity LEVEL  Minimum severity to show: info|low|medium|high (default: medium)
  --compare DIR   Compare with a prior report directory (adds 'Изменения' diff section)
  --force         Bypass scan cache and run a full fresh scan

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
  RAW_DIR="$REPORT_DIR/raw"
  LOG_DIR="$REPORT_DIR/logs"
  mkdir -p "$RAW_DIR" "$LOG_DIR"
  log_info "Working directory : $WORK_DIR"
  log_info "Report directory  : $REPORT_DIR"
}

# ── Scan cache detection ──────────────────────────────────────────────────────
# check_scan_cache: if a previous report exists for the same (TARGET, TARGET_REF)
# and --force was not given, prompt to reuse it (auto-reuse in CI/non-tty).
# Sets REPORT_DIR and CACHE_HIT=true on reuse; returns silently on miss or --force.
check_scan_cache() {
  [[ "$FORCE_SCAN" == true ]] && return  # --force bypasses cache entirely

  local safe_name safe_ref=""
  safe_name=$(echo "$TARGET" | sed 's|https://github.com/||g; s|[^a-zA-Z0-9._-]|_|g' | cut -c1-50)
  [[ -n "$TARGET_REF" ]] && safe_ref="_$(echo "$TARGET_REF" | sed 's|[^a-zA-Z0-9._-]|_|g' | cut -c1-20)"
  local suffix="${safe_name}${safe_ref}"

  # Find the most recent matching report directory (sort -r → newest timestamp first)
  # Escape dots in suffix so find -name treats them as literals, not glob wildcards
  local find_suffix="${suffix//./\\.}"
  local cached_dir
  cached_dir=$(find "$(pwd)/reports" -maxdepth 1 -type d -name "*_${find_suffix}" 2>/dev/null \
    | sort -r | head -1)
  [[ -z "$cached_dir" ]] && return  # no cache found

  # Format the date prefix (YYYYMMDD → YYYY-MM-DD) for display
  local cache_date
  cache_date=$(basename "$cached_dir" | cut -c1-8)
  cache_date="${cache_date:0:4}-${cache_date:4:2}-${cache_date:6:2}"

  local reuse=true
  if [[ -t 0 ]]; then
    # Interactive stdin: prompt with default-yes (anything except explicit 'n' reuses)
    read -rp "[INFO] Found cached scan from ${cache_date} for this repo. Reuse? [Y/n]: " _ans || true
    [[ "$_ans" == "n" || "$_ans" == "N" ]] && reuse=false
  else
    log_info "Non-interactive mode — auto-reusing cached scan from ${cache_date}"
  fi

  if [[ "$reuse" == true ]]; then
    REPORT_DIR="$cached_dir"
    RAW_DIR="$REPORT_DIR/raw"
    LOG_DIR="$REPORT_DIR/logs"
    CACHE_HIT=true
    log_ok "Reusing cached report directory: $REPORT_DIR"
  fi
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

# ── Read per-repo scanner config (.scanner-config JSON) ──────────────────────
read_scanner_config() {
  local cfg_file="$WORK_DIR/source/.scanner-config"
  [[ ! -f "$cfg_file" ]] && return

  # Validate it's parseable JSON before doing anything
  if ! jq -e '.' "$cfg_file" &>/dev/null; then
    log_warn ".scanner-config is not valid JSON — skipping"
    return
  fi

  # Read arrays into bash arrays (bash 3.2: no mapfile, use while+read)
  while IFS= read -r item; do
    CFG_SEMGREP_EXCLUDES+=("$item")
  done < <(jq -r '.semgrep_excludes[]? // empty' "$cfg_file" 2>/dev/null)

  while IFS= read -r item; do
    CFG_CVE_IGNORE+=("$item")
  done < <(jq -r '.cve_ignore[]? // empty' "$cfg_file" 2>/dev/null)

  while IFS= read -r item; do
    CFG_SEMGREP_RULE_IGNORES+=("$item")
  done < <(jq -r '.semgrep_rule_ignores[]? // empty' "$cfg_file" 2>/dev/null)

  CFG_MIN_SEVERITY=$(jq -r '.min_severity // empty' "$cfg_file" 2>/dev/null || true)

  # Validate min_severity against allowlist before using it
  if [[ -n "$CFG_MIN_SEVERITY" ]]; then
    case "$CFG_MIN_SEVERITY" in
      info|low|medium|high)
        [[ "$SEMGREP_MIN_SEV_SET_BY_CLI" == false ]] && SEMGREP_MIN_SEV="$CFG_MIN_SEVERITY"
        ;;
      *)
        log_warn ".scanner-config: unknown min_severity '${CFG_MIN_SEVERITY}' — ignored (valid: info|low|medium|high)"
        CFG_MIN_SEVERITY=""
        ;;
    esac
  fi

  local n_suppressions=$(( ${#CFG_CVE_IGNORE[@]} + ${#CFG_SEMGREP_RULE_IGNORES[@]} ))
  log_info "Applying .scanner-config from repo root ($n_suppressions suppressions)"
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

# ── Dependency manifest detection (GRYPE-03/04) ───────────────────────────────
# Returns 0 if any ecosystem manifest file is present in WORK_DIR/source.
# Tests manifest files only — no source extension scanning (avoids polyglot FPs).
_has_dep_manifests() {
  local src="$WORK_DIR/source"
  [[ ! -d "$src" ]] && return 1
  [[ -f "$src/package.json" ]]     && return 0
  [[ -f "$src/requirements.txt" ]] && return 0
  [[ -f "$src/pyproject.toml" ]]   && return 0
  [[ -f "$src/setup.py" ]]         && return 0
  [[ -f "$src/go.mod" ]]           && return 0
  [[ -f "$src/Gemfile" ]]          && return 0
  [[ -f "$src/pom.xml" ]]          && return 0
  [[ -f "$src/build.gradle" ]]     && return 0
  [[ -f "$src/build.gradle.kts" ]] && return 0
  [[ -f "$src/composer.json" ]]    && return 0
  [[ -f "$src/Cargo.toml" ]]       && return 0
  return 1
}

# ── Semgrep ───────────────────────────────────────────────────────────────────
run_semgrep() {
  log_section "Semgrep — Static Code Analysis"

  local out="$RAW_DIR/semgrep.json"
  local semgrep_log="$LOG_DIR/semgrep.log"

  local semgrep_timeout=900  # 15 min — large codebases can take a while

  # Build extra --exclude flags from .scanner-config (per-repo config, T-07-02-01 mitigation)
  local extra_excludes_arr=()
  for excl in "${CFG_SEMGREP_EXCLUDES[@]}"; do
    extra_excludes_arr+=("--exclude" "$excl")
  done

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
      --exclude 'test' \
      --exclude 'tests' \
      --exclude '__tests__' \
      --exclude 'spec' \
      --exclude 'vendor' \
      --exclude 'node_modules' \
      --exclude 'third_party' \
      --exclude 'fixtures' \
      --exclude 'mocks' \
      --exclude 'testdata' \
      "${extra_excludes_arr[@]}" \
      /src > "$out" 2>"$semgrep_log" || true

  # Level 2: auto failed → smart multi-ruleset based on detected languages.
  # These rulesets are downloaded from semgrep.dev; may fail when offline.
  if [[ ! -s "$out" ]] || ! jq -e '.results' "$out" &>/dev/null; then
    log_info "Auto-config unavailable — detecting project languages…"
    local cfgs
    cfgs=$(_semgrep_configs)
    local config_args_arr=()
    for c in $cfgs; do
      config_args_arr+=("--config=$c")
    done
    log_info "Running with rulesets: $cfgs"
    timeout "$semgrep_timeout" docker run --rm \
      -v "$WORK_DIR/source:/src:ro" \
      "$SEMGREP_IMAGE" \
      semgrep scan \
        "${config_args_arr[@]}" \
        --json \
        --metrics=off \
        --exclude 'Dockerfile*' \
        --exclude '*.dockerfile' \
        --exclude 'test' \
        --exclude 'tests' \
        --exclude '__tests__' \
        --exclude 'spec' \
        --exclude 'vendor' \
        --exclude 'node_modules' \
        --exclude 'third_party' \
        --exclude 'fixtures' \
        --exclude 'mocks' \
        --exclude 'testdata' \
        "${extra_excludes_arr[@]}" \
        /src > "$out" 2>>"$semgrep_log" || true
  fi

  # Level 3: p/default fallback — run when previous levels produced no valid output
  # OR found 0 findings (network rules may have silently loaded 0 rules on timeout).
  local l3_out="$RAW_DIR/semgrep_default.json"
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
        --exclude 'test' \
        --exclude 'tests' \
        --exclude '__tests__' \
        --exclude 'spec' \
        --exclude 'vendor' \
        --exclude 'node_modules' \
        --exclude 'third_party' \
        --exclude 'fixtures' \
        --exclude 'mocks' \
        --exclude 'testdata' \
        "${extra_excludes_arr[@]}" \
        /src > "$l3_out" 2>>"$semgrep_log" || true

    if [[ -s "$l3_out" ]] && jq -e '.results' "$l3_out" &>/dev/null; then
      if [[ -s "$out" ]] && jq -e '.results' "$out" &>/dev/null; then
        jq -s '{
          results: (
            .[0].results + .[1].results
            | sort_by(.extra.severity | if . == "ERROR" then 0 elif . == "WARNING" then 1 else 2 end)
            | unique_by([.path, .start.line, .start.col])
          ),
          errors: (.[0].errors + .[1].errors)
        }' "$out" "$l3_out" > "$out.merged" && mv "$out.merged" "$out"
      else
        mv "$l3_out" "$out"
      fi
    fi
  fi

  # Final positional dedup pass — covers Level 1 output that never went through the L2+L3 merge
  if [[ -s "$out" ]] && jq -e '.results' "$out" &>/dev/null; then
    jq '{
      results: (
        .results
        | sort_by(.extra.severity | if . == "ERROR" then 0 elif . == "WARNING" then 1 else 2 end)
        | unique_by([.path, .start.line, .start.col])
      ),
      errors: .errors
    }' "$out" > "$out.deduped" && mv "$out.deduped" "$out"
  fi

  if [[ ! -s "$out" ]] || ! jq -e '.results' "$out" &>/dev/null; then
    # Check if the failure is due to network issues (semgrep.dev unreachable)
    if grep -q "Read timed out\|ConnectionError\|semgrep.dev" "$semgrep_log" 2>/dev/null; then
      log_warn "Semgrep failed: semgrep.dev unreachable (network timeout). Scan skipped."
      SEMGREP_STATUS="error"
    else
      log_warn "Semgrep produced no usable output — see logs/semgrep.log"
      SEMGREP_STATUS="error"
    fi
    return
  fi

  SEMGREP_FINDINGS=$(jq '[.results[]] | length' "$out" 2>/dev/null || echo 0)
  SEMGREP_ERRORS=$(jq '[.errors[]] | length' "$out" 2>/dev/null || echo 0)
  SEMGREP_AUDIT_FINDINGS=$(jq '[.results[] | select(.check_id | test("audit|test|benchmark|example|sample"; "i"))] | length' "$out" 2>/dev/null || echo 0)

  SEMGREP_VISIBLE=$(jq --arg min_sev "$SEMGREP_MIN_SEV" '
    def above_threshold:
      if   $min_sev == "high"   then . == "ERROR"
      elif $min_sev == "medium" then (. == "ERROR" or . == "WARNING")
      elif $min_sev == "low"    then (. == "ERROR" or . == "WARNING" or . == "LOW")
      else true
      end;
    [.results[]
      | select(.check_id | test("audit|test|benchmark|example|sample"; "i") | not)
      | select(.extra.severity | above_threshold)
    ] | length
  ' "$out" 2>/dev/null || echo 0)

  SEMGREP_HIDDEN=$(jq --arg min_sev "$SEMGREP_MIN_SEV" '
    def above_threshold:
      if   $min_sev == "high"   then . == "ERROR"
      elif $min_sev == "medium" then (. == "ERROR" or . == "WARNING")
      elif $min_sev == "low"    then (. == "ERROR" or . == "WARNING" or . == "LOW")
      else true
      end;
    [.results[]
      | select(.check_id | test("audit|test|benchmark|example|sample"; "i") | not)
      | select(.extra.severity | above_threshold | not)
    ] | length
  ' "$out" 2>/dev/null || echo 0)

  SEMGREP_UNIQUE_RULES=$(jq --arg min_sev "$SEMGREP_MIN_SEV" '
    def above_threshold:
      if   $min_sev == "high"   then . == "ERROR"
      elif $min_sev == "medium" then (. == "ERROR" or . == "WARNING")
      elif $min_sev == "low"    then (. == "ERROR" or . == "WARNING" or . == "LOW")
      else true end;
    [ .results[]
      | select(.check_id | test("audit|test|benchmark|example|sample"; "i") | not)
      | select(.extra.severity | above_threshold)
      | .check_id | gsub("-[0-9a-f]{8,}$";"")
    ] | unique | length
  ' "$out" 2>/dev/null || echo 0)

  SEMGREP_HIGH_VISIBLE=$(jq '[
    .results[]
      | select(.check_id | test("audit|test|benchmark|example|sample"; "i") | not)
      | select(.extra.severity == "ERROR")
    ] | length
  ' "$out" 2>/dev/null || echo 0)

  SEMGREP_MEDIUM_VISIBLE=$(jq '[
    .results[]
      | select(.check_id | test("audit|test|benchmark|example|sample"; "i") | not)
      | select(.extra.severity == "WARNING")
    ] | length
  ' "$out" 2>/dev/null || echo 0)

  if [[ "$SEMGREP_VISIBLE" -eq 0 && "$SEMGREP_AUDIT_FINDINGS" -eq 0 ]]; then
    log_ok "No findings"
    SEMGREP_STATUS="pass"
  elif [[ "$SEMGREP_HIGH_VISIBLE" -gt 0 ]]; then
    log_warn "$SEMGREP_VISIBLE finding(s) — ${SEMGREP_HIGH_VISIBLE} high-severity"
    # Print top findings (severity is semgrep's own classification, not a script error)
    jq -r '.results[:10][] |
      "  · \(.extra.severity | if . == "ERROR" then "HIGH" elif . == "WARNING" then "MEDIUM" else . end)\t\(.check_id | split(".") | last)\t\(.path | split("/") | last):\(.start.line)"' \
      "$out" 2>/dev/null | column -t -s $'\t' || true
    SEMGREP_STATUS="fail"
  elif [[ "$SEMGREP_VISIBLE" -gt 0 ]]; then
    log_warn "$SEMGREP_VISIBLE finding(s) — top 10:"
    jq -r '.results[:10][] |
      "  · \(.extra.severity | if . == "ERROR" then "HIGH" elif . == "WARNING" then "MEDIUM" else . end)\t\(.check_id | split(".") | last)\t\(.path | split("/") | last):\(.start.line)"' \
      "$out" 2>/dev/null | column -t -s $'\t' || true
    SEMGREP_STATUS="warn"
  else
    # Only audit/hidden findings — still pass
    log_ok "No actionable findings (audit/hidden only)"
    SEMGREP_STATUS="pass"
  fi
}

# ── Trivy ─────────────────────────────────────────────────────────────────────
run_trivy() {
  log_section "Trivy — Dependency & Secret Scan"

  local out="$RAW_DIR/trivy_fs.json"
  local trivy_timeout=600  # 10 min

  log_info "Running Trivy (timeout ${trivy_timeout}s)…"
  local ec=0
  timeout "$trivy_timeout" docker run --rm \
    -v "$WORK_DIR/source:/target:ro" \
    -v "$RAW_DIR:/reports" \
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
  TRIVY_PKG_COUNT=$(jq '[.Results[]?.Packages[]?] | length' "$out" 2>/dev/null || echo 0)

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

# ── CVE Merge / Deduplication ─────────────────────────────────────────────────
merge_vulns() {
  local trivy_json="$RAW_DIR/trivy_fs.json"
  local grype_json="$RAW_DIR/grype.json"
  local out="$RAW_DIR/vulns_merged.json"

  log_section "CVE Deduplication"

  # Normalize Trivy entries to common schema with found_by=trivy
  local trivy_normalized="[]"
  if [[ -s "$trivy_json" ]]; then
    trivy_normalized=$(jq '[
      .Results[]? | .Vulnerabilities[]? |
      {
        id: .VulnerabilityID,
        pkg: .PkgName,
        version: (.InstalledVersion // ""),
        fix: (.FixedVersion // ""),
        severity: .Severity,
        title: (.Title // "N/A"),
        found_by: "trivy",
        cvss: ((.CVSS // {} | .nvd.V3Score // .ghsa.V3Score // .redhat.V3Score // (to_entries | if length > 0 then .[0].value.V3Score // null else null end)) | tonumber? // null)
      }
    ]' "$trivy_json" 2>/dev/null || echo "[]")
  fi

  # Normalize Grype entries to common schema with found_by=grype.
  # Logic lives in lib/scanner.grype-normalize.jq (shared with the test suite);
  # see that file for the crash-safety + GHSA->CVE aliasing rationale.
  local grype_normalized="[]"
  if [[ -s "$grype_json" ]]; then
    local grype_err
    grype_err=$(mktemp)
    grype_normalized=$(jq -f "$(dirname "$0")/lib/scanner.grype-normalize.jq" "$grype_json" 2>"$grype_err") || {
      log_warn "Grype normalization failed — grype findings will be MISSING from the merge:"
      sed 's/^/    /' "$grype_err" >&2
      grype_normalized="[]"
    }
    rm -f "$grype_err"
  fi

  # Merge: canonicalized key dedup + set-of-scanners found_by via scanner.merge.jq
  local jq_file
  jq_file="$(dirname "$0")/lib/scanner.merge.jq"
  jq -n \
    --argjson trivy "$trivy_normalized" \
    --argjson grype "$grype_normalized" \
    -f "$jq_file" > "$out" 2>/dev/null \
    || { log_warn "merge_vulns: jq failed — vulns_merged.json set to []"; echo "[]" > "$out"; }

  MERGED_CRITICAL=$(jq '[.[] | select(.severity=="CRITICAL")] | length' "$out" 2>/dev/null || echo 0)
  MERGED_HIGH=$(jq     '[.[] | select(.severity=="HIGH")]     | length' "$out" 2>/dev/null || echo 0)
  MERGED_MEDIUM=$(jq   '[.[] | select(.severity=="MEDIUM")]   | length' "$out" 2>/dev/null || echo 0)
  MERGED_LOW=$(jq      '[.[] | select(.severity=="LOW")]      | length' "$out" 2>/dev/null || echo 0)

  TOTAL_TRIVY=$(jq 'length' <<< "$trivy_normalized" 2>/dev/null || echo 0)
  TOTAL_GRYPE=$(jq 'length' <<< "$grype_normalized" 2>/dev/null || echo 0)
  TOTAL_MERGED=$(jq 'length' "$out" 2>/dev/null || echo 0)

  log_info "Trivy: $TOTAL_TRIVY  Grype: $TOTAL_GRYPE  After dedup: $TOTAL_MERGED"
  log_info "Merged — CRITICAL: $MERGED_CRITICAL  HIGH: $MERGED_HIGH  MEDIUM: $MERGED_MEDIUM  LOW: $MERGED_LOW"
  log_ok "vulns_merged.json written"
}

# ── Grype ─────────────────────────────────────────────────────────────────────
run_grype() {
  log_section "Grype — CVE Scan"

  local out="$RAW_DIR/grype.json"
  local grype_timeout=600  # 10 min

  log_info "Ensuring grype-db-cache volume exists…"
  docker volume create grype-db-cache 2>/dev/null || true

  log_info "Running Grype (timeout ${grype_timeout}s)…"
  local ec=0
  timeout "$grype_timeout" docker run --rm \
    -v "$WORK_DIR/source:/target:ro" \
    -v "$RAW_DIR:/reports" \
    -v "grype-db-cache:/root/.cache/grype/db" \
    "$GRYPE_IMAGE" \
    dir:/target \
      --output json \
      --file /reports/grype.json \
      --quiet 2>/dev/null || ec=$?
  if [[ $ec -ne 0 ]]; then
    if [[ $ec -eq 124 ]]; then
      log_warn "Grype timed out after ${grype_timeout}s"
    else
      log_warn "Grype exited with code $ec"
    fi
  fi

  if [[ ! -s "$out" ]]; then
    log_warn "Grype produced no output"
    GRYPE_STATUS="error"
    return
  fi

  # Grype severity values are Title-case: Critical, High, Medium, Low
  GRYPE_CRITICAL=$(jq '[.matches[]?.vulnerability | select(.severity=="Critical")] | length' "$out" 2>/dev/null || echo 0)
  GRYPE_HIGH=$(jq     '[.matches[]?.vulnerability | select(.severity=="High")]     | length' "$out" 2>/dev/null || echo 0)
  GRYPE_MEDIUM=$(jq   '[.matches[]?.vulnerability | select(.severity=="Medium")]   | length' "$out" 2>/dev/null || echo 0)
  GRYPE_LOW=$(jq      '[.matches[]?.vulnerability | select(.severity=="Low")]      | length' "$out" 2>/dev/null || echo 0)

  # GRYPE-03 diagnostics: package proxy count, DB age, manifest detection
  GRYPE_PKG_COUNT=$(jq '[.matches[]?.artifact | {name, version}] | unique | length' \
    "$out" 2>/dev/null || echo 0)
  GRYPE_DB_AGE_DAYS=$(jq -r '
    if (.descriptor.db.status.built // null) != null then
      (.descriptor.db.status.built | fromdateiso8601) as $built |
      ((now - $built) / 86400 | floor) | tostring
    else
      "-1"
    end
  ' "$out" 2>/dev/null || echo "-1")
  if _has_dep_manifests; then
    DEP_MANIFESTS_PRESENT=true
  else
    DEP_MANIFESTS_PRESENT=false
  fi
  log_info "Grype diagnostics — matches: $GRYPE_CRITICAL+$GRYPE_HIGH+$GRYPE_MEDIUM+$GRYPE_LOW  pkg_proxy: $GRYPE_PKG_COUNT  db_age_days: $GRYPE_DB_AGE_DAYS  manifests: $DEP_MANIFESTS_PRESENT"

  echo -e "  Vulnerabilities — ${RED}CRITICAL: $GRYPE_CRITICAL${NC}  ${YELLOW}HIGH: $GRYPE_HIGH${NC}  MEDIUM: $GRYPE_MEDIUM  LOW: $GRYPE_LOW"

  if [[ "$GRYPE_CRITICAL" -gt 0 ]]; then
    GRYPE_STATUS="fail"
    log_error "Critical vulnerabilities:"
    jq -r '.matches[]? | select(.vulnerability.severity=="Critical") |
      "  [\(.vulnerability.id)] \(.artifact.name)@\(.artifact.version // "?"): \(.vulnerability.description // "N/A")"' \
      "$out" 2>/dev/null | head -10 || true
  elif [[ "$GRYPE_HIGH" -gt 0 ]]; then
    GRYPE_STATUS="warn"
    log_warn "High vulnerabilities found"
  else
    GRYPE_STATUS="pass"
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
  dockerfile="$(dirname "$0")/docker/Dockerfile.vt"
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
  # sha256sum is GNU coreutils — not present on macOS base; fall back to shasum or openssl.
  local sha256
  sha256=$(sha256sum "$archive" 2>/dev/null | awk '{print $1}' \
           || shasum -a 256 "$archive" 2>/dev/null | awk '{print $1}' \
           || openssl dgst -sha256 "$archive" 2>/dev/null | awk '{print $NF}' \
           || true)
  if [[ -z "$sha256" ]]; then
    log_warn "Could not compute SHA256 of archive — skipping VT cache lookup"
  fi
  log_info "SHA256: ${sha256:-<unavailable>}"

  # SEC-3: write API key to a temp config file so it never appears in `ps aux`
  local vt_out
  VT_CFG_DIR=$(mktemp -d /tmp/vt_cfg_XXXXXX)
  chmod 700 "$VT_CFG_DIR"
  printf 'apikey = "%s"\n' "$VT_API_KEY" > "$VT_CFG_DIR/vt.toml"
  chmod 600 "$VT_CFG_DIR/vt.toml"

  if [[ -n "$sha256" ]]; then
    vt_out=$(docker run --rm \
      -v "$VT_CFG_DIR/vt.toml:/root/.vt.toml:ro" \
      "$VT_IMAGE_LOCAL" \
      file "$sha256" 2>&1 || true)
  else
    vt_out=""
  fi

  # Check success first: a valid vt-cli response always contains last_analysis_stats.
  # Only then check error codes to avoid false positives from engine detection names
  # (e.g. "Trojan.Invalid.PE", "W32.Forbidden.Agent") matching broad grep patterns.
  if echo "$vt_out" | grep -q 'last_analysis_stats:'; then
    log_ok "Found in VirusTotal cache"
  elif echo "$vt_out" | grep -qiE 'NotFoundError|ItemNotFoundError|not found|404'; then
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
    # Post-upload: success requires last_analysis_stats in response
    if ! echo "$vt_out" | grep -q 'last_analysis_stats:'; then
      log_error "VirusTotal post-upload fetch returned no results: $(echo "$vt_out" | head -1)"
      rm -rf "$VT_CFG_DIR"; VT_CFG_DIR=""
      VT_STATUS="error"
      return
    fi
  else
    # No last_analysis_stats and no NotFoundError — genuine API/auth error
    log_error "VirusTotal API error: $(echo "$vt_out" | head -2 | tr '\n' ' ')"
    rm -rf "$VT_CFG_DIR"; VT_CFG_DIR=""
    VT_STATUS="error"
    return
  fi

  # Remove temp config dir (key no longer needed)
  rm -rf "$VT_CFG_DIR"; VT_CFG_DIR=""

  # Save raw output (includes full vt-cli YAML-like response)
  echo "$vt_out" > "$RAW_DIR/virustotal.txt"

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
    inconclusive)     echo '<span class="badge inconclusive">INCONCLUSIVE</span>' ;;
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
  [[ "$SEMGREP_STATUS" == "fail" || "$TRIVY_STATUS" == "fail" || "$GRYPE_STATUS" == "fail" || "$VT_STATUS" == "fail" || "$HADOLINT_STATUS" == "fail" ]] && s="FAIL"
  [[ "$s" != "FAIL" ]] && {
    [[ "$SEMGREP_STATUS" == "warn" || "$TRIVY_STATUS" == "warn" || "$GRYPE_STATUS" == "warn" || "$VT_STATUS" == "warn" || "$HADOLINT_STATUS" == "warn" ]] && s="WARN"
  }
  echo "$s"
}

trivy_secrets_html() {
  # $1 = gh_repo (owner/repo), $2 = ref (tag or HEAD)
  [[ ! -s "$RAW_DIR/trivy_fs.json" ]] && return
  local base="https://github.com/${1}/blob/${2}"
  jq -r --arg base "$base" '
    .Results[]? | . as $r | .Secrets[]? |
    "<tr>
      <td class=\"sev-\(.Severity | ascii_downcase)\">\(.Severity)</td>
      <td>\(.Title | gsub("&";"&amp;") | gsub("<";"&lt;") | gsub(">";"&gt;"))</td>
      <td class=\"loc-cell\"><a href=\"\($base)/\($r.Target | gsub("&";"&amp;") | gsub("<";"&lt;") | gsub(">";"&gt;") | gsub("\"";"&quot;"))\" target=\"_blank\" rel=\"noopener noreferrer\" class=\"loc-link\">\($r.Target | gsub("&";"&amp;") | gsub("<";"&lt;") | gsub(">";"&gt;"))</a></td>
      <td class=\"desc-cell\"><code>\(.Match | gsub("&";"&amp;") | gsub("<";"&lt;") | gsub(">";"&gt;") | .[0:120])</code></td>
    </tr>"' "$RAW_DIR/trivy_fs.json" 2>/dev/null || true
}

# ── Hadolint ──────────────────────────────────────────────────────────────────
run_hadolint() {
  log_section "Hadolint — Dockerfile Analysis"

  local out="$RAW_DIR/hadolint.json"

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

# ── Parallel execution helpers ────────────────────────────────────────────────

# _pids_running: returns 0 (true) if any given PID is still alive, 1 if all done.
# Uses POSIX kill -0 (bash 3.2 compatible — no wait -n which requires bash 4.3+).
_pids_running() {
  local pid
  for pid in "$@"; do
    kill -0 "$pid" 2>/dev/null && return 0
  done
  return 1
}

wrapper_semgrep() {
  local log="$LOG_DIR/semgrep-run.log"
  local env_file="$LOG_DIR/semgrep.env"

  { run_semgrep; } >> "$log" 2>&1

  printf 'SEMGREP_STATUS=%s\n'         "$SEMGREP_STATUS"          > "$env_file"
  printf 'SEMGREP_FINDINGS=%s\n'       "$SEMGREP_FINDINGS"       >> "$env_file"
  printf 'SEMGREP_ERRORS=%s\n'         "$SEMGREP_ERRORS"         >> "$env_file"
  printf 'SEMGREP_AUDIT_FINDINGS=%s\n' "$SEMGREP_AUDIT_FINDINGS" >> "$env_file"
  printf 'SEMGREP_VISIBLE=%s\n'        "$SEMGREP_VISIBLE"        >> "$env_file"
  printf 'SEMGREP_HIDDEN=%s\n'         "$SEMGREP_HIDDEN"         >> "$env_file"
  printf 'SEMGREP_UNIQUE_RULES=%s\n'   "$SEMGREP_UNIQUE_RULES"   >> "$env_file"
  printf 'SEMGREP_HIGH_VISIBLE=%s\n'   "$SEMGREP_HIGH_VISIBLE"   >> "$env_file"
  printf 'SEMGREP_MEDIUM_VISIBLE=%s\n' "$SEMGREP_MEDIUM_VISIBLE" >> "$env_file"
}

wrapper_trivy() {
  local log="$LOG_DIR/trivy-run.log"
  local env_file="$LOG_DIR/trivy.env"

  { run_trivy; } >> "$log" 2>&1

  printf 'TRIVY_STATUS=%s\n'   "$TRIVY_STATUS"   > "$env_file"
  printf 'TRIVY_CRITICAL=%s\n' "$TRIVY_CRITICAL" >> "$env_file"
  printf 'TRIVY_HIGH=%s\n'     "$TRIVY_HIGH"     >> "$env_file"
  printf 'TRIVY_MEDIUM=%s\n'   "$TRIVY_MEDIUM"   >> "$env_file"
  printf 'TRIVY_LOW=%s\n'      "$TRIVY_LOW"      >> "$env_file"
  printf 'TRIVY_SECRETS=%s\n'    "$TRIVY_SECRETS"    >> "$env_file"
  printf 'TRIVY_PKG_COUNT=%s\n' "$TRIVY_PKG_COUNT" >> "$env_file"
}

wrapper_grype() {
  local log="$LOG_DIR/grype-run.log"
  local env_file="$LOG_DIR/grype.env"

  { run_grype; } >> "$log" 2>&1

  printf 'GRYPE_STATUS=%s\n'   "$GRYPE_STATUS"   > "$env_file"
  printf 'GRYPE_CRITICAL=%s\n' "$GRYPE_CRITICAL" >> "$env_file"
  printf 'GRYPE_HIGH=%s\n'     "$GRYPE_HIGH"     >> "$env_file"
  printf 'GRYPE_MEDIUM=%s\n'   "$GRYPE_MEDIUM"   >> "$env_file"
  printf 'GRYPE_LOW=%s\n'              "$GRYPE_LOW"              >> "$env_file"
  printf 'GRYPE_PKG_COUNT=%s\n'       "$GRYPE_PKG_COUNT"       >> "$env_file"
  printf 'GRYPE_DB_AGE_DAYS=%s\n'     "$GRYPE_DB_AGE_DAYS"     >> "$env_file"
  printf 'DEP_MANIFESTS_PRESENT=%s\n' "$DEP_MANIFESTS_PRESENT" >> "$env_file"
}

wrapper_virustotal() {
  trap 'rm -rf "$VT_CFG_DIR" 2>/dev/null || true' EXIT
  local log="$LOG_DIR/vt-run.log"
  local env_file="$LOG_DIR/vt.env"

  { run_virustotal; } >> "$log" 2>&1

  printf 'VT_STATUS=%s\n'    "$VT_STATUS"    > "$env_file"
  printf 'VT_MALICIOUS=%s\n' "$VT_MALICIOUS" >> "$env_file"
  printf 'VT_TOTAL=%s\n'     "$VT_TOTAL"     >> "$env_file"
}

wrapper_hadolint() {
  local log="$LOG_DIR/hadolint-run.log"
  local env_file="$LOG_DIR/hadolint.env"

  { run_hadolint; } >> "$log" 2>&1

  printf 'HADOLINT_STATUS=%s\n'   "$HADOLINT_STATUS"   > "$env_file"
  printf 'HADOLINT_FILES=%s\n'    "$HADOLINT_FILES"    >> "$env_file"
  printf 'HADOLINT_ERRORS=%s\n'   "$HADOLINT_ERRORS"   >> "$env_file"
  printf 'HADOLINT_WARNINGS=%s\n' "$HADOLINT_WARNINGS" >> "$env_file"
  printf 'HADOLINT_TOTAL=%s\n'    "$HADOLINT_TOTAL"    >> "$env_file"
}

# Replay the last 5 status lines from each per-scanner run log in canonical order.
# Called after all wrappers have completed and .env files have been sourced.
replay_scanner_summaries() {
  local scanner log_name log
  for scanner in semgrep trivy grype virustotal hadolint; do
    # virustotal wrapper writes vt-run.log (not virustotal-run.log)
    if [[ "$scanner" == "virustotal" ]]; then
      log_name="vt"
    else
      log_name="$scanner"
    fi
    log="$LOG_DIR/${log_name}-run.log"
    [[ -f "$log" ]] || continue
    log_section "$(echo "$scanner" | awk '{print toupper(substr($0,1,1)) substr($0,2)}') — Summary"
    # *-run.log lines are ANSI-colored (echo -e "${BLUE}[INFO]${NC} ..."),
    # so [INFO] is never at line start; strip ANSI then match without ^ anchor.
    sed $'s/\033\\[[0-9;]*m//g' "$log" 2>/dev/null \
      | grep -aE '\[(INFO|WARN|FAIL| OK )\]' | tail -5 || true
  done
}

# Build and print the machine-readable JSON summary to stdout.
# Must be called AFTER generate_report (report.html must exist for report_path).
# Reads scanner globals restored from .env files after all waits complete.
build_json_summary() {
  local verdict
  verdict=$(overall_status)
  local report_path="$REPORT_DIR/report.html"
  [[ -f "$report_path" ]] || log_warn "report.html not found — report_path in JSON may point to a non-existent file"

  local sem_err_msg="" trivy_err_msg="" grype_err_msg="" vt_err_msg="" hadolint_err_msg=""
  [[ "$SEMGREP_STATUS"  == "error" ]] && sem_err_msg="Semgrep produced no usable output — see logs/semgrep.log"
  [[ "$TRIVY_STATUS"    == "error" ]] && trivy_err_msg="Trivy produced no output — see logs/trivy-run.log"
  [[ "$GRYPE_STATUS"    == "error" ]] && grype_err_msg="Grype produced no output — see logs/grype-run.log"
  [[ "$VT_STATUS"       == "error" ]] && vt_err_msg="VirusTotal scan failed — see logs/vt-run.log"
  [[ "$HADOLINT_STATUS" == "error" ]] && hadolint_err_msg="Hadolint scan failed — see logs/hadolint-run.log"

  jq -n \
    --arg  schema_version "1" \
    --arg  verdict        "$verdict" \
    --argjson risk_score   "$RISK_SCORE" \
    --arg  report_path    "$report_path" \
    --arg  sem_status     "$SEMGREP_STATUS" \
    --argjson sem_findings  "$SEMGREP_VISIBLE" \
    --argjson sem_errors    "$SEMGREP_ERRORS" \
    --arg  sem_err        "$sem_err_msg" \
    --arg  trivy_status   "$TRIVY_STATUS" \
    --argjson trivy_crit    "$TRIVY_CRITICAL" \
    --argjson trivy_high    "$TRIVY_HIGH" \
    --argjson trivy_med     "$TRIVY_MEDIUM" \
    --argjson trivy_sec     "$TRIVY_SECRETS" \
    --arg  trivy_err      "$trivy_err_msg" \
    --arg  grype_status   "$GRYPE_STATUS" \
    --argjson grype_crit    "$GRYPE_CRITICAL" \
    --argjson grype_high    "$GRYPE_HIGH" \
    --argjson grype_med     "$GRYPE_MEDIUM" \
    --arg  grype_err      "$grype_err_msg" \
    --arg  vt_status      "$VT_STATUS" \
    --argjson vt_malicious  "$VT_MALICIOUS" \
    --argjson vt_total      "$VT_TOTAL" \
    --arg  vt_err         "$vt_err_msg" \
    --arg  hadolint_status "$HADOLINT_STATUS" \
    --arg  hadolint_err   "$hadolint_err_msg" \
    --argjson hadolint_errors   "$HADOLINT_ERRORS" \
    --argjson hadolint_warnings "$HADOLINT_WARNINGS" \
    --argjson hadolint_total    "$HADOLINT_TOTAL" \
    --argjson hadolint_files    "$HADOLINT_FILES" \
    '{
      schema_version: $schema_version,
      verdict: $verdict,
      risk_score: $risk_score,
      report_path: $report_path,
      scanners: {
        semgrep: (if $sem_status == "skipped" then {status: $sem_status}
                  elif $sem_status == "error" then {status: $sem_status, error_message: $sem_err}
                  else {status: $sem_status, findings: $sem_findings, errors: $sem_errors}
                  end),
        trivy: (if $trivy_status == "skipped" then {status: $trivy_status}
                elif $trivy_status == "error" then {status: $trivy_status, error_message: $trivy_err}
                else {status: $trivy_status, critical: $trivy_crit, high: $trivy_high, medium: $trivy_med, secrets: $trivy_sec}
                end),
        grype: (if $grype_status == "skipped" then {status: $grype_status}
                elif $grype_status == "error" then {status: $grype_status, error_message: $grype_err}
                else {status: $grype_status, critical: $grype_crit, high: $grype_high, medium: $grype_med}
                end),
        virustotal: (if ($vt_status == "skipped" or $vt_status == "skipped_too_large") then {status: "skipped"}
                     elif $vt_status == "error" then {status: $vt_status, error_message: $vt_err}
                     else {status: $vt_status, malicious: $vt_malicious, total: $vt_total}
                     end),
        hadolint: (if ($hadolint_status == "skipped" or $hadolint_status == "skipped_no_docker")
                       then {status: "skipped"}
                   elif $hadolint_status == "error" then {status: $hadolint_status, error_message: $hadolint_err}
                   else {status: $hadolint_status, errors: $hadolint_errors,
                         warnings: $hadolint_warnings, total: ($hadolint_errors + $hadolint_warnings),
                         files_scanned: $hadolint_files}
                   end)
      }
    }'
}

build_report_json() {
  # Build the normalized v2.1 report data layer and write REPORT_DIR/report.json.
  # All values pass through jq --arg / --argjson (DATA-02).
  # Semgrep: one entry per rule, count = locations.length (DATA-04).
  # A scanner with no data emits {status:"skipped"} or {status:"error"} (DATA-01 robustness).

  local overall; overall=$(overall_status)
  local gh_repo; gh_repo=$(parse_github_url "$TARGET")
  local target_ref="${TARGET_REF:-HEAD}"
  local report_date; report_date=$(date "+%Y-%m-%d %H:%M %Z")

  # Lowercase overall for verdict.status (no ${var,,} — Bash 3.2)
  local verdict_status; verdict_status=$(echo "$overall" | tr '[:upper:]' '[:lower:]')

  # Build verdict summary string (reuse logic from generate_report lines 1932-1968)
  local verdict_summary=""
  case "$overall" in
    PASS) verdict_summary="$T_VERDICT_PASS" ;;
    WARN) verdict_summary="$T_VERDICT_WARN" ;;
    *)
      local _parts=""
      if [[ "$VT_STATUS" == "fail" ]]; then
        if [[ "$LANG_REPORT" == "ru" ]]; then
          _parts="VirusTotal: $VT_MALICIOUS из $VT_TOTAL движков пометили файл как вредоносный"
        else
          _parts="VirusTotal flagged $VT_MALICIOUS/$VT_TOTAL engines as malicious"
        fi
      fi
      if [[ "${MERGED_CRITICAL:-0}" -gt 0 ]]; then
        local _tri
        if [[ "$LANG_REPORT" == "ru" ]]; then
          _tri="CVE: $MERGED_CRITICAL критических (после дедупликации)"
        else
          _tri="CVE: $MERGED_CRITICAL critical (after dedup)"
        fi
        _parts="${_parts:+${_parts}; }${_tri}"
      fi
      if [[ "${TRIVY_SECRETS:-0}" -gt 0 ]]; then
        local _sec
        if [[ "$LANG_REPORT" == "ru" ]]; then
          _sec="$TRIVY_SECRETS секрет(ов) обнаружено в исходном коде"
        else
          _sec="$TRIVY_SECRETS secret(s) found in source code"
        fi
        _parts="${_parts:+${_parts}; }${_sec}"
      fi
      verdict_summary="${_parts:-$T_VERDICT_FAIL}"
      ;;
  esac

  # ── VT: extract fields from virustotal.txt via awk (SEC-03: gsub strips quotes from hashes)
  local vt_sha256="" vt_md5="" vt_sha1="" vt_filetype="" vt_name="" vt_filesize=""
  local vt_malicious=0 vt_suspicious=0 vt_undetected=0 vt_unsupported=0
  local f="$RAW_DIR/virustotal.txt"
  if [[ -s "$f" ]]; then
    vt_sha256=$(    awk '/^[[:space:]]+sha256:/{gsub(/"/, "", $2); print $2; exit}' "$f")
    vt_md5=$(       awk '/^[[:space:]]+md5:/{gsub(/"/, "", $2); print $2; exit}' "$f")
    vt_sha1=$(      awk '/^[[:space:]]+sha1:/{gsub(/"/, "", $2); print $2; exit}' "$f")
    vt_filetype=$(  awk '/^[[:space:]]+type_description:/{$1=""; sub(/^[[:space:]]+/,""); gsub(/"/, "", $0); print; exit}' "$f")
    vt_name=$(      awk '/^[[:space:]]+meaningful_name:/{$1=""; sub(/^[[:space:]]+/,""); gsub(/"/, "", $0); print; exit}' "$f")
    vt_malicious=$( awk '/^[[:space:]]+malicious:/{print $2+0; exit}' "$f")
    vt_suspicious=$(awk '/^[[:space:]]+suspicious:/{print $2+0; exit}' "$f")
    vt_undetected=$(awk '/^[[:space:]]+undetected:/{print $2+0; exit}' "$f")
    vt_unsupported=$(awk '/^[[:space:]]+type-unsupported:/{print $2+0; exit}' "$f")
    local vt_size_raw
    vt_size_raw=$(  awk '/^[[:space:]]+size:/{print $2+0; exit}' "$f")
    # Format size into human-readable string
    local size_fmt="—"
    if [[ -n "$vt_size_raw" && "$vt_size_raw" -gt 0 ]] 2>/dev/null; then
      if   [[ "$vt_size_raw" -gt 1073741824 ]]; then size_fmt="$(( vt_size_raw/1024/1024/1024 )) GB"
      elif [[ "$vt_size_raw" -gt 1048576    ]]; then size_fmt="$(( vt_size_raw/1024/1024 )) MB"
      else                                           size_fmt="$(( vt_size_raw/1024 )) KB"
      fi
    fi
    vt_filesize="$size_fmt"
  fi

  # ── Semgrep: group_by(check_id) — one entry per rule, count = length (DATA-04)
  local semgrep_findings="[]"
  if [[ "$SEMGREP_STATUS" != "skipped" && -s "$RAW_DIR/semgrep.json" ]]; then
    semgrep_findings=$(jq -c --arg min_sev "$SEMGREP_MIN_SEV" '
      def sev_norm: ascii_downcase |
        if . == "error" then "high" elif . == "warning" then "medium" else . end;
      def sev_rank: if . == "high" then 2 elif . == "medium" then 1 else 0 end;
      [ .results[]
        | select(.check_id != null)
        | select(.check_id | test("audit|test|benchmark|example|sample"; "i") | not)
        | select((.extra.severity // "INFO") |
            if   $min_sev == "high"   then . == "ERROR"
            elif $min_sev == "medium" then (. == "ERROR" or . == "WARNING")
            else true end)
      ]
      | group_by(.check_id)
      | map({
          rule:      (.[0].check_id | split(".") | .[-1]),
          check_id:  (.[0].check_id),
          severity:  ((.[0].extra.severity // "INFO") | sev_norm),
          message:   (.[0].extra.message // ""),
          locations: (map({path: .path, line: .start.line})),
          count:     (length)
        })
      | sort_by([(.severity | sev_rank | -.), (.count | -.)])
    ' "$RAW_DIR/semgrep.json" 2>/dev/null || echo "[]")
  fi

  # ── Dependencies: vulns_merged.json → normalized vulns array
  local deps_vulns="[]"
  if [[ "$TRIVY_STATUS" != "skipped" && -s "$RAW_DIR/vulns_merged.json" ]]; then
    deps_vulns=$(jq -c '
      [ .[] | {
          id:       .id,
          pkg:      .pkg,
          version:  .version,
          fixed:    (if .fix == "" then null else .fix end),
          severity: (.severity | ascii_downcase),
          title:    .title,
          source:   (if .found_by == "both" then "Trivy + Grype"
                     elif .found_by == "trivy" then "Trivy"
                     else "Grype" end),
          cvss:     .cvss
        }
      ]
    ' "$RAW_DIR/vulns_merged.json" 2>/dev/null || echo "[]")
  fi

  # ── Dependencies: trivy_fs.json → secrets array (rule/category/severity/title/file/line only — no raw match)
  local deps_secrets="[]"
  if [[ "$TRIVY_STATUS" != "skipped" && -s "$RAW_DIR/trivy_fs.json" ]]; then
    deps_secrets=$(jq -c '
      [ .Results[]? | select(.Class=="secret") | .Target as $f | .Secrets[]? |
        {rule: .RuleID, category: .Category, severity: (.Severity|ascii_downcase), title: .Title, file: $f, line: .StartLine}
      ]
    ' "$RAW_DIR/trivy_fs.json" 2>/dev/null || echo "[]")
  fi

  # ── Hadolint: map {code→rule, message→msg, level, line}
  local hadolint_findings="[]"
  if [[ "$HADOLINT_STATUS" != "skipped" && "$HADOLINT_STATUS" != "skipped_no_docker" \
        && -s "$RAW_DIR/hadolint.json" ]]; then
    hadolint_findings=$(jq -c '
      [ .[] | {level: .level, rule: .code, line: .line, msg: .message, file: (.file | ltrimstr("/src/"))} ]
    ' "$RAW_DIR/hadolint.json" 2>/dev/null || echo "[]")
  fi

  # ── GRYPE-04: dep_warning trigger (D-05/D-06/D-03) ──────────────────────────────
  # WR-02: these counts are restored verbatim from grype.env/trivy.env (sourced) and
  # derived from jq, which can exit 0 while emitting an empty/non-integer token. Under
  # set -euo pipefail a non-integer in [[ ... -eq ]] aborts the run, so clamp to 0
  # (a safe default that simply does not fire the trigger) before comparing.
  [[ "$TRIVY_PKG_COUNT" =~ ^-?[0-9]+$ ]] || TRIVY_PKG_COUNT=0
  [[ "$GRYPE_PKG_COUNT" =~ ^-?[0-9]+$ ]] || GRYPE_PKG_COUNT=0
  local dep_warning=""
  if [[ "$DEP_MANIFESTS_PRESENT" == "true" ]] \
     && [[ "$TRIVY_PKG_COUNT" -eq 0 ]] \
     && [[ "$GRYPE_PKG_COUNT" -eq 0 ]] \
     && [[ "$TRIVY_STATUS" == "pass" ]]; then
    dep_warning="manifests-present-zero-packages"
  fi

  # ── Final jq -n: assemble and write report.json (all values via --arg/--argjson — DATA-02)
  jq -n \
    --arg  schema_version  "1" \
    --arg  target_name     "$gh_repo" \
    --arg  target_ref      "$target_ref" \
    --arg  target_date     "$report_date" \
    --arg  target_url      "https://github.com/$gh_repo" \
    --arg  verdict_status  "$verdict_status" \
    --argjson verdict_score   "${RISK_SCORE:-0}" \
    --arg  verdict_summary "$verdict_summary" \
    --arg  vt_status       "$VT_STATUS" \
    --arg  vt_sha256       "${vt_sha256:-}" \
    --arg  vt_md5          "${vt_md5:-}" \
    --arg  vt_sha1         "${vt_sha1:-}" \
    --arg  vt_filetype     "${vt_filetype:-}" \
    --arg  vt_filesize     "${vt_filesize:-}" \
    --arg  vt_name         "${vt_name:-}" \
    --argjson vt_malicious    "${vt_malicious:-0}" \
    --argjson vt_suspicious   "${vt_suspicious:-0}" \
    --argjson vt_undetected   "${vt_undetected:-0}" \
    --argjson vt_unsupported  "${vt_unsupported:-0}" \
    --argjson vt_engines      "${VT_TOTAL:-0}" \
    --arg  sem_status      "$SEMGREP_STATUS" \
    --argjson sem_findings    "$semgrep_findings" \
    --arg  dep_status      "$TRIVY_STATUS" \
    --argjson dep_vulns       "$deps_vulns" \
    --argjson dep_secrets      "$deps_secrets" \
    --argjson dep_src_trivy  "${TOTAL_TRIVY:-0}" \
    --argjson dep_src_grype  "${TOTAL_GRYPE:-0}" \
    --argjson dep_src_merged "${TOTAL_MERGED:-0}" \
    --arg  dep_warning       "$dep_warning" \
    --arg  hado_status     "$HADOLINT_STATUS" \
    --argjson hado_findings   "$hadolint_findings" \
    '{
      schema_version: $schema_version,
      target: {name: $target_name, ref: $target_ref, date: $target_date, url: $target_url},
      verdict: {status: $verdict_status, score: $verdict_score, summary: $verdict_summary},
      scanners: {
        virustotal: (if ($vt_status == "skipped" or $vt_status == "skipped_too_large")
                     then {status: "skipped"}
                     elif $vt_status == "error" then {status: "error"}
                     else {status: $vt_status, sha256: $vt_sha256, md5: $vt_md5,
                           sha1: $vt_sha1, filetype: $vt_filetype, filesize: $vt_filesize,
                           name: $vt_name, malicious: $vt_malicious, suspicious: $vt_suspicious,
                           undetected: $vt_undetected, unsupported: $vt_unsupported,
                           engines: $vt_engines}
                     end),
        semgrep: (if $sem_status == "skipped" then {status: "skipped"}
                  elif $sem_status == "error" then {status: "error"}
                  else {status: $sem_status, findings: $sem_findings}
                  end),
        dependencies: (if $dep_status == "skipped" then {status: "skipped"}
                       elif $dep_status == "error" then {status: "error"}
                       else {status: $dep_status, vulns: $dep_vulns, secrets: $dep_secrets,
                             sources: {trivy: $dep_src_trivy, grype: $dep_src_grype, merged: $dep_src_merged}}
                             + (if $dep_warning != "" then {warning: $dep_warning} else {} end)
                       end),
        hadolint: (if ($hado_status == "skipped" or $hado_status == "skipped_no_docker")
                   then {status: "skipped"}
                   elif $hado_status == "error" then {status: "error"}
                   else {status: $hado_status, findings: $hado_findings}
                   end)
      }
    }' > "$REPORT_DIR/report.json" || {
      # Robustness fallback: ensure report.json is always valid JSON (RESEARCH Pitfall 5)
      printf '{"schema_version":"1","error":"report.json build failed"}\n' \
        > "$REPORT_DIR/report.json"
    }
}

# ── Translations ──────────────────────────────────────────────────────────────
setup_lang() {
  if [[ "$LANG_REPORT" == "ru" ]]; then
    T_REPORT_TITLE="Отчёт о безопасности"
    T_LABEL_TARGET="Репозиторий"
    T_LABEL_REF="Версия"
    T_LABEL_DATE="Дата"
    T_LABEL_COMMIT="Коммит"
    T_DISTRIB_LABEL="Распределение по критичности"
    T_DISTRIB_FINDINGS="находок"
    T_SECTION_SEMGREP_META="статический анализ кода"
    T_SECTION_DEPS_META="Trivy + Grype"
    T_SECTION_HADOLINT_META="Dockerfile · 1 файл"
    T_SECTION_VT_META="vt-cli · файл архива"
    T_CARD_SEMGREP_SUB="правил"
    T_CARD_DEPS_SUB_HIGH="высоких"
    T_CARD_HADOLINT_SUB="предупреждений"
    T_CARD_VT_SUB="движков"
    T_CARD_SKIPPED="пропущено"
    T_CARD_ERROR="ошибка"
    T_VERDICT_UNKNOWN="НЕИЗВЕСТНО"
    T_SECTION_PLACEHOLDER="Полный рендер в фазах 10–11."
    T_THEME_TOGGLE_TITLE="Переключить тему"
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
    T_TRIVY_MODULE_TITLE="Trivy + Grype — Зависимости и секреты"
    T_VT_SKIPPED="Пропущено — укажите <code>VT_API_KEY</code> в <code>.env</code> или через <code>--vt-key</code>"
    T_VT_TOO_LARGE="Пропущено — архив &gt; 650 МБ"
    T_VT_ERROR="Ошибка — проверьте API-ключ или пересоберите образ vt-cli"
    T_VT_TH_CATEGORY="Категория"
    T_VT_TH_COUNT="Кол-во"
    T_VT_RAW="Сырой вывод vt-cli"
    T_SEMGREP_CLEAN="✓ Проблем не найдено"
    T_LOAD_ERROR_PREFIX="Ошибка загрузки данных сканирования: "
    T_SEMGREP_ERROR="Semgrep недоступен — semgrep.dev не отвечает (таймаут). Проверьте интернет-соединение и повторите сканирование."
    T_SEMGREP_FINDINGS_LABEL="находок"
    T_SEMGREP_TH_SEV="Серьёзность"
    T_SEMGREP_TH_RULE="Правило"
    T_SEMGREP_TH_LOC="Расположение"
    T_SEMGREP_TH_MSG="Описание"
    T_SEMGREP_HIDDEN_NOTICE="Скрыто %HIDDEN_COUNT% низкоприоритетных находок (INFO/LOW). Сырой файл: semgrep.json"
    T_SEMGREP_AUDIT_LABEL="Аудит-заметки"
    T_SEMGREP_UNIQUE_RULES_LABEL="уникальных правил"
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
    T_TRIVY_TH_SRC="Источник"
    T_TRIVY_DEDUP_STATS="Trivy: %TRIVY_COUNT%, Grype: %GRYPE_COUNT%, после дедупликации: %MERGED_COUNT%"
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
    T_DIFF_TITLE="Изменения"
    T_DIFF_NEW="Новые"
    T_DIFF_CLOSED="Устранённые"
    T_DIFF_PERSISTENT="Постоянные"
    T_SUPPRESSED_TITLE="Подавленные находки"
    T_SUPPRESSED_REASON="Причина"
    T_FOOTER_GENERATED="Сформировано"
    T_SEM_SEARCH_PLACEHOLDER="Поиск по правилу, файлу, описанию…"
    T_SEM_CHIP_ALL="Все"
    T_SEM_CHIP_HIGH="High"
    T_SEM_CHIP_MEDIUM="Medium"
    T_SEM_CHIP_LOW="Low"
    T_SEM_NO_FINDINGS="Находок нет"
    T_SEM_NO_FINDINGS_ICON="✓"
    T_SEM_FILTER_EMPTY="Ничего не найдено по фильтру"
    T_SEM_SKIPPED="Semgrep не выполнен"
    T_SEM_SKIPPED_ICON="⚠"
    T_SEM_SHOW_MORE="+ показать ещё {N}"
    T_SEM_DOCS_LINK="↗ Semgrep docs · "
    T_SEM_ARTIFACT_JSON="⤓ semgrep.json"
    T_SEM_ARTIFACT_LOG="⤓ semgrep.log"
    T_PLACE_ONE="место"
    T_PLACE_FEW="места"
    T_PLACE_MANY="мест"
    T_DEP_SEARCH_PLACEHOLDER="Поиск CVE, пакет, описание…"
    T_DEP_CHIP_ALL="Все"
    T_DEP_CHIP_CRITICAL="Critical"
    T_DEP_CHIP_HIGH="High"
    T_DEP_CHIP_MEDIUM="Medium"
    T_DEP_CHIP_LOW="Low"
    T_DEP_NO_VULNS="Критичных проблем не найдено"
    T_DEP_NO_VULNS_ICON="✓"
    T_DEP_NO_CVE="CVE не найдено"
    T_DEP_SECRETS_TITLE="Обнаружены секреты"
    T_DEP_SECRETS_TYPE="Тип"
    T_DEP_SECRETS_RULE="Правило"
    T_DEP_SECRETS_LOC="Расположение"
    T_DEP_FILTER_EMPTY="Ничего не найдено"
    T_DEP_SKIPPED="Проверка зависимостей пропущена"
    T_DEP_SKIPPED_ICON="⚠"
    T_DEP_SHOW_MORE="+ показать ещё {N}"
    T_DEP_TH_SEV="Критичность"
    T_DEP_TH_CVE="CVE / ID"
    T_DEP_TH_PKG="Пакет"
    T_DEP_TH_VER="Версия"
    T_DEP_TH_FIXED="Исправлено в"
    T_DEP_TH_CVSS="CVSS"
    T_DEP_TH_SRC="Источник"
    T_DEP_SOURCES_SUMMARY="Trivy {TRIVY} · Grype {GRYPE} · {BOTH} общих · {UNIQUE} уникальных"
    T_DEP_SOURCES_SUMMARY_CACHED="{MERGED} уникальных"
    T_DEP_ARTIFACT_MERGED="⤓ vulns_merged.json"
    T_DEP_ARTIFACT_TRIVY="⤓ trivy_fs.json"
    T_DEP_ARTIFACT_GRYPE="⤓ grype.json"
    T_BADGE_INCONCLUSIVE="НЕ ОПРЕДЕЛЕНО"
    T_DEP_WARN_HEAD="Манифесты найдены — пакеты не определены"
    T_DEP_WARN_BODY="Файлы зависимостей найдены, но ни один сканер не определил пакеты — вероятно, отсутствует lockfile. Результаты не определены и не могут считаться успешным прохождением проверки."
    T_HADO_SEARCH_PLACEHOLDER="Поиск правила, описания…"
    T_HADO_CHIP_ALL="Все"
    T_HADO_CHIP_ERROR="Error"
    T_HADO_CHIP_WARNING="Warning"
    T_HADO_CHIP_INFO="Info"
    T_HADO_NO_FINDINGS="Нет замечаний"
    T_HADO_NO_FINDINGS_ICON="✓"
    T_HADO_FILTER_EMPTY="Ничего не найдено"
    T_HADO_SKIPPED="Dockerfile не найден"
    T_HADO_SKIPPED_ICON="⚠"
    T_HADO_TH_LEVEL="Уровень"
    T_HADO_TH_RULE="Правило"
    T_HADO_TH_LOC="Файл:строка"
    T_HADO_TH_MSG="Описание"
    T_HADO_META_ERRORS="{N} ошибок"
    T_HADO_META_WARNINGS="{N} предупреждений"
    T_HADO_META_INFO="{N} инфо"
    T_HADO_ARTIFACT="⤓ hadolint.json"
    T_VT_GRID_SHA256="SHA-256"
    T_VT_GRID_MD5="MD5"
    T_VT_GRID_SHA1="SHA-1"
    T_VT_GRID_TYPE="Тип"
    T_VT_GRID_SIZE="Размер"
    T_VT_GRID_NAME="Имя"
    T_VT_CLEAN="Ни один из {N} движков не отметил файл как вредоносный"
    T_VT_SKIPPED="VirusTotal пропущен"
    T_VT_SKIPPED_ICON="⚠"
    T_VT_STAT_MALICIOUS="вредоносных"
    T_VT_STAT_SUSPICIOUS="подозрительных"
    T_VT_STAT_UNDETECTED="не определили"
    T_VT_STAT_UNSUPPORTED="не поддерживают"
    T_VT_ARTIFACT="⤓ virustotal.txt"
  else
    T_REPORT_TITLE="Security Scan Report"
    T_LABEL_TARGET="Target"
    T_LABEL_REF="Ref"
    T_LABEL_DATE="Date"
    T_LABEL_COMMIT="Commit"
    T_DISTRIB_LABEL="Severity distribution"
    T_DISTRIB_FINDINGS="findings"
    T_SECTION_SEMGREP_META="static analysis"
    T_SECTION_DEPS_META="Trivy + Grype"
    T_SECTION_HADOLINT_META="Dockerfile"
    T_SECTION_VT_META="vt-cli · archive"
    T_CARD_SEMGREP_SUB="rules"
    T_CARD_DEPS_SUB_HIGH="high"
    T_CARD_HADOLINT_SUB="warnings"
    T_CARD_VT_SUB="engines"
    T_CARD_SKIPPED="skipped"
    T_CARD_ERROR="error"
    T_VERDICT_UNKNOWN="UNKNOWN"
    T_SECTION_PLACEHOLDER="Full rendering in Phase 10–11."
    T_THEME_TOGGLE_TITLE="Toggle theme"
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
    T_TRIVY_MODULE_TITLE="Trivy + Grype — Dependencies &amp; Secrets"
    T_VT_SKIPPED="Skipped — set <code>VT_API_KEY</code> in <code>.env</code> or use <code>--vt-key</code>"
    T_VT_TOO_LARGE="Skipped — archive &gt; 650 MB"
    T_VT_ERROR="Error — check API key or rebuild vt-cli image"
    T_VT_TH_CATEGORY="Category"
    T_VT_TH_COUNT="Count"
    T_VT_RAW="Raw vt-cli output"
    T_SEMGREP_CLEAN="✓ No findings"
    T_LOAD_ERROR_PREFIX="Error loading scan data: "
    T_SEMGREP_ERROR="Semgrep unavailable — semgrep.dev unreachable (network timeout). Check your internet connection and retry."
    T_SEMGREP_FINDINGS_LABEL="finding(s)"
    T_SEMGREP_TH_SEV="Severity"
    T_SEMGREP_TH_RULE="Rule"
    T_SEMGREP_TH_LOC="Location"
    T_SEMGREP_TH_MSG="Message"
    T_SEMGREP_HIDDEN_NOTICE="%HIDDEN_COUNT% low-priority finding(s) hidden (INFO/LOW). Raw file: semgrep.json"
    T_SEMGREP_AUDIT_LABEL="Audit Notes"
    T_SEMGREP_UNIQUE_RULES_LABEL="unique rule type(s)"
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
    T_TRIVY_TH_SRC="Source"
    T_TRIVY_DEDUP_STATS="Trivy: %TRIVY_COUNT%, Grype: %GRYPE_COUNT%, after dedup: %MERGED_COUNT%"
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
    T_DIFF_TITLE="Changes"
    T_DIFF_NEW="New"
    T_DIFF_CLOSED="Resolved"
    T_DIFF_PERSISTENT="Persistent"
    T_SUPPRESSED_TITLE="Suppressed Findings"
    T_SUPPRESSED_REASON="Suppressed By"
    T_FOOTER_GENERATED="Generated"
    T_SEM_SEARCH_PLACEHOLDER="Search rule, file, message…"
    T_SEM_CHIP_ALL="All"
    T_SEM_CHIP_HIGH="High"
    T_SEM_CHIP_MEDIUM="Medium"
    T_SEM_CHIP_LOW="Low"
    T_SEM_NO_FINDINGS="No findings"
    T_SEM_NO_FINDINGS_ICON="✓"
    T_SEM_FILTER_EMPTY="No matches for filter"
    T_SEM_SKIPPED="Semgrep did not run"
    T_SEM_SKIPPED_ICON="⚠"
    T_SEM_SHOW_MORE="+ show {N} more"
    T_SEM_DOCS_LINK="↗ Semgrep docs · "
    T_SEM_ARTIFACT_JSON="⤓ semgrep.json"
    T_SEM_ARTIFACT_LOG="⤓ semgrep.log"
    T_PLACE_ONE="place"
    T_PLACE_FEW="places"
    T_PLACE_MANY="places"
    T_DEP_SEARCH_PLACEHOLDER="Search CVE, package, title…"
    T_DEP_CHIP_ALL="All"
    T_DEP_CHIP_CRITICAL="Critical"
    T_DEP_CHIP_HIGH="High"
    T_DEP_CHIP_MEDIUM="Medium"
    T_DEP_CHIP_LOW="Low"
    T_DEP_NO_VULNS="No critical issues"
    T_DEP_NO_VULNS_ICON="✓"
    T_DEP_NO_CVE="No CVEs found"
    T_DEP_SECRETS_TITLE="Secrets detected"
    T_DEP_SECRETS_TYPE="Type"
    T_DEP_SECRETS_RULE="Rule"
    T_DEP_SECRETS_LOC="Location"
    T_DEP_FILTER_EMPTY="No matches"
    T_DEP_SKIPPED="Dependency scan skipped"
    T_DEP_SKIPPED_ICON="⚠"
    T_DEP_SHOW_MORE="+ show {N} more"
    T_DEP_TH_SEV="Severity"
    T_DEP_TH_CVE="CVE / ID"
    T_DEP_TH_PKG="Package"
    T_DEP_TH_VER="Version"
    T_DEP_TH_FIXED="Fixed in"
    T_DEP_TH_CVSS="CVSS"
    T_DEP_TH_SRC="Source"
    T_DEP_SOURCES_SUMMARY="Trivy {TRIVY} · Grype {GRYPE} · {BOTH} found by both · {UNIQUE} unique"
    T_DEP_SOURCES_SUMMARY_CACHED="{MERGED} unique"
    T_DEP_ARTIFACT_MERGED="⤓ vulns_merged.json"
    T_DEP_ARTIFACT_TRIVY="⤓ trivy_fs.json"
    T_DEP_ARTIFACT_GRYPE="⤓ grype.json"
    T_BADGE_INCONCLUSIVE="INCONCLUSIVE"
    T_DEP_WARN_HEAD="Manifests found — 0 packages cataloged"
    T_DEP_WARN_BODY="Dependency manifests are present but neither scanner cataloged any packages — likely a missing lockfile. Results are inconclusive and must not be read as a clean pass."
    T_HADO_SEARCH_PLACEHOLDER="Search rule, message…"
    T_HADO_CHIP_ALL="All"
    T_HADO_CHIP_ERROR="Error"
    T_HADO_CHIP_WARNING="Warning"
    T_HADO_CHIP_INFO="Info"
    T_HADO_NO_FINDINGS="No issues"
    T_HADO_NO_FINDINGS_ICON="✓"
    T_HADO_FILTER_EMPTY="No matches"
    T_HADO_SKIPPED="No Dockerfile found"
    T_HADO_SKIPPED_ICON="⚠"
    T_HADO_TH_LEVEL="Level"
    T_HADO_TH_RULE="Rule"
    T_HADO_TH_LOC="Location"
    T_HADO_TH_MSG="Message"
    T_HADO_META_ERRORS="{N} errors"
    T_HADO_META_WARNINGS="{N} warnings"
    T_HADO_META_INFO="{N} info"
    T_HADO_ARTIFACT="⤓ hadolint.json"
    T_VT_GRID_SHA256="SHA-256"
    T_VT_GRID_MD5="MD5"
    T_VT_GRID_SHA1="SHA-1"
    T_VT_GRID_TYPE="Type"
    T_VT_GRID_SIZE="Size"
    T_VT_GRID_NAME="Name"
    T_VT_CLEAN="0 malicious — {N} engines checked"
    T_VT_SKIPPED="VirusTotal skipped"
    T_VT_SKIPPED_ICON="⚠"
    T_VT_STAT_MALICIOUS="malicious"
    T_VT_STAT_SUSPICIOUS="suspicious"
    T_VT_STAT_UNDETECTED="undetected"
    T_VT_STAT_UNSUPPORTED="unsupported"
    T_VT_ARTIFACT="⤓ virustotal.txt"
  fi
}

build_lang_dict() {
  # Serialize the currently-active language's labels into a compact JSON object.
  # CRITICAL call-order invariant: setup_lang() must be called first to populate T_* vars.
  # Callers capture via command substitution: lang_dict=$(build_lang_dict)
  # Phase 8 minimal set — Phase 12 (I18N-01) extends this to the full T_* set.
  # All values pass through --arg only (all strings); no T_* interpolation into jq filter (DATA-02).
  jq -n \
    --arg report_title "$T_REPORT_TITLE" \
    --arg label_target "$T_LABEL_TARGET" \
    --arg label_ref    "$T_LABEL_REF" \
    --arg label_date   "$T_LABEL_DATE" \
    --arg verdict_pass "$T_VERDICT_PASS" \
    --arg verdict_warn "$T_VERDICT_WARN" \
    --arg verdict_fail "$T_VERDICT_FAIL" \
    --arg label_commit           "$T_LABEL_COMMIT" \
    --arg distrib_label          "$T_DISTRIB_LABEL" \
    --arg distrib_findings       "$T_DISTRIB_FINDINGS" \
    --arg section_semgrep_meta   "$T_SECTION_SEMGREP_META" \
    --arg section_deps_meta      "$T_SECTION_DEPS_META" \
    --arg section_hadolint_meta  "$T_SECTION_HADOLINT_META" \
    --arg section_vt_meta        "$T_SECTION_VT_META" \
    --arg card_semgrep_sub       "$T_CARD_SEMGREP_SUB" \
    --arg card_deps_sub_high     "$T_CARD_DEPS_SUB_HIGH" \
    --arg card_hadolint_sub      "$T_CARD_HADOLINT_SUB" \
    --arg card_vt_sub            "$T_CARD_VT_SUB" \
    --arg card_skipped           "$T_CARD_SKIPPED" \
    --arg card_error             "$T_CARD_ERROR" \
    --arg verdict_unknown        "$T_VERDICT_UNKNOWN" \
    --arg section_placeholder    "$T_SECTION_PLACEHOLDER" \
    --arg theme_toggle_title     "$T_THEME_TOGGLE_TITLE" \
    --arg sem_search_placeholder "$T_SEM_SEARCH_PLACEHOLDER" \
    --arg sem_chip_all            "$T_SEM_CHIP_ALL" \
    --arg sem_chip_high           "$T_SEM_CHIP_HIGH" \
    --arg sem_chip_medium         "$T_SEM_CHIP_MEDIUM" \
    --arg sem_chip_low            "$T_SEM_CHIP_LOW" \
    --arg sem_no_findings         "$T_SEM_NO_FINDINGS" \
    --arg sem_no_findings_icon    "$T_SEM_NO_FINDINGS_ICON" \
    --arg sem_filter_empty        "$T_SEM_FILTER_EMPTY" \
    --arg sem_skipped             "$T_SEM_SKIPPED" \
    --arg sem_skipped_icon        "$T_SEM_SKIPPED_ICON" \
    --arg sem_show_more           "$T_SEM_SHOW_MORE" \
    --arg sem_docs_link           "$T_SEM_DOCS_LINK" \
    --arg sem_artifact_json       "$T_SEM_ARTIFACT_JSON" \
    --arg sem_artifact_log        "$T_SEM_ARTIFACT_LOG" \
    --arg place_one               "$T_PLACE_ONE" \
    --arg place_few               "$T_PLACE_FEW" \
    --arg place_many              "$T_PLACE_MANY" \
    --arg dep_search_placeholder  "$T_DEP_SEARCH_PLACEHOLDER" \
    --arg dep_chip_all            "$T_DEP_CHIP_ALL" \
    --arg dep_chip_critical       "$T_DEP_CHIP_CRITICAL" \
    --arg dep_chip_high           "$T_DEP_CHIP_HIGH" \
    --arg dep_chip_medium         "$T_DEP_CHIP_MEDIUM" \
    --arg dep_chip_low            "$T_DEP_CHIP_LOW" \
    --arg dep_no_vulns            "$T_DEP_NO_VULNS" \
    --arg dep_no_vulns_icon       "$T_DEP_NO_VULNS_ICON" \
    --arg dep_filter_empty        "$T_DEP_FILTER_EMPTY" \
    --arg dep_skipped             "$T_DEP_SKIPPED" \
    --arg dep_skipped_icon        "$T_DEP_SKIPPED_ICON" \
    --arg dep_show_more           "$T_DEP_SHOW_MORE" \
    --arg dep_th_sev              "$T_DEP_TH_SEV" \
    --arg dep_th_cve              "$T_DEP_TH_CVE" \
    --arg dep_th_pkg              "$T_DEP_TH_PKG" \
    --arg dep_th_ver              "$T_DEP_TH_VER" \
    --arg dep_th_fixed            "$T_DEP_TH_FIXED" \
    --arg dep_th_cvss             "$T_DEP_TH_CVSS" \
    --arg dep_th_src              "$T_DEP_TH_SRC" \
    --arg dep_sources_summary     "$T_DEP_SOURCES_SUMMARY" \
    --arg dep_sources_summary_cached "$T_DEP_SOURCES_SUMMARY_CACHED" \
    --arg dep_artifact_merged     "$T_DEP_ARTIFACT_MERGED" \
    --arg dep_artifact_trivy      "$T_DEP_ARTIFACT_TRIVY" \
    --arg dep_artifact_grype      "$T_DEP_ARTIFACT_GRYPE" \
    --arg badge_inconclusive      "$T_BADGE_INCONCLUSIVE" \
    --arg dep_warn_head           "$T_DEP_WARN_HEAD" \
    --arg dep_warn_body           "$T_DEP_WARN_BODY" \
    --arg dep_no_cve              "$T_DEP_NO_CVE" \
    --arg dep_secrets_title       "$T_DEP_SECRETS_TITLE" \
    --arg dep_secrets_type        "$T_DEP_SECRETS_TYPE" \
    --arg dep_secrets_rule        "$T_DEP_SECRETS_RULE" \
    --arg dep_secrets_loc         "$T_DEP_SECRETS_LOC" \
    --arg hado_search_placeholder "$T_HADO_SEARCH_PLACEHOLDER" \
    --arg hado_chip_all           "$T_HADO_CHIP_ALL" \
    --arg hado_chip_error         "$T_HADO_CHIP_ERROR" \
    --arg hado_chip_warning       "$T_HADO_CHIP_WARNING" \
    --arg hado_chip_info          "$T_HADO_CHIP_INFO" \
    --arg hado_no_findings        "$T_HADO_NO_FINDINGS" \
    --arg hado_no_findings_icon   "$T_HADO_NO_FINDINGS_ICON" \
    --arg hado_filter_empty       "$T_HADO_FILTER_EMPTY" \
    --arg hado_skipped            "$T_HADO_SKIPPED" \
    --arg hado_skipped_icon       "$T_HADO_SKIPPED_ICON" \
    --arg hado_th_level           "$T_HADO_TH_LEVEL" \
    --arg hado_th_rule            "$T_HADO_TH_RULE" \
    --arg hado_th_loc             "$T_HADO_TH_LOC" \
    --arg hado_th_msg             "$T_HADO_TH_MSG" \
    --arg hado_meta_errors        "$T_HADO_META_ERRORS" \
    --arg hado_meta_warnings      "$T_HADO_META_WARNINGS" \
    --arg hado_meta_info          "$T_HADO_META_INFO" \
    --arg hado_artifact           "$T_HADO_ARTIFACT" \
    --arg vt_grid_sha256          "$T_VT_GRID_SHA256" \
    --arg vt_grid_md5             "$T_VT_GRID_MD5" \
    --arg vt_grid_sha1            "$T_VT_GRID_SHA1" \
    --arg vt_grid_type            "$T_VT_GRID_TYPE" \
    --arg vt_grid_size            "$T_VT_GRID_SIZE" \
    --arg vt_grid_name            "$T_VT_GRID_NAME" \
    --arg vt_clean                "$T_VT_CLEAN" \
    --arg vt_skipped              "$T_VT_SKIPPED" \
    --arg vt_skipped_icon         "$T_VT_SKIPPED_ICON" \
    --arg vt_stat_malicious       "$T_VT_STAT_MALICIOUS" \
    --arg vt_stat_suspicious      "$T_VT_STAT_SUSPICIOUS" \
    --arg vt_stat_undetected      "$T_VT_STAT_UNDETECTED" \
    --arg vt_stat_unsupported     "$T_VT_STAT_UNSUPPORTED" \
    --arg vt_artifact             "$T_VT_ARTIFACT" \
    --arg load_error_prefix       "$T_LOAD_ERROR_PREFIX" \
    --arg footer_generated        "$T_FOOTER_GENERATED" \
    '{
      report_title: $report_title,
      label_target: $label_target,
      label_ref:    $label_ref,
      label_date:   $label_date,
      verdict_pass: $verdict_pass,
      verdict_warn: $verdict_warn,
      verdict_fail: $verdict_fail,
      label_commit:          $label_commit,
      distrib_label:         $distrib_label,
      distrib_findings:      $distrib_findings,
      section_semgrep_meta:  $section_semgrep_meta,
      section_deps_meta:     $section_deps_meta,
      section_hadolint_meta: $section_hadolint_meta,
      section_vt_meta:       $section_vt_meta,
      card_semgrep_sub:      $card_semgrep_sub,
      card_deps_sub_high:    $card_deps_sub_high,
      card_hadolint_sub:     $card_hadolint_sub,
      card_vt_sub:           $card_vt_sub,
      card_skipped:          $card_skipped,
      card_error:            $card_error,
      verdict_unknown:       $verdict_unknown,
      section_placeholder:   $section_placeholder,
      theme_toggle_title:    $theme_toggle_title,
      sem_search_placeholder: $sem_search_placeholder,
      sem_chip_all:           $sem_chip_all,
      sem_chip_high:          $sem_chip_high,
      sem_chip_medium:        $sem_chip_medium,
      sem_chip_low:           $sem_chip_low,
      sem_no_findings:        $sem_no_findings,
      sem_no_findings_icon:   $sem_no_findings_icon,
      sem_filter_empty:       $sem_filter_empty,
      sem_skipped:            $sem_skipped,
      sem_skipped_icon:       $sem_skipped_icon,
      sem_show_more:          $sem_show_more,
      sem_docs_link:          $sem_docs_link,
      sem_artifact_json:      $sem_artifact_json,
      sem_artifact_log:       $sem_artifact_log,
      place_one:              $place_one,
      place_few:              $place_few,
      place_many:             $place_many,
      dep_search_placeholder:  $dep_search_placeholder,
      dep_chip_all:            $dep_chip_all,
      dep_chip_critical:       $dep_chip_critical,
      dep_chip_high:           $dep_chip_high,
      dep_chip_medium:         $dep_chip_medium,
      dep_chip_low:            $dep_chip_low,
      dep_no_vulns:            $dep_no_vulns,
      dep_no_vulns_icon:       $dep_no_vulns_icon,
      dep_filter_empty:        $dep_filter_empty,
      dep_skipped:             $dep_skipped,
      dep_skipped_icon:        $dep_skipped_icon,
      dep_show_more:           $dep_show_more,
      dep_th_sev:              $dep_th_sev,
      dep_th_cve:              $dep_th_cve,
      dep_th_pkg:              $dep_th_pkg,
      dep_th_ver:              $dep_th_ver,
      dep_th_fixed:            $dep_th_fixed,
      dep_th_cvss:             $dep_th_cvss,
      dep_th_src:              $dep_th_src,
      dep_sources_summary:     $dep_sources_summary,
      dep_sources_summary_cached: $dep_sources_summary_cached,
      dep_artifact_merged:     $dep_artifact_merged,
      dep_artifact_trivy:      $dep_artifact_trivy,
      dep_artifact_grype:      $dep_artifact_grype,
      badge_inconclusive:      $badge_inconclusive,
      dep_warn_head:           $dep_warn_head,
      dep_warn_body:           $dep_warn_body,
      dep_no_cve:              $dep_no_cve,
      dep_secrets_title:       $dep_secrets_title,
      dep_secrets_type:        $dep_secrets_type,
      dep_secrets_rule:        $dep_secrets_rule,
      dep_secrets_loc:         $dep_secrets_loc,
      hado_search_placeholder: $hado_search_placeholder,
      hado_chip_all:           $hado_chip_all,
      hado_chip_error:         $hado_chip_error,
      hado_chip_warning:       $hado_chip_warning,
      hado_chip_info:          $hado_chip_info,
      hado_no_findings:        $hado_no_findings,
      hado_no_findings_icon:   $hado_no_findings_icon,
      hado_filter_empty:       $hado_filter_empty,
      hado_skipped:            $hado_skipped,
      hado_skipped_icon:       $hado_skipped_icon,
      hado_th_level:           $hado_th_level,
      hado_th_rule:            $hado_th_rule,
      hado_th_loc:             $hado_th_loc,
      hado_th_msg:             $hado_th_msg,
      hado_meta_errors:        $hado_meta_errors,
      hado_meta_warnings:      $hado_meta_warnings,
      hado_meta_info:          $hado_meta_info,
      hado_artifact:           $hado_artifact,
      vt_grid_sha256:          $vt_grid_sha256,
      vt_grid_md5:             $vt_grid_md5,
      vt_grid_sha1:            $vt_grid_sha1,
      vt_grid_type:            $vt_grid_type,
      vt_grid_size:            $vt_grid_size,
      vt_grid_name:            $vt_grid_name,
      vt_clean:                $vt_clean,
      vt_skipped:              $vt_skipped,
      vt_skipped_icon:         $vt_skipped_icon,
      vt_stat_malicious:       $vt_stat_malicious,
      vt_stat_suspicious:      $vt_stat_suspicious,
      vt_stat_undetected:      $vt_stat_undetected,
      vt_stat_unsupported:     $vt_stat_unsupported,
      vt_artifact:             $vt_artifact,
      load_error_prefix:       $load_error_prefix,
      footer_generated:        $footer_generated
    }'
}

# ── PDF Report ─────────────────────────────────────────────────────────────────
ensure_pdf_image() {
  if docker image inspect "$PDF_IMAGE_LOCAL" &>/dev/null 2>&1; then
    return
  fi
  local dockerfile
  dockerfile="$(dirname "$0")/docker/Dockerfile.pdf"
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
  # PDF-01: WeasyPrint cannot execute JavaScript, so it produces a blank page with the new
  # interactive dashboard. PDF generation is deferred to a future milestone (PDF-FUTURE).
  # See .planning/ROADMAP.md for the PDF redesign tracking item.
  log_warn "PDF is not supported with the new interactive dashboard."
  log_warn "Open the HTML report in a browser: file://$REPORT_DIR/report.html"
  return 0
}

# ── Apply per-repo config suppressions (post-merge, pre-risk-score) ──────────
apply_scanner_config_suppressions() {
  [[ ${#CFG_CVE_IGNORE[@]} -eq 0 && ${#CFG_SEMGREP_RULE_IGNORES[@]} -eq 0 ]] && return

  local merged="$RAW_DIR/vulns_merged.json"
  local semgrep_out="$RAW_DIR/semgrep.json"
  local suppressed_file="$RAW_DIR/suppressed.json"

  # ── CVE suppression ──
  if [[ ${#CFG_CVE_IGNORE[@]} -gt 0 && -s "$merged" ]]; then
    local cve_ignore_json
    cve_ignore_json=$(printf '%s\n' "${CFG_CVE_IGNORE[@]}" | jq -R . | jq -s .)

    # Split vulns_merged.json into suppressed (matching IDs + suppressed_by) and kept (non-matching)
    jq --argjson ignore "$cve_ignore_json" \
      '{"suppressed": [.[] | select(.id | IN($ignore[]))
                            | . + {"suppressed_by": "cve_ignore"}],
        "kept":        [.[] | select(.id | IN($ignore[]) | not)]}' \
      "$merged" > "${merged}.supp_tmp" 2>/dev/null || { rm -f "${merged}.supp_tmp"; return; }

    jq '.kept'       "${merged}.supp_tmp" > "${merged}.filtered" && mv "${merged}.filtered" "$merged"
    jq '.suppressed' "${merged}.supp_tmp" > "$suppressed_file"
    rm -f "${merged}.supp_tmp"

    # Re-read MERGED_* counters to reflect post-suppression counts
    MERGED_CRITICAL=$(jq '[.[] | select(.severity=="CRITICAL")] | length' "$merged" 2>/dev/null || echo 0)
    MERGED_HIGH=$(jq     '[.[] | select(.severity=="HIGH")]     | length' "$merged" 2>/dev/null || echo 0)
    MERGED_MEDIUM=$(jq   '[.[] | select(.severity=="MEDIUM")]   | length' "$merged" 2>/dev/null || echo 0)
    MERGED_LOW=$(jq      '[.[] | select(.severity=="LOW")]      | length' "$merged" 2>/dev/null || echo 0)
  fi

  # ── Semgrep rule suppression ──
  if [[ ${#CFG_SEMGREP_RULE_IGNORES[@]} -gt 0 && -s "$semgrep_out" ]]; then
    local rule_ignore_json
    rule_ignore_json=$(printf '%s\n' "${CFG_SEMGREP_RULE_IGNORES[@]}" | jq -R . | jq -s .)

    # Build suppressed semgrep entries + filter results
    jq --argjson ignore "$rule_ignore_json" \
      '{"suppressed": [.results[] | select(.check_id | IN($ignore[]))
                                  | {id: .check_id,
                                     detail: (.path + ":" + (.start.line | tostring)),
                                     suppressed_by: "semgrep_rule_ignores"}],
        "kept_results": [.results[] | select(.check_id | IN($ignore[]) | not)]}' \
      "$semgrep_out" > "${semgrep_out}.supp_tmp" 2>/dev/null || { rm -f "${semgrep_out}.supp_tmp"; return; }

    # Update semgrep.json with kept results only
    jq --slurpfile tmp "${semgrep_out}.supp_tmp" \
      '.results = $tmp[0].kept_results' \
      "$semgrep_out" > "${semgrep_out}.filtered" && mv "${semgrep_out}.filtered" "$semgrep_out"

    # Append semgrep suppressed entries to suppressed.json (merge arrays if file already exists)
    if [[ -s "$suppressed_file" ]]; then
      jq -s '.[0] + .[1]' "$suppressed_file" \
        <(jq '.suppressed' "${semgrep_out}.supp_tmp") > "${suppressed_file}.merged" \
        && mv "${suppressed_file}.merged" "$suppressed_file"
    else
      jq '.suppressed' "${semgrep_out}.supp_tmp" > "$suppressed_file"
    fi
    rm -f "${semgrep_out}.supp_tmp"

    # Recalculate semgrep counter globals from the now-filtered semgrep.json
    if [[ -s "$semgrep_out" ]]; then
      SEMGREP_FINDINGS=$(jq '[.results[]] | length' "$semgrep_out" 2>/dev/null || echo 0)
      SEMGREP_VISIBLE=$(jq --arg min_sev "$SEMGREP_MIN_SEV" '
        def above_threshold:
          if   $min_sev == "high"   then . == "ERROR"
          elif $min_sev == "medium" then (. == "ERROR" or . == "WARNING")
          elif $min_sev == "low"    then (. == "ERROR" or . == "WARNING" or . == "LOW")
          else true end;
        [.results[]
          | select(.check_id | test("audit|test|benchmark|example|sample"; "i") | not)
          | select(.extra.severity | above_threshold)
        ] | length' "$semgrep_out" 2>/dev/null || echo 0)

      SEMGREP_HIGH_VISIBLE=$(jq '[.results[]
        | select(.check_id | test("audit|test|benchmark|example|sample"; "i") | not)
        | select(.extra.severity == "ERROR")] | length' "$semgrep_out" 2>/dev/null || echo 0)

      SEMGREP_MEDIUM_VISIBLE=$(jq '[.results[]
        | select(.check_id | test("audit|test|benchmark|example|sample"; "i") | not)
        | select(.extra.severity == "WARNING")] | length' "$semgrep_out" 2>/dev/null || echo 0)

      SEMGREP_UNIQUE_RULES=$(jq --arg min_sev "$SEMGREP_MIN_SEV" '
        def above_threshold:
          if   $min_sev == "high"   then . == "ERROR"
          elif $min_sev == "medium" then (. == "ERROR" or . == "WARNING")
          elif $min_sev == "low"    then (. == "ERROR" or . == "WARNING" or . == "LOW")
          else true end;
        [.results[]
          | select(.check_id | test("audit|test|benchmark|example|sample"; "i") | not)
          | select(.extra.severity | above_threshold)
          | .check_id | gsub("-[0-9a-f]{8,}$";"")
        ] | unique | length' "$semgrep_out" 2>/dev/null || echo 0)

      # Update SEMGREP_STATUS based on refreshed counts
      if [[ "$SEMGREP_VISIBLE" -eq 0 ]]; then
        SEMGREP_STATUS="pass"
      elif [[ "$SEMGREP_HIGH_VISIBLE" -gt 0 ]]; then
        SEMGREP_STATUS="fail"
      elif [[ "$SEMGREP_MEDIUM_VISIBLE" -gt 0 ]]; then
        SEMGREP_STATUS="warn"
      else
        SEMGREP_STATUS="pass"
      fi
    fi
  fi
}

# ── HTML helper: suppressed findings rows ────────────────────────────────────
suppressed_rows_html() {
  [[ ! -s "$RAW_DIR/suppressed.json" ]] && return
  jq -r 'to_entries[] | .key as $i | .value |
    "<tr><td class=\"num\">\($i + 1)</td>" +
    "<td>" + (if .suppressed_by == "cve_ignore" then "CVE" else "Semgrep" end) + "</td>" +
    "<td><code>" + (.id // .check_id // "—" | gsub("&";"&amp;") | gsub("<";"&lt;") | gsub(">";"&gt;")) + "</code></td>" +
    "<td>" + (.suppressed_by // "unknown") + "</td></tr>"' \
    "$RAW_DIR/suppressed.json" 2>/dev/null || true
}

calculate_risk_score() {
  RISK_SCORE=$(awk -v c="$MERGED_CRITICAL" -v h="$MERGED_HIGH" -v m="$MERGED_MEDIUM" \
                   -v l="$MERGED_LOW" -v sh="$SEMGREP_HIGH_VISIBLE" -v sm="$SEMGREP_MEDIUM_VISIBLE" \
                   -v sec="$TRIVY_SECRETS" -v vt="$VT_MALICIOUS" \
    'BEGIN {
      score = (c*20) + (h*5) + (m*2) + (l*0.5) + (sh*3) + (sm*1) + (sec*25) + (vt>0 ? 30 : 0)
      if (score > 100) score = 100
      printf "%d\n", score
    }')
}

diff_count() {
  [[ -z "$1" ]] && echo 0 && return
  echo "$1" | wc -l | tr -d ' '
}

# resolve_artifact dir name
# Probes dir/raw/name → dir/logs/name → dir/name (legacy flat layout).
# Echoes the first path that exists as a regular file; echoes nothing if none found.
resolve_artifact() {
  local _dir="$1" _name="$2"
  if   [[ -f "$_dir/raw/$_name"  ]]; then echo "$_dir/raw/$_name"
  elif [[ -f "$_dir/logs/$_name" ]]; then echo "$_dir/logs/$_name"
  elif [[ -f "$_dir/$_name"      ]]; then echo "$_dir/$_name"
  fi
}

compare_findings() {
  [[ -z "$COMPARE_DIR" ]] && return

  log_section "Diff Mode"
  log_info "Comparing against prior report: $COMPARE_DIR"

  # ── CVE diff (D-01): key = id+pkg+version ─────────────────────────────────
  local curr_cve_keys="" prev_cve_keys=""
  local curr_cve_file="$RAW_DIR/vulns_merged.json"
  local prev_cve_file
  prev_cve_file=$(resolve_artifact "$COMPARE_DIR" "vulns_merged.json")
  if [[ -s "$curr_cve_file" ]]; then
    curr_cve_keys=$(jq -r '[.[] | (.id | @base64) + ":" + (.pkg | @base64) + ":" + (.version | @base64)] | sort[]' "$curr_cve_file" 2>/dev/null || echo "")
  fi
  if [[ -n "$prev_cve_file" && -s "$prev_cve_file" ]]; then
    prev_cve_keys=$(jq -r '[.[] | (.id | @base64) + ":" + (.pkg | @base64) + ":" + (.version | @base64)] | sort[]' "$prev_cve_file" 2>/dev/null || echo "")
  fi
  DIFF_CVE_NEW=$(comm -23 <(echo "$curr_cve_keys") <(echo "$prev_cve_keys") 2>/dev/null || echo "")
  DIFF_CVE_CLOSED=$(comm -13 <(echo "$curr_cve_keys") <(echo "$prev_cve_keys") 2>/dev/null || echo "")
  DIFF_CVE_PERSISTENT=$(comm -12 <(echo "$curr_cve_keys") <(echo "$prev_cve_keys") 2>/dev/null || echo "")

  # ── Semgrep diff (D-02): key = check_id ───────────────────────────────────
  local curr_sg_keys="" prev_sg_keys=""
  local curr_sg_file="$RAW_DIR/semgrep.json"
  local prev_sg_file
  prev_sg_file=$(resolve_artifact "$COMPARE_DIR" "semgrep.json")
  if [[ -s "$curr_sg_file" ]]; then
    curr_sg_keys=$(jq -r '[.results[].check_id] | unique | sort[]' "$curr_sg_file" 2>/dev/null || echo "")
  fi
  if [[ -n "$prev_sg_file" && -s "$prev_sg_file" ]]; then
    prev_sg_keys=$(jq -r '[.results[].check_id] | unique | sort[]' "$prev_sg_file" 2>/dev/null || echo "")
  fi
  DIFF_SEMGREP_NEW=$(comm -23 <(echo "$curr_sg_keys") <(echo "$prev_sg_keys") 2>/dev/null || echo "")
  DIFF_SEMGREP_CLOSED=$(comm -13 <(echo "$curr_sg_keys") <(echo "$prev_sg_keys") 2>/dev/null || echo "")
  DIFF_SEMGREP_PERSISTENT=$(comm -12 <(echo "$curr_sg_keys") <(echo "$prev_sg_keys") 2>/dev/null || echo "")

  # ── Hadolint diff (D-03): key = code+line ─────────────────────────────────
  local curr_hl_keys="" prev_hl_keys=""
  local curr_hl_file="$RAW_DIR/hadolint.json"
  local prev_hl_file
  prev_hl_file=$(resolve_artifact "$COMPARE_DIR" "hadolint.json")
  if [[ -s "$curr_hl_file" ]]; then
    curr_hl_keys=$(jq -r '[.[] | .code + "|" + (.line|tostring)] | sort[]' "$curr_hl_file" 2>/dev/null || echo "")
  fi
  if [[ -n "$prev_hl_file" && -s "$prev_hl_file" ]]; then
    prev_hl_keys=$(jq -r '[.[] | .code + "|" + (.line|tostring)] | sort[]' "$prev_hl_file" 2>/dev/null || echo "")
  fi
  DIFF_HADOLINT_NEW=$(comm -23 <(echo "$curr_hl_keys") <(echo "$prev_hl_keys") 2>/dev/null || echo "")
  DIFF_HADOLINT_CLOSED=$(comm -13 <(echo "$curr_hl_keys") <(echo "$prev_hl_keys") 2>/dev/null || echo "")
  DIFF_HADOLINT_PERSISTENT=$(comm -12 <(echo "$curr_hl_keys") <(echo "$prev_hl_keys") 2>/dev/null || echo "")

  # ── VT diff (D-04): malicious count change ────────────────────────────────
  VT_DIFF_CURR="${VT_MALICIOUS:-0}"
  local prev_vt_file
  prev_vt_file=$(resolve_artifact "$COMPARE_DIR" "vt.env")
  if [[ -n "$prev_vt_file" ]]; then
    VT_DIFF_PREV=$(grep '^VT_MALICIOUS=' "$prev_vt_file" 2>/dev/null \
      | head -1 | cut -d= -f2 | tr -d "'" | tr -d '"' || echo 0)
    VT_DIFF_PREV="${VT_DIFF_PREV:-0}"
  else
    prev_vt_file=$(resolve_artifact "$COMPARE_DIR" "vt.json")
    if [[ -n "$prev_vt_file" && -s "$prev_vt_file" ]]; then
      VT_DIFF_PREV=$(jq -r '.last_analysis_stats.malicious // 0' "$prev_vt_file" 2>/dev/null || echo 0)
    fi
  fi
  VT_DIFF_PREV="${VT_DIFF_PREV:-0}"
  if ! [[ "$VT_DIFF_PREV" =~ ^[0-9]+$ ]]; then
    log_warn "--compare: invalid VT_MALICIOUS in prior vt.env — defaulting to 0"
    VT_DIFF_PREV=0
  fi

  log_info "CVE diff  — new: $(echo "$DIFF_CVE_NEW" | grep -c . || echo 0) closed: $(echo "$DIFF_CVE_CLOSED" | grep -c . || echo 0) persistent: $(echo "$DIFF_CVE_PERSISTENT" | grep -c . || echo 0)"
  log_info "Semgrep   — new: $(echo "$DIFF_SEMGREP_NEW" | grep -c . || echo 0) closed: $(echo "$DIFF_SEMGREP_CLOSED" | grep -c . || echo 0) persistent: $(echo "$DIFF_SEMGREP_PERSISTENT" | grep -c . || echo 0)"
  log_info "Hadolint  — new: $(echo "$DIFF_HADOLINT_NEW" | grep -c . || echo 0) closed: $(echo "$DIFF_HADOLINT_CLOSED" | grep -c . || echo 0) persistent: $(echo "$DIFF_HADOLINT_PERSISTENT" | grep -c . || echo 0)"
  log_info "VT        — prev: $VT_DIFF_PREV curr: $VT_DIFF_CURR"
}

# ── HTML helper: diff rows for one scanner/variable ──────────────────────────
# Usage: _diff_rows_html "Scanner Label" "$DIFF_VAR"
_diff_rows_html() {
  local label="$1" data="$2"
  if [[ -n "$data" ]]; then
    echo "$data" | while IFS= read -r _k; do
      _ke=$(printf '%s' "$_k" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
      printf '<tr><td>%s</td><td>%s</td></tr>\n' "$label" "$_ke"
    done
  else
    printf '<tr><td colspan="2" class="muted">—</td></tr>\n'
  fi
}

# ── HTML helper: diff module (Изменения) — only when COMPARE_DIR is set ──────
diff_module_html() {
  [[ -z "$COMPARE_DIR" ]] && return
  printf '<div class="module">\n'
  printf '  <div class="mod-head">\n'
  printf '    <div class="mod-title"><span class="mod-icon">🔄</span> %s</div>\n' "$T_DIFF_TITLE"
  printf '  </div>\n'
  printf '  <div class="mod-body">\n'
  printf '    <details open>\n'
  printf '      <summary>%s (%s CVE + %s Semgrep + %s Hadolint) &nbsp;&middot;&nbsp; %s (%s CVE + %s Semgrep + %s Hadolint) &nbsp;&middot;&nbsp; %s (%s CVE + %s Semgrep + %s Hadolint)</summary>\n' \
    "$T_DIFF_NEW"        "$(diff_count "$DIFF_CVE_NEW")"        "$(diff_count "$DIFF_SEMGREP_NEW")"        "$(diff_count "$DIFF_HADOLINT_NEW")" \
    "$T_DIFF_CLOSED"     "$(diff_count "$DIFF_CVE_CLOSED")"     "$(diff_count "$DIFF_SEMGREP_CLOSED")"     "$(diff_count "$DIFF_HADOLINT_CLOSED")" \
    "$T_DIFF_PERSISTENT" "$(diff_count "$DIFF_CVE_PERSISTENT")" "$(diff_count "$DIFF_SEMGREP_PERSISTENT")" "$(diff_count "$DIFF_HADOLINT_PERSISTENT")"
  printf '\n      <h4 style='"'"'margin:0.8rem 0 0.3rem'"'"'>%s</h4>\n' "$T_DIFF_NEW"
  printf '      <div class='"'"'tbl-wrap'"'"'><table class='"'"'tbl-fixed'"'"'>\n'
  printf '        <thead><tr><th>Scanner</th><th>Finding</th></tr></thead>\n'
  printf '        <tbody>\n'
  _diff_rows_html "CVE"      "$DIFF_CVE_NEW"
  _diff_rows_html "Semgrep"  "$DIFF_SEMGREP_NEW"
  _diff_rows_html "Hadolint" "$DIFF_HADOLINT_NEW"
  printf '        </tbody>\n      </table></div>\n'
  printf '\n      <h4 style='"'"'margin:0.8rem 0 0.3rem'"'"'>%s</h4>\n' "$T_DIFF_CLOSED"
  printf '      <div class='"'"'tbl-wrap'"'"'><table class='"'"'tbl-fixed'"'"'>\n'
  printf '        <thead><tr><th>Scanner</th><th>Finding</th></tr></thead>\n'
  printf '        <tbody>\n'
  _diff_rows_html "CVE"      "$DIFF_CVE_CLOSED"
  _diff_rows_html "Semgrep"  "$DIFF_SEMGREP_CLOSED"
  _diff_rows_html "Hadolint" "$DIFF_HADOLINT_CLOSED"
  printf '        </tbody>\n      </table></div>\n'
  printf '\n      <h4 style='"'"'margin:0.8rem 0 0.3rem'"'"'>%s</h4>\n' "$T_DIFF_PERSISTENT"
  printf '      <div class='"'"'tbl-wrap'"'"'><table class='"'"'tbl-fixed'"'"'>\n'
  printf '        <thead><tr><th>Scanner</th><th>Finding</th></tr></thead>\n'
  printf '        <tbody>\n'
  _diff_rows_html "CVE"      "$DIFF_CVE_PERSISTENT"
  _diff_rows_html "Semgrep"  "$DIFF_SEMGREP_PERSISTENT"
  _diff_rows_html "Hadolint" "$DIFF_HADOLINT_PERSISTENT"
  printf '        </tbody>\n      </table></div>\n'
  printf '\n      <p class='"'"'msg muted'"'"' style='"'"'margin-top:0.5rem'"'"'>VirusTotal: %s &rarr; %s malicious</p>\n' \
    "$VT_DIFF_PREV" "$VT_DIFF_CURR"
  printf '    </details>\n  </div>\n</div>\n'
}

# ── HTML helper: suppressed findings module (Подавленные находки) ─────────────
suppressed_module_html() {
  [[ ! -s "$RAW_DIR/suppressed.json" ]] && return
  local _count
  _count=$(jq 'length' "$RAW_DIR/suppressed.json" 2>/dev/null || echo 0)
  printf '<div class="module">\n'
  printf '  <div class="mod-head">\n'
  printf '    <div class="mod-title"><span class="mod-icon">🔕</span> %s</div>\n' "$T_SUPPRESSED_TITLE"
  printf '  </div>\n'
  printf '  <div class="mod-body">\n'
  printf '    <details open>\n'
  printf '      <summary>%s findings suppressed via .scanner-config</summary>\n' "$_count"
  printf '      <div class='"'"'tbl-wrap'"'"'><table class='"'"'tbl-fixed'"'"'>\n'
  printf '        <colgroup><col class='"'"'col-num'"'"'><col style='"'"'width:8%%'"'"'><col><col style='"'"'width:20%%'"'"'></colgroup>\n'
  printf '        <thead><tr><th>#</th><th>Type</th><th>Finding</th><th>%s</th></tr></thead>\n' "$T_SUPPRESSED_REASON"
  printf '        <tbody>%s</tbody>\n' "$(suppressed_rows_html)"
  printf '      </table></div>\n'
  printf '    </details>\n  </div>\n</div>\n'
}

generate_report() {
  [[ "$REPORT_GENERATED" == true ]] && return
  REPORT_GENERATED=true
  local overall; overall=$(overall_status)
  local gh_repo; gh_repo=$(parse_github_url "$TARGET")

  # Step 1: setup_lang must come first — populates T_* vars for build_lang_dict (Pitfall 3)
  setup_lang

  # Step 2: Build report.json data layer (writes $REPORT_DIR/report.json)
  build_report_json

  # Step 3: Read compact blob — jq -c produces single-line JSON (Pitfall 2)
  local json_blob
  json_blob=$(jq -c . "$REPORT_DIR/report.json")

  # Step 4: Build i18n dict (T_* already set by setup_lang above — Pitfall 3)
  local lang_dict
  lang_dict=$(build_lang_dict)

  # Step 4a (CR-02): Neutralize the HTML-sensitive '<' by escaping it to its JSON
  # unicode escape <. This makes a literal </script>, <script, or <!-- in
  # untrusted scanner output impossible inside the <script type="application/json">
  # block while remaining valid JSON that JSON.parse() accepts unchanged. jq does
  # NOT escape '/', so escaping '<' is what closes the script-termination vector.
  json_blob=$(printf '%s' "$json_blob" | sed 's/</\\u003c/g')
  lang_dict=$(printf '%s' "$lang_dict" | sed 's/</\\u003c/g')

  # Step 5: Write STATIC template via QUOTED heredoc — zero shell expansion (D-01 / DATA-05)
  # Quoted delimiter (the single-quote around HTML below) disables ALL $(...) and ${...} inside.
  # Placeholders __SCAN_DATA__ and __LANG_DICT__ are injected by sed in Step 6.
  cat > "$REPORT_DIR/report.html" <<'HTML'
<!DOCTYPE html>
<html data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Scan</title>
<style>
  /* System font stack — D-03: system fonts only; no external web font links. */
  :root {
    --fs-xs:0.62rem; --fs-sm:0.74rem; --fs-base:0.85rem; --fs-ui:1rem; --fs-hero:1.3rem;
    --fs-2xs:0.64rem; --fs-stat:1.9rem;
    --pass:#22c55e; --warn:#f59e0b; --fail:#ef4444; --skip:#64748b;
    --bg:#080d18; --surface:#0f172a; --surface2:#162032;
    --border:#1e2d45; --text:#e2e8f0; --muted:#7589a1; --code:#7dd3fc;
    --r:8px;
    --sev-critical:#f0506e; --sev-high:#ff7849; --sev-medium:#f5a623; --sev-low:#4ba3f5;
    --accent:#7c9cf5; --r-sm:6px;
    --shadow:0 1px 0 rgba(255,255,255,.02), 0 8px 24px -12px rgba(0,0,0,.6);
  }
  [data-theme="light"]{
    --bg:#f4f6fb; --bg2:#eef1f8; --surface:#ffffff; --surface2:#f1f4fa;
    --border:#dde3ee; --border2:#cbd4e6;
    --text:#16203a; --muted:#5d6b88; --faint:#617088;
    --shadow:0 1px 2px rgba(16,28,60,.06), 0 12px 28px -16px rgba(16,28,60,.18);
  }
  /* System fonts for text: -apple-system, BlinkMacSystemFont, Segoe UI, system-ui, sans-serif */
  /* System fonts for code: ui-monospace, SFMono-Regular, Menlo, monospace */
  *{box-sizing:border-box;margin:0;padding:0}
  :focus-visible{outline:2px solid var(--accent);outline-offset:2px}
  body{
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
    background:var(--bg);color:var(--text);font-size:14px;min-height:100vh;
  }
  a{color:var(--code);text-decoration:none}
  a:hover{text-decoration:underline}
  .idcard-link{color:var(--accent);text-decoration:none}
  .idcard-link:hover{text-decoration:underline}
  code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--code);font-size:0.8rem}

  /* ── Page wrapper ── */
  .page{max-width:min(96vw,1680px);margin:0 auto;padding:2rem 1.5rem}

  /* ── Hero ── */
  .hero{
    background:var(--surface);border:1px solid var(--border);border-radius:var(--r);
    padding:1.75rem 1.5rem 1.5rem;text-align:center;margin-bottom:1.25rem;
  }
  .hero h1{font-size:var(--fs-hero);font-weight:700;letter-spacing:-0.4px;margin-bottom:1.25rem;color:var(--text)}

  /* ── Identity cards (Target / Ref / Date) ── */
  .identity-cards{display:flex;justify-content:center;gap:0.75rem;flex-wrap:wrap;margin-bottom:1.1rem}
  .id-card{
    background:var(--surface2);border:1px solid var(--border);border-radius:var(--r);
    padding:0.6rem 1.25rem;text-align:center;min-width:150px;
  }
  .id-label{font-size:0.7rem;text-transform:uppercase;letter-spacing:0.8px;color:var(--muted);margin-bottom:0.35rem}
  .id-val{font-size:0.95rem;font-weight:600;color:var(--text)}

  /* ── Topbar ── */
  .topbar{
    position:sticky;top:0;z-index:50;
    background:color-mix(in srgb,var(--bg) 82%,transparent);
    backdrop-filter:blur(12px);border-bottom:1px solid var(--border);
  }
  .topbar-inner{
    max-width:min(96vw,1680px);margin:0 auto;padding:.5rem 1.5rem;
    display:flex;align-items:center;gap:1rem;
  }
  .brand{display:flex;align-items:center;gap:.5rem;font-size:.9rem;font-weight:700;color:var(--text)}
  .brand .dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
  .verdict-pill{
    font-size:.68rem;font-weight:700;letter-spacing:.6px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
    padding:2px 8px;border-radius:var(--r-sm);
  }
  .v-pass{background:rgba(34,197,94,.15);color:var(--pass)}
  .v-warn{background:rgba(245,158,11,.15);color:var(--warn)}
  .v-fail{background:rgba(239,68,68,.15);color:var(--fail)}
  .v-skip{background:rgba(100,116,139,.15);color:var(--skip)}
  .sep{flex:1}
  .sevdots{display:flex;align-items:center;gap:.75rem}
  .sd{display:flex;align-items:center;gap:.25rem;font-size:.7rem;font-weight:700;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
  .sd i{width:8px;height:8px;border-radius:50%;display:inline-block}
  .iconbtn{
    width:34px;height:34px;border:1px solid var(--border);border-radius:var(--r);
    background:var(--surface2);color:var(--text);cursor:pointer;
    display:flex;align-items:center;justify-content:center;font-size:1rem;
  }
  .iconbtn:hover{border-color:var(--border2,var(--border))}

  /* ── Identity grid ── */
  .idgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.75rem;margin-bottom:1rem}
  .idcard{
    background:var(--surface2);border:1px solid var(--border);border-radius:var(--r);
    padding:.6rem 1.25rem;
  }
  .idcard .k{font-size:var(--fs-2xs);text-transform:uppercase;letter-spacing:.8px;color:var(--muted);margin-bottom:.35rem}
  .idcard .v{font-size:.9rem;font-weight:700;color:var(--text);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}

  /* ── Verdict banner ── */
  .banner{
    display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;
    padding:.9rem 1.25rem;border-radius:var(--r);border:1px solid var(--border);
    border-left:3px solid var(--skip);margin-bottom:1.25rem;background:var(--surface);
  }
  .b-pass.banner,.banner.b-pass{border-left-color:var(--pass);background:linear-gradient(90deg,color-mix(in srgb,var(--pass) 10%,transparent),transparent 60%),var(--surface)}
  .b-warn.banner,.banner.b-warn{border-left-color:var(--warn);background:linear-gradient(90deg,color-mix(in srgb,var(--warn) 10%,transparent),transparent 60%),var(--surface)}
  .b-fail.banner,.banner.b-fail{border-left-color:var(--fail);background:linear-gradient(90deg,color-mix(in srgb,var(--fail) 10%,transparent),transparent 60%),var(--surface)}
  .b-skip.banner,.banner.b-skip{border-left-color:var(--skip);background:var(--surface)}
  .banner .big{font-size:1.05rem;font-weight:700;letter-spacing:.5px;color:var(--text);margin-bottom:.3rem}
  .banner .desc{font-size:.8rem;color:var(--muted);line-height:1.5}
  .banner .score{text-align:right;flex-shrink:0}
  .banner .score b{display:block;font-size:1.6rem;font-weight:700;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--text)}
  .banner .score span{font-size:.65rem;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
  /* .warn-banner — zero-package warning (GRYPE-04) */
  .warn-banner{display:flex;align-items:flex-start;gap:1rem;padding:.9rem 1.25rem;margin-bottom:1.25rem;border-radius:var(--r);border:1px solid var(--border);border-left:3px solid var(--muted);background:rgba(100,116,139,.08)}
  .warn-banner .wb-icon{font-size:1rem;color:var(--muted);flex-shrink:0;line-height:1.5}
  .warn-banner .whead{font-size:var(--fs-base);font-weight:700;color:var(--text);margin-bottom:.25rem;line-height:1.2}
  .warn-banner .wbody{font-size:var(--fs-sm);color:var(--muted);line-height:1.5;font-style:normal}

  /* ── Severity distribution bar ── */
  .distrib{margin-bottom:1.25rem}
  .distrib .lbl{font-size:.7rem;color:var(--muted);margin-bottom:.4rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
  .bar{display:flex;height:12px;border-radius:6px;overflow:hidden;background:var(--surface2);gap:2px}
  .bar span{transition:flex .3s}
  .barlegend{display:flex;flex-wrap:wrap;gap:.5rem 1rem;margin-top:.4rem}
  .barlegend span{display:flex;align-items:center;gap:.3rem;font-size:.68rem;color:var(--muted);font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
  .barlegend i{width:8px;height:8px;border-radius:2px;display:inline-block;flex-shrink:0}

  /* ── Scanner cards ── */
  html{scroll-behavior:smooth}
  .scanners{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:.75rem;margin-bottom:1.5rem}
  .scard{
    background:var(--surface);border:1px solid var(--border);border-radius:var(--r);
    padding:1rem 1.25rem;display:block;text-decoration:none;
    transition:transform .15s,border-color .15s;
  }
  .scard:hover{transform:translateY(-1px);border-color:var(--border2,var(--border))}
  .scard .top{display:flex;align-items:center;justify-content:space-between;margin-bottom:.5rem}
  .scard .name{font-size:.8rem;font-weight:700;color:var(--text)}
  .scard .num{font-size:var(--fs-stat);font-weight:700;line-height:1.1;margin-bottom:.2rem}
  .scard .sub{font-size:.72rem;color:var(--muted)}
  .t-pass{color:var(--pass)} .t-warn{color:var(--warn)} .t-fail{color:var(--fail)} .t-skip{color:var(--skip)}
  .badge{font-size:var(--fs-xs);font-weight:700;padding:2px 6px;border-radius:var(--r-sm);font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
  .b-pass{background:rgba(34,197,94,.15);color:var(--pass)}
  .b-warn{background:rgba(245,158,11,.15);color:var(--warn)}
  .b-fail{background:rgba(239,68,68,.15);color:var(--fail)}
  .b-skip{background:rgba(100,116,139,.15);color:var(--skip)}
  /* .badge.inconclusive — "ran but couldn't assess" neutral state (GRYPE-04) */
  .badge.inconclusive{background:rgba(100,116,139,.15);color:var(--muted);outline:1px solid var(--border);outline-offset:-1px}

  /* ── Section modules ── */
  .module{
    background:var(--surface);border:1px solid var(--border);
    border-radius:var(--r);margin-bottom:1.25rem;
    scroll-margin-top:72px;box-shadow:var(--shadow);
  }
  .mhead{
    display:flex;align-items:center;gap:.75rem;
    padding:.85rem 1.4rem;background:var(--surface2);
    border-bottom:1px solid var(--border);
  }
  .mhead .ttl{font-size:var(--fs-ui);font-weight:700;color:var(--text);flex:1}
  .mhead .meta{font-size:.68rem;color:var(--muted);font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
  .mbody{padding:1.25rem 1.5rem;color:var(--muted);font-size:var(--fs-base);font-style:italic}

  /* ── Footer ── */
  footer{
    text-align:center;padding:1.5rem 0;
    color:var(--muted);font-size:0.8rem;
    border-top:1px solid var(--border);margin-top:0.5rem;
  }

  /* ── Error state ── */
  .load-error{padding:2rem;text-align:center;color:var(--fail);font-size:0.9rem}

  /* ── Semgrep section: toolbar / chips / accordions / location list ── */
  .toolbar{display:flex;gap:.55rem;flex-wrap:wrap;align-items:center;margin-bottom:1rem}
  .search{flex:1;min-width:200px;position:relative}
  .search input{
    width:100%;background:var(--surface2);border:1px solid var(--border);
    border-radius:8px;color:var(--text);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
    font-size:var(--fs-base);padding:.5rem .7rem .5rem 2rem;
  }
  .search input:focus{border-color:var(--accent)}
  .search input:focus:not(:focus-visible){outline:none}
  .search svg{position:absolute;left:.6rem;top:50%;transform:translateY(-50%);opacity:.5}
  .chip{
    font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:var(--fs-sm);font-weight:400;
    padding:.42rem .7rem;border-radius:8px;border:1px solid var(--border);
    background:var(--surface2);color:var(--muted);cursor:pointer;
    user-select:none;transition:.12s;
  }
  .chip:hover{border-color:var(--border);color:var(--text)}
  .chip.on{color:var(--text);border-color:var(--accent);background:color-mix(in srgb,var(--accent) 14%,transparent)}
  .chip .c{opacity:.6;margin-left:.3rem}
  .chip i{width:8px;height:8px;border-radius:2px;display:inline-block;margin-right:.4rem;vertical-align:middle}
  .fg{border:1px solid var(--border);border-radius:var(--r-sm);margin-bottom:.55rem;
    overflow:hidden;background:var(--surface2)}
  .fg>summary{list-style:none;cursor:pointer;display:flex;align-items:center;
    gap:.7rem;padding:.5rem .85rem;font-size:var(--fs-base);transition:background .12s}
  .fg>summary::-webkit-details-marker{display:none}
  .fg>summary:hover{background:var(--surface2)}
  .fg>summary .caret{transition:transform .15s;color:var(--faint);font-size:var(--fs-sm)}
  .fg[open]>summary .caret{transform:rotate(90deg)}
  .sevtag{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:var(--fs-xs);font-weight:600;
    letter-spacing:.6px;padding:.25rem .5rem;border-radius:4px;text-transform:uppercase;
    flex-shrink:0;min-width:62px;text-align:center}
  .s-critical{color:#fff;background:var(--sev-critical)}
  .s-high    {color:#fff;background:var(--sev-high)}
  .s-medium  {color:#1a1505;background:var(--sev-medium)}
  .s-low     {color:#fff;background:var(--sev-low)}
  .fg .rule{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:600;color:var(--text)}
  .fg .cnt{margin-left:auto;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:var(--fs-sm);
    color:var(--muted);background:var(--surface2);border:1px solid var(--border);
    padding:.1rem .5rem;border-radius:999px;flex-shrink:0}
  .fg-body{padding:.5rem .85rem 1rem;border-top:1px solid var(--border)}
  .fg-msg{color:var(--muted);font-size:var(--fs-base);margin:.7rem 0 .6rem;line-height:1.55}
  .fg-doc{font-size:var(--fs-sm);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--faint)}
  .loclist{list-style:none;margin-top:.7rem;display:flex;flex-direction:column;gap:.15rem}
  .loclist li{display:flex;align-items:center;gap:.5rem;padding:.32rem .5rem;
    border-radius:6px;font-size:var(--fs-sm)}
  .loclist li:hover{background:var(--surface)}
  .loclist .ln{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--code)}
  .loclist .more{font-size:var(--fs-sm);color:var(--accent);cursor:pointer;padding:.35rem .5rem;background:none;border:none}
  .empty{text-align:center;color:var(--muted);padding:1.4rem;font-size:var(--fs-base)}
  .empty .ok{color:var(--pass);font-size:1.4rem;display:block;margin-bottom:.3rem}
  .rawlinks{display:flex;gap:1rem;flex-wrap:wrap;margin-top:1rem;
    padding-top:.9rem;border-top:1px solid var(--border);
    font-size:var(--fs-sm);font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
  .rawlinks a{color:var(--faint)}

  /* Phase 11 — table support (CVE + Hadolint) */
  .tbl-wrap{overflow-x:auto}
  table{width:100%;border-collapse:collapse;font-size:var(--fs-base)}
  th{text-align:left;color:var(--faint);font-size:var(--fs-sm);text-transform:uppercase;
    letter-spacing:.8px;padding:.55rem .7rem;border-bottom:1px solid var(--border);font-weight:600}
  td{padding:.55rem .7rem;border-bottom:1px solid var(--border);font-size:var(--fs-base);overflow-wrap:break-word}
  tr:last-child td{border-bottom:none}
  tbody tr:hover{background:var(--surface2)}
  .mono-cell{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--code);word-break:break-all}
  .fix-cell{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--pass)}
  .src-pill{display:inline-block;font-size:var(--fs-xs);font-weight:700;padding:2px 6px;border-radius:var(--r-sm);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;border:1px solid var(--border);background:var(--surface2);color:var(--muted);white-space:nowrap}
  .src-pill.src-both{border-color:var(--accent);background:color-mix(in srgb,var(--accent) 14%,transparent);color:var(--text)}
  .tbl-fixed{table-layout:fixed}
  .path-cell{max-width:280px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}

  /* Phase 11 — VT metadata grid */
  .vtgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:.6rem;margin-bottom:1rem}
  .vtitem{background:var(--surface2);border:1px solid var(--border);border-radius:var(--r-sm);padding:.6rem .75rem}
  .vtitem .k{font-size:var(--fs-sm);text-transform:uppercase;letter-spacing:.8px;color:var(--faint);margin-bottom:.25rem}
  .vtitem .v{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.82rem;word-break:break-all}
  .vtstat{display:flex;gap:.6rem;flex-wrap:wrap;margin-top:1rem}
  .vtstat .x{flex:1;min-width:90px;text-align:center;background:var(--surface2);
    border:1px solid var(--border);border-radius:var(--r-sm);padding:.7rem .4rem}
  .vtstat .x b{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:1.4rem;display:block}
  .vtstat .x span{font-size:var(--fs-sm);text-transform:uppercase;letter-spacing:.6px;color:var(--faint)}
  /* Phase 12 — responsive 480px breakpoint */
  @media (max-width:480px) {
    .page{padding:1rem}
    .topbar-inner{padding:.5rem 1rem}
    .sevdots{flex-wrap:wrap;gap:.4rem}
    .toolbar{flex-direction:column;align-items:stretch}
    .search{min-width:0}
    .module{overflow:visible}
  }
  /* Phase 17 — fixed print width for browser Print-to-PDF (D-04, LAYOUT-04) */
  @media print {
    .page{max-width:1080px}
  }
</style>

<!-- Embedded scan data (DATA-05 / DATA-06) — JS bootstrap reads via el.textContent + JSON.parse (T-08-07) -->
<script type="application/json" id="scan-data">__SCAN_DATA__</script>
<script type="application/json" id="scan-lang">__LANG_DICT__</script>
<script>
(function(){
  try {
    var t = localStorage.getItem('theme');
    if (t === 'light' || t === 'dark') {
      document.documentElement.dataset.theme = t;
    } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
      document.documentElement.dataset.theme = 'light';
    }
  } catch(e) {}
})();
</script>
</head>
<body>
<div class="topbar">
  <div class="topbar-inner">
    <div class="brand" id="topbar-brand"></div>
    <span class="verdict-pill" id="topbar-pill"></span>
    <div class="sep"></div>
    <div class="sevdots" id="sevdots"></div>
    <button class="iconbtn" id="themebtn">&#9680;</button>
  </div>
</div>
<div class="wrap">
<div id="app">
  <!-- Minimal loading state — JS bootstrap replaces this -->
  <noscript><p style="padding:2rem;color:var(--text);background:var(--bg)">JavaScript is required to view this report.</p></noscript>
</div>
</div>

<script>
/* Vanilla-JS bootstrap (DATA-06) — reads embedded JSON, renders identity/verdict skeleton.
   DOM-XSS safety (T-08-07): ALL untrusted values set via .textContent or createElement/appendChild.
   No external runtime deps; no network requests; system fonts only (D-03).
   Full per-section rendering deferred to Phases 9-12. */
(function() {
  'use strict';
  var el = document.getElementById('scan-data');
  var langEl = document.getElementById('scan-lang');
  if (!el) return;

  var D, L = {};
  try {
    D = JSON.parse(el.textContent);
    L = langEl ? JSON.parse(langEl.textContent) : {};
  } catch (e) {
    var app = document.getElementById('app');
    if (app) {
      app.className = 'load-error';
      app.textContent = (L.load_error_prefix || 'Error loading scan data: ') + e.message;
    }
    return;
  }

  /* ── Helpers (DOM-safe: textContent + createElement; no unescaped DOM writes) ── */
  function el_(tag, cls) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    return n;
  }
  function txt_(parent, tag, cls, text) {
    var n = el_(tag, cls);
    n.textContent = text;
    parent.appendChild(n);
    return n;
  }

  /* ── Page title ── */
  var targetName = (D.target && D.target.name) ? D.target.name : 'Unknown';
  var targetUrl = (D.target && D.target.url)
    || ('https://github.com/' + (targetName || ''));
  function encRef(ref) {
    return (ref || 'HEAD').split('/').map(encodeURIComponent).join('/');
  }
  function ghBlobBase() {
    return targetUrl + '/blob/' + encRef((D.target && D.target.ref) || 'HEAD');
  }
  var reportTitle = L.report_title || 'Security Scan';
  document.title = reportTitle + ' — ' + targetName;

  /* ── Severity aggregation (D-01: Semgrep + CVE only) ── */
  var sc = D.scanners || {};
  var semFindings  = (sc.semgrep       && sc.semgrep.findings)       || [];
  var depVulns     = (sc.dependencies  && sc.dependencies.vulns)     || [];
  var hadoFindings = (sc.hadolint      && sc.hadolint.findings)      || [];
  var counts = {critical:0, high:0, medium:0, low:0};
  semFindings.forEach(function(g) {
    if (counts.hasOwnProperty(g.severity)) { counts[g.severity] += (g.count || 0); }
  });
  depVulns.forEach(function(v) {
    if (counts.hasOwnProperty(v.severity)) { counts[v.severity] += 1; }
  });
  var total = counts.critical + counts.high + counts.medium + counts.low;

  /* ── resolveStatus + bStatus (CR-03: pass/warn/fail → self; else → skip) ── */
  var verdict = D.verdict || {};
  function resolveStatus(s) {
    s = (s || '').toLowerCase();
    return (s === 'pass' || s === 'warn' || s === 'fail') ? s : 'skip';
  }
  var bStatus = resolveStatus(verdict.status);
  var statusText = bStatus === 'pass' ? (L.verdict_pass ? L.verdict_pass.split('—')[0].trim() : 'PASS')
                 : bStatus === 'warn' ? (L.verdict_warn ? L.verdict_warn.split('—')[0].trim() : 'WARN')
                 : bStatus === 'fail' ? (L.verdict_fail ? L.verdict_fail.split('—')[0].trim() : 'FAIL')
                 : (L.verdict_unknown || 'UNKNOWN');

  /* ── Build #app content ── */
  var app = document.getElementById('app');
  if (!app) return;
  app.textContent = ''; /* clear loading placeholder */

  /* ── Topbar fill (scaffold already rendered by static heredoc HTML) ── */
  var brandEl = document.getElementById('topbar-brand');
  if (brandEl) {
    var dot = el_('span', 'dot');
    dot.style.background = 'var(--' + bStatus + ')';
    brandEl.appendChild(dot);
    txt_(brandEl, 'span', '', reportTitle);
  }
  var pillEl = document.getElementById('topbar-pill');
  if (pillEl) {
    pillEl.className = 'verdict-pill v-' + bStatus;
    txt_(pillEl, 'span', '', statusText);
  }
  var sevdotsEl = document.getElementById('sevdots');
  if (sevdotsEl) {
    ['critical','high','medium','low'].forEach(function(sev) {
      if (!counts[sev]) return;
      var sd = el_('span', 'sd');
      var i = el_('i', '');
      i.style.background = 'var(--sev-' + sev + ')';
      sd.appendChild(i);
      sd.appendChild(document.createTextNode(sev[0].toUpperCase() + ' '));
      txt_(sd, 'b', '', String(counts[sev]));
      sevdotsEl.appendChild(sd);
    });
  }
  var themebtn = document.getElementById('themebtn');
  if (themebtn) {
    themebtn.title = L.theme_toggle_title || 'Toggle theme';
    themebtn.onclick = function() {
      var r = document.documentElement;
      var next = r.dataset.theme === 'dark' ? 'light' : 'dark';
      r.dataset.theme = next;
      try { localStorage.setItem('theme', next); } catch(e) {}
    };
  }

  /* ── Page wrapper ── */
  var page = el_('div', 'page');
  app.appendChild(page);

  /* ── Hero ── */
  var hero = el_('div', 'hero');
  page.appendChild(hero);

  txt_(hero, 'h1', '', reportTitle);

  /* ── Identity cards (.idgrid / .idcard) ── */
  var idgrid = el_('div', 'idgrid');
  hero.appendChild(idgrid);
  function addIdCard(label, value, link) {
    var card = el_('div', 'idcard');
    txt_(card, 'div', 'k', label);
    if (link) {
      var vDiv = el_('div', 'v');
      var a = el_('a', 'idcard-link');
      a.href = link;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.textContent = value || '—';
      var icon = el_('span', '');
      icon.setAttribute('aria-hidden', 'true');
      icon.textContent = ' ↗'; /* ↗ U+2197 NORTH EAST ARROW */
      a.appendChild(icon);
      vDiv.appendChild(a);
      card.appendChild(vDiv);
    } else {
      txt_(card, 'div', 'v', value || '—');
    }
    idgrid.appendChild(card);
  }
  var targetRef = (D.target && D.target.ref) || 'HEAD';
  var targetHref = (targetRef !== 'HEAD')
    ? (targetUrl + '/tree/' + encRef(targetRef))
    : targetUrl;
  addIdCard(L.label_target || 'Target', targetName, targetHref || null);
  addIdCard(L.label_ref || 'Ref', (D.target && D.target.ref) ? D.target.ref : '—');
  addIdCard(L.label_date || 'Date', (D.target && D.target.date) ? D.target.date : '—');
  if (D.target && D.target.commit) {
    addIdCard(L.label_commit || 'Commit', D.target.commit);
  }

  /* ── Verdict banner (.banner) — CR-03 preserved ── */
  /* bStatus and statusText already computed above (resolveStatus, Task 1 block) */
  var banner = el_('div', 'banner b-' + bStatus);
  var bannerLeft = el_('div', '');
  txt_(bannerLeft, 'div', 'big', statusText);
  if (verdict.summary) {
    txt_(bannerLeft, 'div', 'desc', verdict.summary);
  }
  if (bStatus === 'skip' && D.error && !verdict.summary) {
    txt_(bannerLeft, 'div', 'desc', 'Report generation error: ' + D.error);
  }
  banner.appendChild(bannerLeft);
  var scoreVal = (typeof verdict.score === 'number' && verdict.score !== null) ? verdict.score : null;
  if (scoreVal !== null) {
    var scoreBlock = el_('div', 'score');
    txt_(scoreBlock, 'b', '', String(scoreVal));
    txt_(scoreBlock, 'span', '', 'Risk score');
    banner.appendChild(scoreBlock);
  }
  hero.appendChild(banner);

  /* ── Severity distribution bar ── */
  var distrib = el_('div', 'distrib');
  var distribLbl = el_('div', 'lbl');
  distribLbl.appendChild(document.createTextNode((L.distrib_label || 'Severity distribution') + ' · '));
  txt_(distribLbl, 'b', '', String(total));
  distribLbl.appendChild(document.createTextNode(' ' + (L.distrib_findings || 'findings')));
  distrib.appendChild(distribLbl);
  var bar = el_('div', 'bar');
  bar.id = 'distbar';
  var legend = el_('div', 'barlegend');
  legend.id = 'distlegend';
  if (total === 0) {
    var seg0 = el_('span', '');
    seg0.style.cssText = 'flex:1;background:var(--pass)';
    seg0.title = '0 findings';
    bar.appendChild(seg0);
    txt_(legend, 'span', '', '0 ' + (L.distrib_findings || 'findings'));
  } else {
    ['critical','high','medium','low'].forEach(function(sev) {
      if (!counts[sev]) return;
      var seg = el_('span', '');
      seg.style.cssText = 'flex:' + counts[sev] + ';background:var(--sev-' + sev + ')';
      seg.title = sev + ': ' + counts[sev];
      bar.appendChild(seg);
      var li = el_('span', '');
      var i = el_('i', '');
      i.style.background = 'var(--sev-' + sev + ')';
      li.appendChild(i);
      li.appendChild(document.createTextNode(sev + ' · ' + counts[sev]));
      legend.appendChild(li);
    });
  }
  distrib.appendChild(bar);
  distrib.appendChild(legend);
  hero.appendChild(distrib);

  /* ── Scanner summary cards (UI-04) ── */
  function resolveCardStatus(scannerObj) {
    if (!scannerObj) return 'skip';
    var s = (scannerObj.status || '').toLowerCase();
    return (s === 'pass' || s === 'warn' || s === 'fail') ? s : 'skip';
  }
  function buildCard(icon, name, anchor, metric, sub, status) {
    var a = el_('a', 'scard');
    a.href = anchor;
    var top = el_('div', 'top');
    txt_(top, 'span', 'name', icon + ' ' + name);
    txt_(top, 'span', 'badge b-' + status, status.toUpperCase());
    a.appendChild(top);
    txt_(a, 'div', 'num t-' + status, String(metric));
    txt_(a, 'div', 'sub', sub);
    return a;
  }
  var scannerGrid = el_('div', 'scanners');
  scannerGrid.id = 'scanners';

  /* Semgrep */
  var sgStatus = resolveCardStatus(sc.semgrep);
  var sgMetric = sgStatus === 'skip' ? '—' : String(semFindings.reduce(function(a,g){return a+(g.count||0);},0));
  var sgSub    = sgStatus === 'skip' ? (L.card_skipped || 'skipped') : (semFindings.length + ' ' + (L.card_semgrep_sub || 'rules'));
  scannerGrid.appendChild(buildCard('🔎', 'Semgrep', '#sec-semgrep', sgMetric, sgSub, sgStatus));

  /* Dependencies */
  var depStatus = resolveCardStatus(sc.dependencies);
  var depMetric = depStatus === 'skip' ? '—' : String(depVulns.length);
  var highCount = depVulns.filter(function(v){return v.severity==='high';}).length;
  var depSub    = depStatus === 'skip' ? (L.card_skipped || 'skipped') : ('CVE · ' + highCount + ' ' + (L.card_deps_sub_high || 'high'));
  scannerGrid.appendChild(buildCard('📦', 'Dependencies', '#sec-dependencies', depMetric, depSub, depStatus));

  /* Hadolint */
  var hadoStatus = resolveCardStatus(sc.hadolint);
  var hadoMetric = hadoStatus === 'skip' ? '—' : String(hadoFindings.length);
  var hadoWarn   = hadoFindings.filter(function(f){return f.level==='warning';}).length;
  var hadoSub    = hadoStatus === 'skip' ? (L.card_skipped || 'skipped') : (hadoWarn + ' ' + (L.card_hadolint_sub || 'warnings'));
  scannerGrid.appendChild(buildCard('🐳', 'Hadolint', '#sec-hadolint', hadoMetric, hadoSub, hadoStatus));

  /* VirusTotal */
  var vtStatus = resolveCardStatus(sc.virustotal);
  var vtMetric = vtStatus === 'skip' ? '—' : String((sc.virustotal && sc.virustotal.malicious) || 0);
  var vtSub    = vtStatus === 'skip' ? (L.card_skipped || 'skipped') : (((sc.virustotal && sc.virustotal.engines) || 0) + ' ' + (L.card_vt_sub || 'engines'));
  scannerGrid.appendChild(buildCard('🦠', 'VirusTotal', '#sec-virustotal', vtMetric, vtSub, vtStatus));

  page.appendChild(scannerGrid);

  /* ── Section anchor shells (.module / .mhead / .mbody) ── */
  var SECTIONS = [
    { id:'sec-semgrep',      icon:'🔎', name:'Semgrep',      metaKey:'section_semgrep_meta',  scannerKey:'semgrep' },
    { id:'sec-dependencies', icon:'📦', name:'Dependencies', metaKey:'section_deps_meta',     scannerKey:'dependencies' },
    { id:'sec-hadolint',     icon:'🐳', name:'Hadolint',     metaKey:'section_hadolint_meta', scannerKey:'hadolint' },
    { id:'sec-virustotal',   icon:'🦠', name:'VirusTotal',   metaKey:'section_vt_meta',       scannerKey:'virustotal' }
  ];
  SECTIONS.forEach(function(s) {
    var mod = el_('div', 'module');
    mod.id = s.id;
    var mhead = el_('div', 'mhead');
    txt_(mhead, 'span', 'ttl', s.icon + ' ' + s.name);
    txt_(mhead, 'span', 'meta', L[s.metaKey] || '');
    var secStatus = resolveCardStatus(sc[s.scannerKey] || null);
    txt_(mhead, 'span', 'badge b-' + secStatus, secStatus.toUpperCase());
    mod.appendChild(mhead);
    txt_(mod, 'div', 'mbody', L.section_placeholder || 'Full rendering in Phase 10–11.');
    page.appendChild(mod);
  });

  /* ── Semgrep section rendering (SEM-01..05) ── */
  function pluralPlaces(n, L) {
    /* ru: L.place_few !== L.place_many (3 CLDR forms); en: 2 forms */
    if (L.place_few !== L.place_many) {
      var r10 = n % 10, r100 = n % 100;
      if (r10 === 1 && r100 !== 11)                            return n + ' ' + L.place_one;
      if (r10 >= 2 && r10 <= 4 && (r100 < 10 || r100 >= 20)) return n + ' ' + L.place_few;
      return n + ' ' + L.place_many;
    }
    return n + ' ' + (n === 1 ? L.place_one : L.place_many);
  }

  function renderSemgrep(semFindings, activeSev, q, D, L) {
    var mod = document.getElementById('sec-semgrep');
    if (!mod) return;
    var body = mod.querySelector('.mbody');
    if (!body) return;

    var semStatus = (D.scanners && D.scanners.semgrep && D.scanners.semgrep.status) || '';
    var isSkipped = (semStatus === 'skipped' || semStatus === 'error');

    /* Locate or create #semgrep-list (persists across re-renders) */
    var list = document.getElementById('semgrep-list');
    if (!list) {
      list = el_('div', '');
      list.id = 'semgrep-list';
    }

    /* ── State (c): skipped / error ── */
    if (isSkipped) {
      body.textContent = '';
      var emptyC = el_('div', 'empty');
      var iconC = el_('span', 'ok');
      iconC.style.color = 'var(--warn)';  /* warn tone for skipped/error glyph */
      iconC.textContent = L.sem_skipped_icon || '⚠';
      emptyC.appendChild(iconC);
      emptyC.appendChild(document.createTextNode(L.sem_skipped || 'Semgrep did not run'));
      body.appendChild(emptyC);
      return;
    }

    /* ── State (a): clean scan / 0 findings ── */
    if (semFindings.length === 0) {
      body.textContent = '';
      var emptyA = el_('div', 'empty');
      var iconA = el_('span', 'ok');
      iconA.textContent = L.sem_no_findings_icon || '✓';
      emptyA.appendChild(iconA);
      emptyA.appendChild(document.createTextNode(L.sem_no_findings || 'No findings'));
      body.appendChild(emptyA);
      var rawA = el_('div', 'rawlinks');
      var aJson = el_('a', '');
      aJson.href = 'raw/semgrep.json';
      aJson.target = '_blank';
      aJson.rel = 'noopener noreferrer';
      aJson.textContent = L.sem_artifact_json || '⤓ semgrep.json';
      rawA.appendChild(aJson);
      body.appendChild(rawA);
      return;
    }

    /* ── Toolbar (built ONCE — Pitfall 2: guard prevents rebuild on re-render) ── */
    if (!body.querySelector('.toolbar') && !isSkipped) {
      var toolbar = el_('div', 'toolbar');

      /* Search input with SVG icon */
      var searchWrap = el_('div', 'search');
      var inp = el_('input', '');
      inp.type = 'text';
      inp.placeholder = L.sem_search_placeholder || 'Search rule, file, message…';
      inp.setAttribute('autocomplete', 'off');
      var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      svg.setAttribute('width', '14');
      svg.setAttribute('height', '14');
      svg.setAttribute('viewBox', '0 0 24 24');
      svg.setAttribute('fill', 'none');
      svg.setAttribute('stroke', 'currentColor');
      svg.setAttribute('stroke-width', '2');
      var circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', '11');
      circle.setAttribute('cy', '11');
      circle.setAttribute('r', '8');
      var line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', '21');
      line.setAttribute('y1', '21');
      line.setAttribute('x2', '16.65');
      line.setAttribute('y2', '16.65');
      svg.appendChild(circle);
      svg.appendChild(line);
      searchWrap.appendChild(svg);
      searchWrap.appendChild(inp);
      toolbar.appendChild(searchWrap);

      /* Severity chips: All / High / Medium / Low */
      var chipDefs = [
        { sev: 'all',    label: L.sem_chip_all    || 'All',    id: 'c-all',    dot: false },
        { sev: 'high',   label: L.sem_chip_high   || 'High',   id: 'c-high',   dot: true  },
        { sev: 'medium', label: L.sem_chip_medium || 'Medium', id: 'c-medium', dot: true  },
        { sev: 'low',    label: L.sem_chip_low    || 'Low',    id: 'c-low',    dot: true  }
      ];
      var chips = [];
      chipDefs.forEach(function(def) {
        var chip = el_('button', 'chip');
        chip.dataset.sev = def.sev;
        if (def.dot) {
          var dot = el_('i', '');
          dot.style.background = 'var(--sev-' + def.sev + ')';
          chip.appendChild(dot);
        }
        chip.appendChild(document.createTextNode(def.label));
        var cspan = el_('span', 'c');
        cspan.id = def.id;
        cspan.textContent = '0';
        chip.appendChild(cspan);
        if (def.sev === 'all') chip.classList.add('on');
        chips.push(chip);
        toolbar.appendChild(chip);
      });

      /* Chip onclick — remove .on from all, add to clicked, re-render (mirrors themebtn pattern) */
      chips.forEach(function(chip) {
        chip.onclick = function() {
          chips.forEach(function(c) { c.classList.remove('on'); });
          this.classList.add('on');
          _semActiveSev = this.dataset.sev;
          renderSemgrep(semFindings, _semActiveSev, _semQ, D, L);
        };
      });

      /* Search oninput */
      inp.oninput = function() {
        _semQ = this.value.toLowerCase().trim();
        renderSemgrep(semFindings, _semActiveSev, _semQ, D, L);
      };

      /* Insert toolbar before list in body */
      body.appendChild(toolbar);

      /* Chip count computation (D-07: total locations per severity — fixed, not filtered) */
      var cAll = 0, cHigh = 0, cMed = 0, cLow = 0;
      semFindings.forEach(function(g) {
        cAll += (g.count || 0);
        if (g.severity === 'high')   cHigh += (g.count || 0);
        if (g.severity === 'medium') cMed  += (g.count || 0);
        if (g.severity === 'low')    cLow  += (g.count || 0);
      });
      var allSpan = document.getElementById('c-all');
      var hiSpan  = document.getElementById('c-high');
      var medSpan = document.getElementById('c-medium');
      var lowSpan = document.getElementById('c-low');
      if (allSpan) allSpan.textContent = String(cAll);
      if (hiSpan)  hiSpan.textContent  = String(cHigh);
      if (medSpan) medSpan.textContent = String(cMed);
      if (lowSpan) lowSpan.textContent = String(cLow);
    }

    /* Filtering (preserve pre-sorted order — do NOT re-sort) */
    var filtered = semFindings.filter(function(g) {
      if (activeSev !== 'all' && g.severity !== activeSev) return false;
      if (q) {
        var hay = (g.rule + ' ' + g.message + ' ' +
                   g.locations.map(function(l) { return l.path; }).join(' ')).toLowerCase();
        if (hay.indexOf(q) === -1) return false;
      }
      return true;
    });

    /* Ensure list is in DOM (toolbar built in Task 2 guard inserts it) */
    if (!list.parentNode) {
      body.appendChild(list);
    }
    list.textContent = '';  /* clear previous render (D-05 reset-to-collapsed) */

    /* ── State (b): filter miss — message inside list, toolbar stays ── */
    if (filtered.length === 0) {
      txt_(list, 'div', 'empty', L.sem_filter_empty || 'No matches for filter');
      return;
    }

    /* ── Normal: render one accordion per group ── */
    filtered.forEach(function(g) {
      var det = el_('details', 'fg');
      var sum = el_('summary', '');
      txt_(sum, 'span', 'caret', '▶');
      var sev = el_('span', 'sevtag s-' + (g.severity || 'low'));
      sev.textContent = g.severity || 'low';  /* controlled enum — safe concat */
      sum.appendChild(sev);
      txt_(sum, 'span', 'rule', g.rule);
      txt_(sum, 'span', 'cnt', pluralPlaces(g.count, L));  /* g.count per DATA-04 */
      det.appendChild(sum);

      /* Finding body */
      var fbody = el_('div', 'fg-body');
      txt_(fbody, 'div', 'fg-msg', g.message);

      /* Semgrep docs link (T-10-03: .href property, rel=noopener noreferrer) */
      var docLink = el_('a', 'fg-doc');
      docLink.href = 'https://semgrep.dev/r/' + g.check_id;
      docLink.target = '_blank';
      docLink.rel = 'noopener noreferrer';
      docLink.textContent = (L.sem_docs_link || '↗ Semgrep docs · ') + g.check_id;
      fbody.appendChild(docLink);

      /* Location list (D-01: strip /src/, link to github blob line) */
      var ul = el_('ul', 'loclist');
      var base = ghBlobBase();
      var showCount = Math.min(5, g.locations.length);
      g.locations.slice(0, showCount).forEach(function(loc) {
        var li = el_('li', '');
        var a = el_('a', 'ln');
        var clean = loc.path.replace(/^\/src\//, '');
        a.href = base + '/' + clean + '#L' + loc.line;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        a.textContent = clean + ':' + loc.line;
        li.appendChild(a);
        ul.appendChild(li);
      });

      /* One-way "show N more" expander (D-06, SEM-03) */
      if (g.locations.length > 5) {
        var rest = g.locations.length - 5;
        var moreLi = el_('li', '');
        var moreBtn = el_('button', 'more');
        moreBtn.type = 'button';
        moreBtn.textContent = (L.sem_show_more || '+ show {N} more').replace('{N}', String(rest));
        (function(locs, ulEl, baseUrl, mLi, mBtn) {
          mBtn.onclick = function() {
            locs.slice(5).forEach(function(loc) {
              var li = el_('li', '');
              var a = el_('a', 'ln');
              var clean = loc.path.replace(/^\/src\//, '');
              a.href = baseUrl + '/' + clean + '#L' + loc.line;
              a.target = '_blank';
              a.rel = 'noopener noreferrer';
              a.textContent = clean + ':' + loc.line;
              li.appendChild(a);
              ulEl.insertBefore(li, mLi);
            });
            ulEl.removeChild(mLi);
          };
        })(g.locations, ul, base, moreLi, moreBtn);
        moreLi.appendChild(moreBtn);
        ul.appendChild(moreLi);
      }

      fbody.appendChild(ul);
      det.appendChild(fbody);
      list.appendChild(det);
    });
  }

  /* ─────────────────────────────────────────────────────────────────────────
     renderDeps(depVulns, activeSev, q, D, L)
     SEC-01: Dependencies CVE table — severity-sorted, NVD/GHSA links, CVSS
     Clones renderSemgrep() structure (three states, toolbar-once guard, show-more)
  ───────────────────────────────────────────────────────────────────────────── */
  function renderDeps(depVulns, activeSev, q, D, L) {
    var mod = document.getElementById('sec-dependencies');
    if (!mod) return;
    var body = mod.querySelector('.mbody');
    if (!body) return;

    var depStatus = (D.scanners && D.scanners.dependencies && D.scanners.dependencies.status) || '';
    var isSkipped = (depStatus === 'skipped' || depStatus === 'error');
    var secrets = (D.scanners && D.scanners.dependencies && D.scanners.dependencies.secrets) || [];

    /* Locate or create #deps-list (persists across re-renders) */
    var list = document.getElementById('deps-list');
    if (!list) {
      list = el_('div', '');
      list.id = 'deps-list';
    }

    /* ── State (c): skipped / error ── */
    if (isSkipped) {
      body.textContent = '';
      var emptyC = el_('div', 'empty');
      var iconC = el_('span', 'ok');
      iconC.style.color = depStatus === 'error' ? 'var(--warn)' : 'var(--skip)';
      iconC.textContent = L.dep_skipped_icon || '⚠';
      emptyC.appendChild(iconC);
      emptyC.appendChild(document.createTextNode(L.dep_skipped || 'Dependency scan skipped'));
      body.appendChild(emptyC);
      return;
    }

    /* ── Scanner contribution summary line (D-11) — mirrors hadolint metaEl pattern ── */
    /* Re-render-safe: reuse a dedicated .meta.src-summary element, mutate textContent in place */
    var mhead = mod.querySelector('.mhead');
    var src = D.scanners && D.scanners.dependencies && D.scanners.dependencies.sources;
    if (src && mhead) {
      /* D-11 semantics (CR-01): merged = deduplicated union (total unique CVEs).
       * found-by-both (intersection) = trivy + grype - merged, clamped to >= 0.
       * "unique" token = the dedup union total (merged). */
      var trivyN  = src.trivy  || 0;
      var grypeN  = src.grype  || 0;
      var mergedN = src.merged || 0;
      var both    = trivyN + grypeN - mergedN;
      if (both < 0) { both = 0; }
      var summaryText;
      if (trivyN === 0 && grypeN === 0 && mergedN > 0) {
        /* Cache hit: per-scanner pre-dedup counts are unknowable. Degrade to an
         * honest reduced form showing only the dedup total — never a fabricated
         * overlap or a negative count. */
        summaryText = (L.dep_sources_summary_cached || '{MERGED} unique')
          .replace('{MERGED}', String(mergedN));
      } else {
        summaryText = (L.dep_sources_summary || 'Trivy {TRIVY} · Grype {GRYPE} · {BOTH} found by both · {UNIQUE} unique')
          .replace('{TRIVY}',  String(trivyN))
          .replace('{GRYPE}',  String(grypeN))
          .replace('{BOTH}',   String(both))
          .replace('{UNIQUE}', String(mergedN));
      }
      var sumEl = mhead.querySelector('.meta.src-summary');
      if (!sumEl) { sumEl = el_('span', 'meta src-summary'); mhead.appendChild(sumEl); }
      sumEl.textContent = summaryText;
    }

    /* ── GRYPE-04: badge override + warn-banner ── */
    var depWarn = D.scanners && D.scanners.dependencies && D.scanners.dependencies.warning;
    var displayStatus = resolveStatus(depStatus);
    if (depWarn && displayStatus === 'pass') {
      displayStatus = 'inconclusive';
      var mhead2 = mod.querySelector('.mhead');
      var badgeEl = mhead2 && mhead2.querySelector('.badge');
      if (badgeEl) {
        badgeEl.className = 'badge inconclusive';
        badgeEl.textContent = L.badge_inconclusive || 'INCONCLUSIVE';
      }
    }

    /* ── State (a): clean scan / 0 vulns AND 0 secrets ── */
    if (depVulns.length === 0 && secrets.length === 0 && !depWarn) {
      body.textContent = '';
      var emptyA = el_('div', 'empty');
      var iconA = el_('span', 'ok');
      iconA.textContent = L.dep_no_vulns_icon || '✓';
      emptyA.appendChild(iconA);
      emptyA.appendChild(document.createTextNode(L.dep_no_vulns || 'No critical issues'));
      body.appendChild(emptyA);
      var rawA = el_('div', 'rawlinks');
      var aMerged = el_('a', '');
      aMerged.href = 'raw/vulns_merged.json';
      aMerged.target = '_blank';
      aMerged.rel = 'noopener noreferrer';
      aMerged.textContent = L.dep_artifact_merged || '⤓ vulns_merged.json';
      rawA.appendChild(aMerged);
      var aTrivy = el_('a', '');
      aTrivy.href = 'raw/trivy_fs.json';
      aTrivy.target = '_blank';
      aTrivy.rel = 'noopener noreferrer';
      aTrivy.textContent = L.dep_artifact_trivy || '⤓ trivy_fs.json';
      rawA.appendChild(aTrivy);
      var aGrype = el_('a', '');
      aGrype.href = 'raw/grype.json';
      aGrype.target = '_blank';
      aGrype.rel = 'noopener noreferrer';
      aGrype.textContent = L.dep_artifact_grype || '⤓ grype.json';
      rawA.appendChild(aGrype);
      body.appendChild(rawA);
      return;
    }

    /* ── Clear Phase-9 placeholder on first render (before toolbar exists) ── */
    if (!body.querySelector('.toolbar')) { body.textContent = ''; }

    /* ── GRYPE-04 warn-banner (D-07): built ONCE after the placeholder-clear so it
       survives, prepended as the first child of body so it sits above secrets/CVE/
       no-CVE content. Id-guard (WR-01) prevents duplicate banners on chip/search
       re-render. The badge override above already flips the header to INCONCLUSIVE. */
    if (depWarn && !document.getElementById('deps-warn-banner')) {
      var wDiv  = el_('div', 'warn-banner');
      wDiv.id = 'deps-warn-banner';
      var wIcon = el_('span', 'wb-icon');
      wIcon.textContent = '⚠';
      var wText = el_('div', 'wb-text');
      var wHead = el_('div', 'whead');
      wHead.textContent = L.dep_warn_head || 'Dependency scan inconclusive';
      var wBody = el_('div', 'wbody');
      wBody.textContent = L.dep_warn_body || 'Manifests found but 0 packages were cataloged — likely a missing lockfile. CVE results cannot be treated as a clean pass.';
      wText.appendChild(wHead);
      wText.appendChild(wBody);
      wDiv.appendChild(wIcon);
      wDiv.appendChild(wText);
      if (body.firstChild) { body.insertBefore(wDiv, body.firstChild); }
      else { body.appendChild(wDiv); }
    }

    /* ── Secrets block (built ONCE — guard by id; rendered above CVE area) ── */
    if (secrets.length > 0 && !document.getElementById('deps-secrets-block')) {
      var SEV_RANK_SEC = {critical:4, high:3, medium:2, low:1};
      var sortedSec = secrets.slice().sort(function(a, b) {
        return (SEV_RANK_SEC[b.severity] || 0) - (SEV_RANK_SEC[a.severity] || 0);
      });
      var secBlock = el_('div', '');
      secBlock.id = 'deps-secrets-block';
      secBlock.style.cssText = 'margin-bottom:.9rem';

      /* Heading */
      var secHead = el_('div', '');
      secHead.style.cssText = 'font-size:.78rem;font-weight:600;color:var(--text);margin-bottom:.45rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace';
      secHead.textContent = (L.dep_secrets_title || 'Secrets detected') + ' (' + String(secrets.length) + ')';
      secBlock.appendChild(secHead);

      /* Table */
      var secWrap = el_('div', 'tbl-wrap');
      var secTbl = el_('table', 'tbl-fixed');
      /* Pin the Location column (col 4) to 280px: table-layout:fixed ignores
         td max-width, so a <colgroup> width is the correct way to cap it. */
      var secCg = el_('colgroup', '');
      for (var sci = 0; sci < 4; sci++) {
        var sCol = el_('col', '');
        if (sci === 3) { sCol.style.width = '280px'; }
        secCg.appendChild(sCol);
      }
      secTbl.appendChild(secCg);
      var secThead = el_('thead', '');
      var secHdr = el_('tr', '');
      var secCols = [
        L.dep_th_sev         || 'Severity',
        L.dep_secrets_type   || 'Type',
        L.dep_secrets_rule   || 'Rule',
        L.dep_secrets_loc    || 'Location'
      ];
      secCols.forEach(function(h) { txt_(secHdr, 'th', '', h); });
      secThead.appendChild(secHdr);
      secTbl.appendChild(secThead);

      var secTbody = el_('tbody', '');
      sortedSec.forEach(function(s) {
        var tr = el_('tr', '');

        /* Col 1: Severity sevtag — controlled enum with 'low' fallback */
        var tdSev = el_('td', '');
        var sevTag = el_('span', 'sevtag s-' + (s.severity || 'low'));
        sevTag.textContent = s.severity || 'low';
        tdSev.appendChild(sevTag);
        tr.appendChild(tdSev);

        /* Col 2: Type (category || rule) */
        var tdType = el_('td', '');
        tdType.textContent = s.category || s.rule || '';
        tr.appendChild(tdType);

        /* Col 3: Rule ID (mono) */
        var tdRule = el_('td', 'mono-cell');
        tdRule.textContent = s.rule || '';
        tr.appendChild(tdRule);

        /* Col 4: Location file:line — GitHub blob link (T-08-07, T-10-03/04) */
        var tdLoc = el_('td', 'mono-cell path-cell');
        var secBase = ghBlobBase();
        var secFile = s.file || '';
        var secLine = s.line != null ? String(s.line) : '';
        tdLoc.title = secFile + ':' + secLine;
        if (secFile) {
          var secA = el_('a', '');
          secA.href = secBase + '/' + secFile + '#L' + secLine;
          secA.target = '_blank';
          secA.rel = 'noopener noreferrer';
          secA.textContent = secFile + ':' + secLine;
          tdLoc.appendChild(secA);
        } else {
          tdLoc.textContent = secFile + ':' + secLine;
        }
        tr.appendChild(tdLoc);

        secTbody.appendChild(tr);
      });
      secTbl.appendChild(secTbody);
      secWrap.appendChild(secTbl);
      secBlock.appendChild(secWrap);
      body.appendChild(secBlock);
    }

    /* ── State (a2): secrets present but 0 CVEs — show "No CVEs found" + raw links ── */
    if (depVulns.length === 0) {
      /* CR-01: when inconclusive (depWarn), SUPPRESS the green "✓ No CVEs found"
         clean-pass notice — the warn-banner above is the message, and a green ✓
         alongside it would contradict D-03 (inconclusive must never read as clean).
         Raw links still render so the operator can inspect the underlying JSON. */
      if (!depWarn && !document.getElementById('deps-no-cve-notice')) {
        var noCveDiv = el_('div', 'empty');
        noCveDiv.id = 'deps-no-cve-notice';
        var noCveIcon = el_('span', 'ok');
        noCveIcon.textContent = '✓';
        noCveDiv.appendChild(noCveIcon);
        noCveDiv.appendChild(document.createTextNode(L.dep_no_cve || 'No CVEs found'));
        body.appendChild(noCveDiv);
      }
      if (!document.getElementById('deps-raw-links')) {
        var rawA2 = el_('div', 'rawlinks');
        rawA2.id = 'deps-raw-links';
        var aMerged2 = el_('a', '');
        aMerged2.href = 'raw/vulns_merged.json';
        aMerged2.target = '_blank';
        aMerged2.rel = 'noopener noreferrer';
        aMerged2.textContent = L.dep_artifact_merged || '⤓ vulns_merged.json';
        rawA2.appendChild(aMerged2);
        var aTrivy2 = el_('a', '');
        aTrivy2.href = 'raw/trivy_fs.json';
        aTrivy2.target = '_blank';
        aTrivy2.rel = 'noopener noreferrer';
        aTrivy2.textContent = L.dep_artifact_trivy || '⤓ trivy_fs.json';
        rawA2.appendChild(aTrivy2);
        var aGrype2 = el_('a', '');
        aGrype2.href = 'raw/grype.json';
        aGrype2.target = '_blank';
        aGrype2.rel = 'noopener noreferrer';
        aGrype2.textContent = L.dep_artifact_grype || '⤓ grype.json';
        rawA2.appendChild(aGrype2);
        body.appendChild(rawA2);
      }
      return;
    }

    /* ── Toolbar (built ONCE — guard prevents rebuild on re-render) ── */
    if (!body.querySelector('.toolbar') && !isSkipped) {
      var toolbar = el_('div', 'toolbar');

      /* Search input with SVG icon */
      var searchWrap = el_('div', 'search');
      var inp = el_('input', '');
      inp.type = 'text';
      inp.placeholder = L.dep_search_placeholder || 'Search CVE, package, title…';
      inp.setAttribute('autocomplete', 'off');
      var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      svg.setAttribute('width', '14');
      svg.setAttribute('height', '14');
      svg.setAttribute('viewBox', '0 0 24 24');
      svg.setAttribute('fill', 'none');
      svg.setAttribute('stroke', 'currentColor');
      svg.setAttribute('stroke-width', '2');
      var circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', '11');
      circle.setAttribute('cy', '11');
      circle.setAttribute('r', '8');
      var line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', '21');
      line.setAttribute('y1', '21');
      line.setAttribute('x2', '16.65');
      line.setAttribute('y2', '16.65');
      svg.appendChild(circle);
      svg.appendChild(line);
      searchWrap.appendChild(svg);
      searchWrap.appendChild(inp);
      toolbar.appendChild(searchWrap);

      /* Severity chips: All / Critical / High / Medium / Low (dep-c-* ids — no collision with c-*) */
      var SEV_RANK_CFG = {critical:4, high:3, medium:2, low:1};
      var depCritCount = depVulns.filter(function(v){ return v.severity === 'critical'; }).length;
      var depHighCount  = depVulns.filter(function(v){ return v.severity === 'high'; }).length;
      var depMedCount   = depVulns.filter(function(v){ return v.severity === 'medium'; }).length;
      var depLowCount   = depVulns.filter(function(v){ return v.severity === 'low'; }).length;
      var depChipDefs = [
        { sev: 'all',      label: L.dep_chip_all      || 'All',      id: 'dep-c-all',      dot: false, count: depVulns.length },
        { sev: 'critical', label: L.dep_chip_critical  || 'Critical', id: 'dep-c-critical', dot: true,  count: depCritCount },
        { sev: 'high',     label: L.dep_chip_high      || 'High',     id: 'dep-c-high',     dot: true,  count: depHighCount },
        { sev: 'medium',   label: L.dep_chip_medium    || 'Medium',   id: 'dep-c-medium',   dot: true,  count: depMedCount },
        { sev: 'low',      label: L.dep_chip_low       || 'Low',      id: 'dep-c-low',      dot: true,  count: depLowCount }
      ];
      var depChips = [];
      depChipDefs.forEach(function(def) {
        var chip = el_('button', 'chip');
        chip.dataset.sev = def.sev;
        if (def.dot) {
          var dot = el_('i', '');
          dot.style.background = 'var(--sev-' + def.sev + ')';
          chip.appendChild(dot);
        }
        chip.appendChild(document.createTextNode(def.label));
        var cspan = el_('span', 'c');
        cspan.id = def.id;
        cspan.textContent = String(def.count);
        chip.appendChild(cspan);
        if (def.sev === 'all') chip.classList.add('on');
        depChips.push(chip);
        toolbar.appendChild(chip);
      });

      /* Chip onclick */
      depChips.forEach(function(chip) {
        chip.onclick = function() {
          depChips.forEach(function(c) { c.classList.remove('on'); });
          this.classList.add('on');
          _depActiveSev = this.dataset.sev;
          renderDeps(depVulns, _depActiveSev, _depQ, D, L);
        };
      });

      /* Search oninput */
      inp.oninput = function() {
        _depQ = this.value.toLowerCase().trim();
        renderDeps(depVulns, _depActiveSev, _depQ, D, L);
      };

      body.appendChild(toolbar);
    }

    /* Severity sort safety net (D-11) */
    var SEV_RANK = {critical:4, high:3, medium:2, low:1};
    var sorted = depVulns.slice().sort(function(a, b) {
      return (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0);
    });

    /* Filter by active severity + search query */
    var filtered = sorted.filter(function(v) {
      if (activeSev !== 'all' && v.severity !== activeSev) return false;
      if (q) {
        var hay = ((v.id || '') + ' ' + (v.pkg || '') + ' ' + (v.title || '') + ' ' + (v.source || '')).toLowerCase();
        if (hay.indexOf(q) === -1) return false;
      }
      return true;
    });

    /* Ensure list is in DOM */
    if (!list.parentNode) {
      body.appendChild(list);
    }
    list.textContent = '';  /* clear previous render */

    /* ── State (b): filter miss — message inside list, toolbar stays ── */
    if (filtered.length === 0) {
      txt_(list, 'div', 'empty', L.dep_filter_empty || 'No matches');
      return;
    }

    /* ── Table render ── */
    var wrap = el_('div', 'tbl-wrap');
    var tbl  = el_('table', '');
    var thead = el_('thead', '');
    var hdr  = el_('tr', '');
    var depHeaders = [
      L.dep_th_sev   || 'Severity',
      L.dep_th_cve   || 'CVE / ID',
      L.dep_th_pkg   || 'Package',
      L.dep_th_ver   || 'Version',
      L.dep_th_fixed || 'Fixed in',
      L.dep_th_cvss  || 'CVSS',
      L.dep_th_src   || 'Source'
    ];
    depHeaders.forEach(function(h) {
      txt_(hdr, 'th', '', h);
    });
    thead.appendChild(hdr);
    tbl.appendChild(thead);

    var tbody = el_('tbody', '');

    /* First-20 cap; build all rows first, then slice */
    var visibleRows = [];
    var hiddenRows  = [];
    filtered.forEach(function(v, idx) {
      var tr = el_('tr', '');

      /* Col 1: Severity tag */
      var tdSev = el_('td', '');
      var sevTag = el_('span', 'sevtag s-' + (v.severity || 'low'));
      sevTag.textContent = v.severity || 'low';  /* controlled enum — safe concat */
      tdSev.appendChild(sevTag);
      tr.appendChild(tdSev);

      /* Col 2: CVE / ID — NVD/GHSA link or plain text (D-06, T-10-03/04) */
      var tdCve = el_('td', 'mono-cell');
      (function(id) {
        if (id && id.indexOf('CVE-') === 0) {
          var a = el_('a', '');
          a.href = 'https://nvd.nist.gov/vuln/detail/' + id;
          a.target = '_blank';
          a.rel = 'noopener noreferrer';
          a.textContent = id;
          tdCve.appendChild(a);
        } else if (id && id.indexOf('GHSA-') === 0) {
          var a = el_('a', '');
          a.href = 'https://github.com/advisories/' + id;
          a.target = '_blank';
          a.rel = 'noopener noreferrer';
          a.textContent = id;
          tdCve.appendChild(a);
        } else {
          tdCve.appendChild(document.createTextNode(id || ''));
        }
      })(v.id);
      tr.appendChild(tdCve);

      /* Col 3: Package (mono) */
      var tdPkg = el_('td', 'mono-cell');
      tdPkg.textContent = v.pkg || '';
      tr.appendChild(tdPkg);

      /* Col 4: Version (mono, muted) */
      var tdVer = el_('td', '');
      tdVer.style.fontFamily = 'ui-monospace,SFMono-Regular,Menlo,monospace';
      tdVer.style.color = 'var(--muted)';
      tdVer.textContent = v.version || '';
      tr.appendChild(tdVer);

      /* Col 5: Fixed-in (fix-cell = green mono) */
      var tdFix = el_('td', 'fix-cell');
      tdFix.textContent = v.fixed || '—';
      tr.appendChild(tdFix);

      /* Col 6: CVSS (null guard — Pitfall 6) */
      var tdCvss = el_('td', '');
      tdCvss.style.fontFamily = 'ui-monospace,SFMono-Regular,Menlo,monospace';
      tdCvss.style.color = 'var(--text)';
      tdCvss.textContent = typeof v.cvss === 'number' ? v.cvss.toFixed(1) : '—';
      tr.appendChild(tdCvss);

      /* Col 7: Source badge */
      var tdSrc = el_('td', '');
      var pill  = el_('span', 'src-pill' + (v.source === 'Trivy + Grype' ? ' src-both' : ''));
      pill.textContent = v.source || '';
      tdSrc.appendChild(pill);
      tr.appendChild(tdSrc);

      if (idx < 20) {
        visibleRows.push(tr);
      } else {
        hiddenRows.push(tr);
      }
    });

    visibleRows.forEach(function(tr) { tbody.appendChild(tr); });
    tbl.appendChild(tbody);
    wrap.appendChild(tbl);
    list.appendChild(wrap);

    /* First-20 + one-way show-more (D-05) */
    if (hiddenRows.length > 0) {
      var moreBtn = el_('button', '');
      moreBtn.type = 'button';
      moreBtn.style.cssText = 'color:var(--accent);cursor:pointer;font-size:.74rem;padding:.35rem .5rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;' + 'background:none;border:none;';
      moreBtn.textContent = (L.dep_show_more || '+ show {N} more').replace('{N}', String(hiddenRows.length));
      (function(rows, tbodyEl, btn) {
        btn.onclick = function() {
          rows.forEach(function(tr) { tbodyEl.appendChild(tr); });
          btn.parentNode.removeChild(btn);
        };
      })(hiddenRows, tbody, moreBtn);
      list.appendChild(moreBtn);
    }
  }

  /* ─────────────────────────────────────────────────────────────────────────
     renderHadolint(hadoFindings, activeLevel, q, D, L)
     SEC-02: Hadolint Level/Rule/Location/Message table, level chips, three-count meta
     Clones renderDeps/renderSemgrep structure
  ───────────────────────────────────────────────────────────────────────────── */
  function renderHadolint(hadoFindings, activeLevel, q, D, L) {
    var mod = document.getElementById('sec-hadolint');
    if (!mod) return;
    var body = mod.querySelector('.mbody');
    if (!body) return;

    var hadoStatus = (D.scanners && D.scanners.hadolint && D.scanners.hadolint.status) || '';
    var isSkipped = (hadoStatus === 'skipped' || hadoStatus === 'skipped_no_docker' || hadoStatus === 'error');

    /* Locate or create #hado-list */
    var list = document.getElementById('hado-list');
    if (!list) {
      list = el_('div', '');
      list.id = 'hado-list';
    }

    /* ── Three-count meta (D-07) — derive from findings, never shell counters (Pitfall 7) ── */
    var hadoErrors   = hadoFindings.filter(function(f) { return f.level === 'error'; }).length;
    var hadoWarnings = hadoFindings.filter(function(f) { return f.level === 'warning'; }).length;
    var hadoInfo     = hadoFindings.filter(function(f) { return f.level !== 'error' && f.level !== 'warning'; }).length;
    var metaEl = mod.querySelector('.mhead .meta');
    if (metaEl && hadoFindings.length > 0) {
      metaEl.textContent = (L.hado_meta_errors || '{N} errors').replace('{N}', String(hadoErrors))
        + ' · '
        + (L.hado_meta_warnings || '{N} warnings').replace('{N}', String(hadoWarnings))
        + ' · '
        + (L.hado_meta_info || '{N} info').replace('{N}', String(hadoInfo));
    }

    /* ── State (c): skipped / no Dockerfile ── */
    if (isSkipped) {
      body.textContent = '';
      var emptyC = el_('div', 'empty');
      var iconC = el_('span', 'ok');
      iconC.style.color = hadoStatus === 'error' ? 'var(--warn)' : 'var(--skip)';
      iconC.textContent = L.hado_skipped_icon || '⚠';
      emptyC.appendChild(iconC);
      emptyC.appendChild(document.createTextNode(L.hado_skipped || 'No Dockerfile found'));
      body.appendChild(emptyC);
      return;
    }

    /* ── State (a): clean scan / 0 findings ── */
    if (hadoFindings.length === 0) {
      body.textContent = '';
      var emptyA = el_('div', 'empty');
      var iconA = el_('span', 'ok');
      iconA.textContent = L.hado_no_findings_icon || '✓';
      emptyA.appendChild(iconA);
      emptyA.appendChild(document.createTextNode(L.hado_no_findings || 'No issues'));
      body.appendChild(emptyA);
      var rawA = el_('div', 'rawlinks');
      var aJson = el_('a', '');
      aJson.href = 'raw/hadolint.json';
      aJson.target = '_blank';
      aJson.rel = 'noopener noreferrer';
      aJson.textContent = L.hado_artifact || '⤓ hadolint.json';
      rawA.appendChild(aJson);
      body.appendChild(rawA);
      return;
    }

    /* ── Clear Phase-9 placeholder on first render (before toolbar exists) ── */
    if (!body.querySelector('.toolbar')) { body.textContent = ''; }

    /* ── Toolbar (built ONCE) ── */
    if (!body.querySelector('.toolbar') && !isSkipped) {
      var toolbar = el_('div', 'toolbar');

      /* Search input with SVG icon */
      var searchWrap = el_('div', 'search');
      var inp = el_('input', '');
      inp.type = 'text';
      inp.placeholder = L.hado_search_placeholder || 'Search rule, message…';
      inp.setAttribute('autocomplete', 'off');
      var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      svg.setAttribute('width', '14');
      svg.setAttribute('height', '14');
      svg.setAttribute('viewBox', '0 0 24 24');
      svg.setAttribute('fill', 'none');
      svg.setAttribute('stroke', 'currentColor');
      svg.setAttribute('stroke-width', '2');
      var circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', '11');
      circle.setAttribute('cy', '11');
      circle.setAttribute('r', '8');
      var line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', '21');
      line.setAttribute('y1', '21');
      line.setAttribute('x2', '16.65');
      line.setAttribute('y2', '16.65');
      svg.appendChild(circle);
      svg.appendChild(line);
      searchWrap.appendChild(svg);
      searchWrap.appendChild(inp);
      toolbar.appendChild(searchWrap);

      /* Level chips: All / Error / Warning / Info (hado-c-* ids) */
      var hadoErrCount  = hadoFindings.filter(function(f){ return f.level === 'error'; }).length;
      var hadoWarnCount = hadoFindings.filter(function(f){ return f.level === 'warning'; }).length;
      var hadoInfoCount = hadoFindings.filter(function(f){ return f.level !== 'error' && f.level !== 'warning'; }).length;
      var hadoChipDefs = [
        { level: 'all',     label: L.hado_chip_all     || 'All',     id: 'hado-c-all',     dot: false, count: hadoFindings.length },
        { level: 'error',   label: L.hado_chip_error   || 'Error',   id: 'hado-c-error',   dot: true,  dotSev: 'critical', count: hadoErrCount },
        { level: 'warning', label: L.hado_chip_warning || 'Warning', id: 'hado-c-warning', dot: true,  dotSev: 'medium',   count: hadoWarnCount },
        { level: 'info',    label: L.hado_chip_info    || 'Info',    id: 'hado-c-info',    dot: true,  dotSev: 'low',      count: hadoInfoCount }
      ];
      var hadoChips = [];
      hadoChipDefs.forEach(function(def) {
        var chip = el_('button', 'chip');
        chip.dataset.level = def.level;
        if (def.dot) {
          var dot = el_('i', '');
          dot.style.background = 'var(--sev-' + def.dotSev + ')';
          chip.appendChild(dot);
        }
        chip.appendChild(document.createTextNode(def.label));
        var cspan = el_('span', 'c');
        cspan.id = def.id;
        cspan.textContent = String(def.count);
        chip.appendChild(cspan);
        if (def.level === 'all') chip.classList.add('on');
        hadoChips.push(chip);
        toolbar.appendChild(chip);
      });

      /* Chip onclick */
      hadoChips.forEach(function(chip) {
        chip.onclick = function() {
          hadoChips.forEach(function(c) { c.classList.remove('on'); });
          this.classList.add('on');
          _hadoActiveLevel = this.dataset.level;
          renderHadolint(hadoFindings, _hadoActiveLevel, _hadoQ, D, L);
        };
      });

      /* Search oninput */
      inp.oninput = function() {
        _hadoQ = this.value.toLowerCase().trim();
        renderHadolint(hadoFindings, _hadoActiveLevel, _hadoQ, D, L);
      };

      body.appendChild(toolbar);
    }

    /* Level → sevtag class mapping */
    var LEVEL_SEV = {error: 'critical', warning: 'medium'};

    /* Filter by active level + search query */
    var filtered = hadoFindings.filter(function(f) {
      if (activeLevel !== 'all') {
        /* Info chip matches non-error, non-warning levels */
        if (activeLevel === 'info') {
          if (f.level === 'error' || f.level === 'warning') return false;
        } else {
          if (f.level !== activeLevel) return false;
        }
      }
      if (q) {
        var hay = ((f.rule || '') + ' ' + (f.msg || '')).toLowerCase();
        if (hay.indexOf(q) === -1) return false;
      }
      return true;
    });

    /* Ensure list is in DOM */
    if (!list.parentNode) {
      body.appendChild(list);
    }
    list.textContent = '';  /* clear previous render */

    /* ── State (b): filter miss ── */
    if (filtered.length === 0) {
      txt_(list, 'div', 'empty', L.hado_filter_empty || 'No matches');
      return;
    }

    /* ── Table render ── */
    var wrap = el_('div', 'tbl-wrap');
    var tbl  = el_('table', 'tbl-fixed');
    /* Pin the Location column (col 3) to 280px: table-layout:fixed ignores
       td max-width, so a <colgroup> width is the correct way to cap it. */
    var hadoCg = el_('colgroup', '');
    for (var hci = 0; hci < 4; hci++) {
      var hCol = el_('col', '');
      if (hci === 2) { hCol.style.width = '280px'; }
      hadoCg.appendChild(hCol);
    }
    tbl.appendChild(hadoCg);
    var thead = el_('thead', '');
    var hdr  = el_('tr', '');
    var hadoHeaders = [
      L.hado_th_level || 'Level',
      L.hado_th_rule  || 'Rule',
      L.hado_th_loc   || 'Location',
      L.hado_th_msg   || 'Message'
    ];
    hadoHeaders.forEach(function(h) {
      txt_(hdr, 'th', '', h);
    });
    thead.appendChild(hdr);
    tbl.appendChild(thead);

    var tbody = el_('tbody', '');
    var hadoVisibleRows = [];
    var hadoHiddenRows  = [];

    filtered.forEach(function(f, idx) {
      var tr = el_('tr', '');

      /* Col 1: Level tag */
      var tdLevel = el_('td', '');
      var sevClass = LEVEL_SEV[f.level] || 'low';  /* controlled mapping — T-11-07 */
      var levTag = el_('span', 'sevtag s-' + sevClass);
      levTag.textContent = f.level || 'info';
      tdLevel.appendChild(levTag);
      tr.appendChild(tdLevel);

      /* Col 2: Rule — DL* → hadolint wiki, SC* → shellcheck wiki, else plain (T-08-07, T-10-03/04) */
      var tdRule = el_('td', 'mono-cell');
      (function(code) {
        if (code && /^DL/i.test(code)) {
          var rA = el_('a', '');
          rA.href = 'https://github.com/hadolint/hadolint/wiki/' + code;
          rA.target = '_blank';
          rA.rel = 'noopener noreferrer';
          rA.textContent = code;
          tdRule.appendChild(rA);
        } else if (code && /^SC/i.test(code)) {
          var rA = el_('a', '');
          rA.href = 'https://www.shellcheck.net/wiki/' + code;
          rA.target = '_blank';
          rA.rel = 'noopener noreferrer';
          rA.textContent = code;
          tdRule.appendChild(rA);
        } else {
          tdRule.textContent = code || '';
        }
      })(f.rule);
      tr.appendChild(tdRule);

      /* Col 3: Location — GitHub blob link (D-08; fallback when f.file absent; T-08-07, T-10-03/04) */
      var tdLoc = el_('td', 'mono-cell path-cell');
      tdLoc.style.color = 'var(--muted)';
      (function(hadoBase) {
        var hadoFile = f.file || 'Dockerfile';
        var hadoLine = f.line != null ? String(f.line) : '';
        tdLoc.title = hadoFile + ':' + hadoLine;
        var hA = el_('a', '');
        hA.href = hadoBase + '/' + hadoFile + '#L' + hadoLine;
        hA.target = '_blank';
        hA.rel = 'noopener noreferrer';
        hA.textContent = hadoFile + ':' + hadoLine;
        tdLoc.appendChild(hA);
      })(ghBlobBase());
      tr.appendChild(tdLoc);

      /* Col 4: Message (sans, muted) */
      var tdMsg = el_('td', '');
      tdMsg.style.color = 'var(--muted)';
      tdMsg.textContent = f.msg || '';
      tr.appendChild(tdMsg);

      if (idx < 20) {
        hadoVisibleRows.push(tr);
      } else {
        hadoHiddenRows.push(tr);
      }
    });

    hadoVisibleRows.forEach(function(tr) { tbody.appendChild(tr); });
    tbl.appendChild(tbody);
    wrap.appendChild(tbl);
    list.appendChild(wrap);

    /* Optional show-more for unusually long Hadolint lists (executor discretion) */
    if (hadoHiddenRows.length > 0) {
      var moreBtn = el_('button', '');
      moreBtn.type = 'button';
      moreBtn.style.cssText = 'color:var(--accent);cursor:pointer;font-size:.74rem;padding:.35rem .5rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;' + 'background:none;border:none;';
      moreBtn.textContent = (L.dep_show_more || '+ show {N} more').replace('{N}', String(hadoHiddenRows.length));
      (function(rows, tbodyEl, btn) {
        btn.onclick = function() {
          rows.forEach(function(tr) { tbodyEl.appendChild(tr); });
          btn.parentNode.removeChild(btn);
        };
      })(hadoHiddenRows, tbody, moreBtn);
      list.appendChild(moreBtn);
    }
  }

  /* ─────────────────────────────────────────────────────────────────────────
     renderVT(D, L)
     SEC-03: VirusTotal static metadata grid + engine-stats block + 0-malicious message
     Static one-shot render (D-04): no toolbar, no re-render path.
     Three states: (c) skipped/error, (a) 0-malicious clean, (b) detections.
  ───────────────────────────────────────────────────────────────────────────── */
  function renderVT(D, L) {
    var mod = document.getElementById('sec-virustotal');
    if (!mod) return;
    var body = mod.querySelector('.mbody');
    if (!body) return;
    var vt = (D.scanners && D.scanners.virustotal) || {};
    var vtStatus = vt.status || '';
    var isSkipped = (vtStatus === 'skipped' || vtStatus === 'skipped_too_large' || vtStatus === 'error');

    /* ── State (c): skipped / error / too-large ── */
    if (isSkipped) {
      body.textContent = '';
      var emptyC = el_('div', 'empty');
      var iconC = el_('span', 'ok');
      iconC.style.color = vtStatus === 'error' ? 'var(--warn)' : 'var(--skip)';
      iconC.textContent = L.vt_skipped_icon || '⚠';
      emptyC.appendChild(iconC);
      emptyC.appendChild(document.createTextNode(L.vt_skipped || 'VirusTotal skipped'));
      body.appendChild(emptyC);
      /* Existence-gated raw link for virustotal.txt (T-10-04: noopener noreferrer) */
      var rawC = el_('div', 'rawlinks');
      var aVtC = el_('a', '');
      aVtC.href = 'raw/virustotal.txt';
      aVtC.target = '_blank';
      aVtC.rel = 'noopener noreferrer';
      aVtC.textContent = L.vt_artifact || '⤓ virustotal.txt';
      rawC.appendChild(aVtC);
      body.appendChild(rawC);
      return;
    }

    /* ── Normal render: metadata grid + engine stats ── */
    body.textContent = '';

    /* Six-tile metadata grid (.vtgrid) */
    var grid = el_('div', 'vtgrid');
    [
      [L.vt_grid_sha256 || 'SHA-256', vt.sha256],
      [L.vt_grid_md5    || 'MD5',     vt.md5],
      [L.vt_grid_sha1   || 'SHA-1',   vt.sha1],
      [L.vt_grid_type   || 'Type',    vt.filetype],
      [L.vt_grid_size   || 'Size',    vt.filesize],
      [L.vt_grid_name   || 'Name',    vt.name]
    ].forEach(function(pair) {
      var item = el_('div', 'vtitem');
      txt_(item, 'div', 'k', pair[0]);
      txt_(item, 'div', 'v', String(pair[1] != null ? pair[1] : '—'));
      grid.appendChild(item);
    });
    body.appendChild(grid);

    /* Four-tile engine-stats block (.vtstat) */
    var stats = el_('div', 'vtstat');
    [
      [L.vt_stat_malicious   || 'malicious',   vt.malicious,   't-fail'],
      [L.vt_stat_suspicious  || 'suspicious',  vt.suspicious,  't-warn'],
      [L.vt_stat_undetected  || 'undetected',  vt.undetected,  't-pass'],
      [L.vt_stat_unsupported || 'unsupported', vt.unsupported, '']
    ].forEach(function(row) {
      var x = el_('div', 'x');
      var b = el_('b', row[2]);
      b.textContent = String(row[1] != null ? row[1] : '—');
      x.appendChild(b);
      txt_(x, 'span', '', row[0]);
      stats.appendChild(x);
    });
    body.appendChild(stats);

    /* 0-malicious clean message (D-10, SEC-03): MUST appear, never an empty div */
    if (!vt.malicious) {
      var emptyA = el_('div', 'empty');
      var iconA = el_('span', 'ok');
      iconA.textContent = '✓';
      emptyA.appendChild(iconA);
      var cleanMsg = (L.vt_clean || '0 malicious — {N} engines checked')
        .replace('{N}', String(vt.engines != null ? vt.engines : '?'));
      emptyA.appendChild(document.createTextNode(cleanMsg));
      body.appendChild(emptyA);
    }

    /* Existence-gated raw link for virustotal.txt (T-10-04) */
    var rawA = el_('div', 'rawlinks');
    var aVtA = el_('a', '');
    aVtA.href = 'raw/virustotal.txt';
    aVtA.target = '_blank';
    aVtA.rel = 'noopener noreferrer';
    aVtA.textContent = L.vt_artifact || '⤓ virustotal.txt';
    rawA.appendChild(aVtA);
    body.appendChild(rawA);
  }

  /* ── Semgrep call site (after SECTIONS.forEach) ── */
  var _semActiveSev = 'all', _semQ = '';
  renderSemgrep(semFindings, _semActiveSev, _semQ, D, L);

  /* ── Phase 11 call sites: Dependencies, Hadolint, VirusTotal (after SECTIONS.forEach) ── */
  var _depActiveSev = 'all', _depQ = '';
  renderDeps(depVulns, _depActiveSev, _depQ, D, L);
  var _hadoActiveLevel = 'all', _hadoQ = '';
  renderHadolint(hadoFindings, _hadoActiveLevel, _hadoQ, D, L);
  renderVT(D, L);

  /* ── Footer ── */
  var footer = el_('footer', '');
  footer.textContent = (L.footer_generated || 'Generated') + ' · ' + reportTitle;
  page.appendChild(footer);

})();
</script>
</body>
</html>
HTML

  # Step 6 (CR-01): Inject the JSON blobs by SPLITTING the static template at the
  # placeholder lines and concatenating, NEVER via sed. sed treats &, \, and the
  # s-command delimiter as special in the *replacement* text; jq -c output is full
  # of \n, \", &, and / that sed would silently corrupt, breaking JSON.parse.
  # Here the template (just written by the quoted heredoc) is read line by line and
  # each placeholder line is replaced by printf '%s' of the blob — the blob is
  # emitted verbatim as data and is never re-interpreted by any regex engine or the
  # shell. Bash 3.2 safe (no mapfile / no sed -i); write-tmp-then-mv for atomicity.
  local _tpl="$REPORT_DIR/report.html" _out="$REPORT_DIR/report.html.tmp" _line
  : > "$_out"
  while IFS= read -r _line || [[ -n "$_line" ]]; do
    case "$_line" in
      *__SCAN_DATA__*)
        printf '%s' '<script type="application/json" id="scan-data">' >> "$_out"
        printf '%s' "$json_blob" >> "$_out"
        printf '%s\n' '</script>' >> "$_out"
        ;;
      *__LANG_DICT__*)
        printf '%s' '<script type="application/json" id="scan-lang">' >> "$_out"
        printf '%s' "$lang_dict" >> "$_out"
        printf '%s\n' '</script>' >> "$_out"
        ;;
      *)
        printf '%s\n' "$_line" >> "$_out"
        ;;
    esac
  done < "$_tpl"
  mv "$_out" "$_tpl"

  # Step 7: Report path to user
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
  local RUN_SEMGREP=true RUN_TRIVY=true RUN_VT=true RUN_HADOLINT=true RUN_GRYPE=true
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
      --no-grype)     RUN_GRYPE=false ;;
      --pdf)          GENERATE_PDF=true ;;
      --vt-key)
        [[ $# -lt 2 ]] && { log_error "--vt-key requires a value"; exit 1; }
        VT_API_KEY="$2"; shift ;;
      --lang)
        [[ $# -lt 2 ]] && { log_error "--lang requires a value"; exit 1; }
        LANG_REPORT="$2"; shift ;;
      --semgrep-min-severity)
        [[ $# -lt 2 ]] && { log_error "--semgrep-min-severity requires a value"; exit 1; }
        SEMGREP_MIN_SEV="$2"; SEMGREP_MIN_SEV_SET_BY_CLI=true; shift ;;
      --output-format)
        [[ $# -lt 2 ]] && { log_error "--output-format requires a value (json)"; exit 1; }
        [[ "$2" != "json" ]] && { log_error "Invalid --output-format value: '$2' (only 'json' is supported)"; exit 1; }
        OUTPUT_FORMAT="$2"; shift ;;
      --compare)
        [[ $# -lt 2 ]] && { log_error "--compare requires a directory path"; exit 1; }
        [[ ! -d "$2" ]] && { log_error "--compare path does not exist or is not a directory: '$2'"; exit 1; }
        COMPARE_DIR="$(cd "$2" && pwd)"; shift ;;
      --force)
        FORCE_SCAN=true ;;
      *) log_warn "Unknown option: $1" ;;
    esac
    shift
  done

  echo -e "${BOLD}${CYAN}"
  echo "╔══════════════════════════════════════════════════╗"
  echo "║   OSS Security Scanner                         ║"
  echo "║   VirusTotal · Semgrep · Trivy · Grype · Hadolint║"
  echo "╚══════════════════════════════════════════════════╝"
  echo -e "${NC}"
  log_info "Target : $TARGET"
  [[ -n "$TARGET_REF" ]] && log_info "Ref    : $TARGET_REF" || log_info "Ref    : HEAD (default branch)"
  [[ -z "$VT_API_KEY" ]] && log_warn "VT_API_KEY not set — VirusTotal scan will be skipped"

  check_deps
  check_scan_cache

  if [[ "$CACHE_HIT" == false ]]; then
    setup_workdir
    # Always generate HTML report on exit — even if a scanner crashes
    trap '
      for _p in "${PID_SEMGREP:-}" "${PID_VT:-}" "${PID_HADOLINT:-}" \
                "${PID_TRIVY:-}" "${PID_GRYPE:-}"; do
        [[ -n "$_p" ]] && kill "$_p" 2>/dev/null || true
      done
      generate_report 2>/dev/null || true
      [[ "$GENERATE_PDF" == true ]] && generate_pdf 2>/dev/null || true
      cleanup
    ' EXIT

    clone_repo
    read_scanner_config

    # Ensure VT Docker image is built before we background anything (Pitfall 5).
    # A first-run build can take 1-2 min; do it synchronously so progress is visible.
    if [[ "$RUN_VT" == true ]]; then
      ensure_vt_image || RUN_VT=false
    fi

    # ── Parallel scanner launch ───────────────────────────────────────────────
    # Init PID vars empty first (Pitfall 1 — prevents stale $! capture).
    PID_SEMGREP=""; PID_TRIVY=""; PID_GRYPE=""; PID_VT=""; PID_HADOLINT=""

    # Fire Trivy + Grype first (paired sub-group per D-02); braces form captures correct PID.
    [[ "$RUN_TRIVY"    == true ]] && { wrapper_trivy & PID_TRIVY=$!; }
    [[ "$RUN_GRYPE"    == true ]] && { wrapper_grype & PID_GRYPE=$!; }

    # Fire remaining three simultaneously.
    [[ "$RUN_SEMGREP"  == true ]] && { wrapper_semgrep & PID_SEMGREP=$!; }
    [[ "$RUN_VT"       == true ]] && { wrapper_virustotal & PID_VT=$!; }
    [[ "$RUN_HADOLINT" == true ]] && { wrapper_hadolint & PID_HADOLINT=$!; }

    # ── Sync point 1: wait for Trivy + Grype, then run merge_vulns ───────────
    ec_trivy=0;  [[ -n "$PID_TRIVY" ]] && { wait "$PID_TRIVY" || ec_trivy=$?; }
    ec_grype=0;  [[ -n "$PID_GRYPE" ]] && { wait "$PID_GRYPE" || ec_grype=$?; }
    [[ $ec_trivy    -ne 0 ]] && log_warn "wrapper_trivy exited non-zero (ec=$ec_trivy)"
    [[ $ec_grype    -ne 0 ]] && log_warn "wrapper_grype exited non-zero (ec=$ec_grype)"
    [[ -f "$LOG_DIR/trivy.env" ]] && . "$LOG_DIR/trivy.env"
    [[ -f "$LOG_DIR/grype.env" ]] && . "$LOG_DIR/grype.env"
    # WR-02: a malformed sourced env line (or unexpected jq output) could leave these
    # globals non-integer; under set -euo pipefail that aborts the run at the numeric
    # tests below. Clamp to safe sentinels right after sourcing: ages default to -1
    # (never stale), counts default to 0.
    [[ "$GRYPE_DB_AGE_DAYS" =~ ^-?[0-9]+$ ]] || GRYPE_DB_AGE_DAYS=-1
    [[ "$GRYPE_PKG_COUNT"   =~ ^-?[0-9]+$ ]] || GRYPE_PKG_COUNT=0
    [[ "$TRIVY_PKG_COUNT"   =~ ^-?[0-9]+$ ]] || TRIVY_PKG_COUNT=0
    # GRYPE-03: stale-DB console warn — only on fresh scan with DB age > 7 days (D-10/D-11)
    if [[ "$CACHE_HIT" == false ]] && [[ "$GRYPE_STATUS" != "error" ]] \
       && [[ "$GRYPE_DB_AGE_DAYS" -gt 7 ]]; then
      log_warn "Grype vulnerability DB is ${GRYPE_DB_AGE_DAYS} days old — auto-update may have failed"
    fi
    merge_vulns  # synchronous — sets MERGED_* globals in-process

    # ── Sync point 2: wait for Semgrep, VT, Hadolint (with live status) ──────
    # Collect active PIDs for the spinner.
    local _active_pids=()
    [[ -n "$PID_SEMGREP"  ]] && _active_pids+=("$PID_SEMGREP")
    [[ -n "$PID_VT"       ]] && _active_pids+=("$PID_VT")
    [[ -n "$PID_HADOLINT" ]] && _active_pids+=("$PID_HADOLINT")

    if [[ ${#_active_pids[@]} -gt 0 ]]; then
      local _SPIN_CHARS=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
      local _spin_idx=0
      while _pids_running "${_active_pids[@]}"; do
        local _spin_char="${_SPIN_CHARS[$(( _spin_idx % ${#_SPIN_CHARS[@]} ))]}"
        _spin_idx=$(( _spin_idx + 1 ))
        local _still=""
        [[ -n "$PID_SEMGREP"  ]] && kill -0 "$PID_SEMGREP"  2>/dev/null && _still="${_still}semgrep "
        [[ -n "$PID_VT"       ]] && kill -0 "$PID_VT"       2>/dev/null && _still="${_still}virustotal "
        [[ -n "$PID_HADOLINT" ]] && kill -0 "$PID_HADOLINT" 2>/dev/null && _still="${_still}hadolint "
        if [[ -t 1 ]]; then
          printf '\r\033[2K%s Scanning: %s' "$_spin_char" "${_still:-done}"
        else
          echo "[INFO] Scanning in progress: ${_still:-done}"
        fi
        sleep 0.2
      done
      [[ -t 1 ]] && printf '\r\033[2K'
    fi

    ec_semgrep=0;  [[ -n "$PID_SEMGREP"  ]] && { wait "$PID_SEMGREP" || ec_semgrep=$?; }
    ec_vt=0;       [[ -n "$PID_VT"       ]] && { wait "$PID_VT" || ec_vt=$?; }
    ec_hadolint=0; [[ -n "$PID_HADOLINT" ]] && { wait "$PID_HADOLINT" || ec_hadolint=$?; }
    [[ $ec_semgrep  -ne 0 ]] && log_warn "wrapper_semgrep exited non-zero (ec=$ec_semgrep)"
    [[ $ec_vt       -ne 0 ]] && log_warn "wrapper_virustotal exited non-zero (ec=$ec_vt)"
    [[ $ec_hadolint -ne 0 ]] && log_warn "wrapper_hadolint exited non-zero (ec=$ec_hadolint)"
    [[ -f "$LOG_DIR/semgrep.env"  ]] && . "$LOG_DIR/semgrep.env"
    [[ -f "$LOG_DIR/vt.env"       ]] && . "$LOG_DIR/vt.env"
    [[ -f "$LOG_DIR/hadolint.env" ]] && . "$LOG_DIR/hadolint.env"

    apply_scanner_config_suppressions  # filters CVEs + semgrep rules; updates MERGED_* counters; writes suppressed.json
  else
    # Cache hit: REPORT_DIR already set by check_scan_cache
    # Register trap for cleanup only (no WORK_DIR to clean; REPORT_DIR is the cached dir)
    trap '
      for _p in "${PID_SEMGREP:-}" "${PID_VT:-}" "${PID_HADOLINT:-}" \
                "${PID_TRIVY:-}" "${PID_GRYPE:-}"; do
        [[ -n "$_p" ]] && kill "$_p" 2>/dev/null || true
      done
      generate_report 2>/dev/null || true
      [[ "$GENERATE_PDF" == true ]] && generate_pdf 2>/dev/null || true
      cleanup
    ' EXIT

    # Source cached .env files to restore scanner result globals
    [[ -f "$LOG_DIR/semgrep.env"  ]] && . "$LOG_DIR/semgrep.env"
    [[ -f "$LOG_DIR/trivy.env"    ]] && . "$LOG_DIR/trivy.env"
    [[ -f "$LOG_DIR/grype.env"    ]] && . "$LOG_DIR/grype.env"
    [[ -f "$LOG_DIR/vt.env"       ]] && . "$LOG_DIR/vt.env"
    [[ -f "$LOG_DIR/hadolint.env" ]] && . "$LOG_DIR/hadolint.env"

    # Re-derive MERGED_* from cached vulns_merged.json
    local merged_cached="$RAW_DIR/vulns_merged.json"
    if [[ -s "$merged_cached" ]]; then
      MERGED_CRITICAL=$(jq '[.[] | select(.severity=="CRITICAL")] | length' "$merged_cached" 2>/dev/null || echo 0)
      MERGED_HIGH=$(jq '[.[] | select(.severity=="HIGH")] | length' "$merged_cached" 2>/dev/null || echo 0)
      MERGED_MEDIUM=$(jq '[.[] | select(.severity=="MEDIUM")] | length' "$merged_cached" 2>/dev/null || echo 0)
      MERGED_LOW=$(jq '[.[] | select(.severity=="LOW")] | length' "$merged_cached" 2>/dev/null || echo 0)
      # Re-derive TOTAL_MERGED from the merged file so dependencies.sources.merged is populated.
      # TOTAL_TRIVY and TOTAL_GRYPE are NOT recoverable from vulns_merged.json on cache hit —
      # the pre-dedup per-scanner counts are lost; they stay at 0 (honest, UI null-guards gracefully).
      TOTAL_MERGED=$(jq 'length' "$merged_cached" 2>/dev/null || echo 0)
    fi
  fi

  # ── Replay per-scanner summaries then generate report ─────────────────────
  replay_scanner_summaries
  calculate_risk_score  # reads MERGED_*, TRIVY_SECRETS, VT_MALICIOUS, SEMGREP_HIGH/MEDIUM_VISIBLE
  compare_findings      # computes diff globals if --compare was given

  generate_report
  [[ "$GENERATE_PDF" == true ]] && generate_pdf
  [[ "$OUTPUT_FORMAT" == "json" ]] && build_json_summary

  local overall
  overall=$(overall_status)
  echo ""
  log_section "FINAL RESULT: $overall"
  echo -e "  VirusTotal  : $(term_badge "$VT_STATUS")  malicious=$VT_MALICIOUS/$VT_TOTAL"
  echo -e "  Semgrep     : $(term_badge "$SEMGREP_STATUS")  findings=$SEMGREP_FINDINGS  errors=$SEMGREP_ERRORS"
  echo -e "  Trivy+Grype : $(term_badge "$TRIVY_STATUS")  merged critical=$MERGED_CRITICAL  high=$MERGED_HIGH  secrets=$TRIVY_SECRETS"
  echo -e "  Grype       : $(term_badge "$GRYPE_STATUS")  critical=$GRYPE_CRITICAL  high=$GRYPE_HIGH  medium=$GRYPE_MEDIUM"
  echo -e "  Hadolint    : $(term_badge "$HADOLINT_STATUS")  files=$HADOLINT_FILES  errors=$HADOLINT_ERRORS  warnings=$HADOLINT_WARNINGS"
  echo ""
  echo -e "  ${BOLD}HTML:${NC} file://$REPORT_DIR/report.html"
  [[ "$GENERATE_PDF" == true && -f "$REPORT_DIR/report.pdf" ]] && echo -e "  ${BOLD}PDF :${NC} file://$REPORT_DIR/report.pdf"
  echo ""
}

main "$@"
