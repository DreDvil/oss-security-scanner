# 🔍 OSS Security Scanner

Automated security scanner for open source GitHub repositories. Runs four independent checks — **VirusTotal**, **Semgrep**, **Trivy**, and **Hadolint** — entirely via Docker. No local installations required beyond Docker, Git, curl, and jq.

Generates a self-contained **HTML report** (and optional **PDF**) with a color-coded verdict (PASS / WARN / FAIL) for each scanner.

---

## Features

| Scanner | What it checks |
|---|---|
| 🦠 **VirusTotal** | Malware detection across 70+ AV engines (via vt-cli) |
| 🔎 **Semgrep** | Static code analysis — security patterns, bad practices |
| 🛡️ **Trivy** | CVE vulnerabilities in dependencies, secrets in source code, misconfigs |
| 🐳 **Hadolint** | Dockerfile best-practices and security linting |

- Scan any public GitHub repository by URL
- Pin to a specific release tag or branch with `--release`
- Skip individual scanners with `--no-vt`, `--no-semgrep`, `--no-trivy`, `--no-hadolint`
- **HTML report** always generated; optional **PDF export** with `--pdf`
- Report language: **English** and **Russian** (`--lang ru`)
- **VirusTotal detail view** — file metadata (SHA256/MD5/SHA1, size, type) + per-engine malicious detections
- **Semgrep severity mapping** — ERROR → HIGH, WARNING → MEDIUM (no confusion with script errors)
- Clickable GitHub links in findings tables — jump directly to the vulnerable line
- Report is always generated — even if a scanner fails mid-run

---

## Requirements

- [Docker](https://www.docker.com/) (daemon must be running)
- `git`, `curl`, `jq`
- VirusTotal API key *(free tier: 4 req/min)* — optional, VT scan is skipped without it

---

## Installation

```bash
git clone https://github.com/DreDvil/oss-security-scanner.git
cd oss-security-scanner
chmod +x check.sh

# Optional: add your VirusTotal API key
cp .env.example .env
echo "VT_API_KEY=your_key_here" >> .env
```

---

## Usage

```bash
# Basic scan (default branch HEAD)
./check.sh https://github.com/owner/repo

# Scan a specific release tag
./check.sh https://github.com/owner/repo --release v2.4.0

# Also generate a PDF report
./check.sh https://github.com/owner/repo --pdf

# Report in Russian
./check.sh https://github.com/owner/repo --lang ru

# Skip VirusTotal (no API key)
./check.sh https://github.com/owner/repo --no-vt

# Pass VT key inline
VT_API_KEY=xxx ./check.sh https://github.com/sigstore/cosign --release v2.2.4

# Skip multiple scanners
./check.sh https://github.com/owner/repo --no-vt --no-trivy
```

### Options

| Flag | Description |
|---|---|
| `--release TAG` | Scan a specific tag or branch (default: HEAD) |
| `--lang LANG` | Report language: `en` (default) or `ru` |
| `--pdf` | Generate PDF report in addition to HTML |
| `--no-vt` | Skip VirusTotal scan |
| `--no-semgrep` | Skip Semgrep scan |
| `--no-trivy` | Skip Trivy scan |
| `--no-hadolint` | Skip Hadolint Dockerfile scan |
| `--vt-key KEY` | VirusTotal API key (overrides `.env`) |

### Environment variables

| Variable | Description |
|---|---|
| `VT_API_KEY` | VirusTotal API key — can also be set in `.env` |
| `LANG_REPORT` | Report language (`en` or `ru`) |

---

## How it works

```
check.sh https://github.com/owner/repo
    │
    ├─ git clone --depth 1 (or --branch TAG)
    │
    ├─ 🦠 VirusTotal
    │     └─ tar + sha256 → vt-cli (Docker, built from Dockerfile.vt)
    │         ├─ Cache hit  → fetch existing analysis
    │         └─ Cache miss → upload file, wait for results
    │         └─ Report: file metadata + per-engine malicious detections
    │
    ├─ 🔎 Semgrep
    │     └─ docker run semgrep/semgrep
    │         ├─ Level 1: --config=auto (language-aware)
    │         ├─ Level 2: language-specific rulesets (js, py, go, java …)
    │         └─ Level 3: bundled p/default (always runs as fallback)
    │
    ├─ 🛡️ Trivy
    │     └─ docker run aquasec/trivy fs --scanners vuln,secret,misconfig
    │
    ├─ 🐳 Hadolint
    │     └─ docker run hadolint/hadolint (all Dockerfiles in repo)
    │
    ├─ 📄 Generate reports/.../report.html
    └─ 📑 Generate reports/.../report.pdf  (optional, --pdf flag)
```

### Verdict logic

| Status | Condition |
|---|---|
| ✅ PASS | No critical issues across all scanners |
| ⚠️ WARN | Non-critical findings (HIGH CVEs, Semgrep warnings, Hadolint warnings) |
| ❌ FAIL | Malware detected **or** CRITICAL CVEs **or** secrets in source |

---

## Report structure

```
reports/
└── 20260319_195100_owner_repo/
    ├── report.html       ← main report (open in browser)
    ├── report.pdf        ← PDF export (if --pdf was used)
    ├── semgrep.json
    ├── trivy_fs.json
    ├── hadolint.json
    └── virustotal.txt
```

Open the report:
```bash
open reports/*/report.html          # macOS
xdg-open reports/*/report.html      # Linux
```

---

## Report highlights

- **Dark theme** with module cards per scanner
- **VirusTotal block**: file hashes (SHA256/MD5/SHA1), size, type, reputation, scan dates + per-engine malicious verdict table
- **Semgrep table**: numbered rows, severity mapped to HIGH/MEDIUM/LOW/INFO, clickable GitHub links to exact lines
- **Trivy secrets**: file links pointing directly to the affected file in the repo
- **Hadolint**: lists all Dockerfile issues with rule codes, severity, and line numbers
- **Responsive layout** — adapts to any screen width

---

## Docker images (auto-built on first run)

| Image | Dockerfile | Purpose |
|---|---|---|
| `vt-cli:local` | `Dockerfile.vt` | VirusTotal CLI (Go binary) |
| `weasyprint-pdf:local` | `Dockerfile.pdf` | HTML → PDF export (with Noto fonts) |

All images are built automatically on first use (~1–3 min each) and cached by Docker for subsequent runs. `hadolint/hadolint` and `semgrep/semgrep` are pulled from Docker Hub.

---

## Notes

- **VirusTotal free tier**: 4 requests/min, 500 req/day. Large repos (>650 MB archive) are skipped automatically.
- **VirusTotal freshness**: each run downloads a fresh archive from GitHub. If the SHA256 differs from a previous upload, VT treats it as a new file and starts a fresh scan — some engines may time out on the first run. Results stabilise if the same file is re-checked.
- **Semgrep**: uses a 3-level fallback (auto → language-specific rulesets → bundled p/default) to maximise rule coverage regardless of network availability.
- **Hadolint**: automatically finds all `Dockerfile*` files in the repository. Skipped (SKIP badge) if none are found.
- **Trivy**: fetches the latest vulnerability database on each run.
- All scanners run independently — a failure in one does not stop others.
- PDF generation requires building `weasyprint-pdf:local` on first run. Includes Noto fonts for full Unicode/Cyrillic support.

---

## License

MIT
