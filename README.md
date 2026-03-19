# 🔍 OSS Security Scanner

Automated security scanner for open source GitHub repositories. Runs three independent checks — **VirusTotal**, **Semgrep**, and **Trivy** — entirely via Docker. No local installations required beyond Docker, Git, curl, and jq.

Generates a self-contained **HTML report** and **PDF report** with a color-coded verdict (PASS / WARN / FAIL) for each check.

---

## Features

| Scanner | What it checks |
|---|---|
| 🦠 **VirusTotal** | Malware detection across 70+ AV engines (via vt-cli) |
| 🔎 **Semgrep** | Static code analysis — security patterns, bad practices |
| 🛡️ **Trivy** | CVE vulnerabilities in dependencies, secrets in source code, misconfigs |

- Scan any public GitHub repository by URL
- Pin to a specific release tag or branch with `--release`
- Skip individual scanners with `--no-vt`, `--no-semgrep`, `--no-trivy`
- **HTML + PDF reports** — both generated automatically after each scan
- Report language: **English** and **Russian** (`--lang ru`)
- Clickable GitHub links in findings tables — jump directly to the vulnerable line
- Row numbering in Semgrep findings table
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
| `--no-vt` | Skip VirusTotal scan |
| `--no-semgrep` | Skip Semgrep scan |
| `--no-trivy` | Skip Trivy scan |
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
    │
    ├─ 🔎 Semgrep
    │     └─ docker run semgrep/semgrep --config=auto (fallback: p/default)
    │
    ├─ 🛡️ Trivy
    │     └─ docker run aquasec/trivy fs --scanners vuln,secret,misconfig
    │
    ├─ 📄 Generate reports/.../report.html
    └─ 📑 Generate reports/.../report.pdf  (WeasyPrint, built from Dockerfile.pdf)
```

### Verdict logic

| Status | Condition |
|---|---|
| ✅ PASS | No critical issues across all scanners |
| ⚠️ WARN | Non-critical findings (HIGH CVEs, Semgrep warnings) |
| ❌ FAIL | Malware detected **or** CRITICAL CVEs **or** secrets in source |

---

## Report structure

```
reports/
└── 20260319_195100_owner_repo_v2.4.0/
    ├── report.html       ← main report (open in browser)
    ├── report.pdf        ← PDF export
    ├── semgrep.json
    ├── trivy_fs.json
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
- **Semgrep table**: numbered rows, clickable GitHub links to exact lines (`file.ts#L42`)
- **Trivy secrets**: file links pointing directly to the affected file in the repo
- **Responsive layout** — adapts to any screen width
- **Local timezone** displayed in report header and footer

---

## Docker images (auto-built on first run)

| Image | Dockerfile | Purpose |
|---|---|---|
| `vt-cli:local` | `Dockerfile.vt` | VirusTotal CLI (Go binary) |
| `weasyprint-pdf:local` | `Dockerfile.pdf` | HTML → PDF export |

Both images are built automatically on first use (~1–3 min each) and cached by Docker for subsequent runs.

---

## Notes

- **VirusTotal free tier**: 4 requests/min, 500 req/day. Large repos (>650 MB archive) are skipped automatically.
- **Semgrep**: Dockerfiles are excluded from analysis to avoid false positives. Uses `--config=auto` with fallback to bundled `p/default`.
- **Trivy**: Fetches the latest vulnerability database on each run.
- All scanners run independently — a failure in one does not stop others.
- PDF generation requires building `weasyprint-pdf:local` on first run. Includes Noto fonts for full Unicode/Cyrillic support.

---

## License

MIT
