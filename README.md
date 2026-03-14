# 🔍 OSS Security Scanner

Automated security scanner for open source GitHub repositories. Runs three independent checks — **VirusTotal**, **Semgrep**, and **Trivy** — entirely via Docker. No local installations required beyond Docker, Git, curl, and jq.

Generates a self-contained **HTML report** with a color-coded verdict (PASS / WARN / FAIL) for each check.

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
- HTML report with module cards, severity tables, and raw JSON links
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
| `--no-vt` | Skip VirusTotal scan |
| `--no-semgrep` | Skip Semgrep scan |
| `--no-trivy` | Skip Trivy scan |
| `--vt-key KEY` | VirusTotal API key (overrides `.env`) |

### Environment variables

| Variable | Description |
|---|---|
| `VT_API_KEY` | VirusTotal API key — can also be set in `.env` |

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
    └─ 📄 Generate reports/YYYYMMDD_HHMMSS_<repo>[_tag]/report.html
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
└── 20260314_113100_owner_repo_v2.4.0/
    ├── report.html       ← main report (open in browser)
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

## VirusTotal — first run

The `vt-cli` binary is built automatically from `Dockerfile.vt` on the first run (takes ~1–2 minutes). Subsequent runs use the cached Docker image.

---

## Notes

- **VirusTotal free tier**: 4 requests/min, 500 req/day. Large repos (>650 MB archive) are skipped automatically.
- **Semgrep**: Dockerfiles are excluded from analysis to avoid false positives.
- **Trivy**: Fetches the latest vulnerability database on each run.
- All scanners run independently — a failure in one does not stop others.

---

## License

MIT
