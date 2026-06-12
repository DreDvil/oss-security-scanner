# 🔍 OSS Security Scanner

Automated security scanner for open source GitHub repositories. Runs independent checks — **VirusTotal**, **Semgrep**, **Trivy + Grype** (deduplicated CVE scanning), and **Hadolint** — entirely via Docker, and generates a **Syft SBOM** that feeds Grype for wider package coverage. No local installations required beyond Docker, Git, curl, and jq.

Generates a self-contained, interactive **HTML report** (`report.html`) plus machine-readable **`report.json`**, with a color-coded verdict (PASS / WARN / FAIL) per scanner and an overall risk score.

---

## Features

| Scanner | What it checks |
|---|---|
| 🦠 **VirusTotal** | Malware detection across 70+ AV engines (via vt-cli); cache-first with automatic upload and 5-minute analysis timeout |
| 🔎 **Semgrep** | Static code analysis — security patterns, bad practices; errors surfaced in terminal summary |
| 🛡️ **Trivy** | CVE vulnerabilities in dependencies, secrets in source code, misconfigs |
| 📦 **Grype** | Second CVE engine — scans the Syft SBOM (falls back to directory mode) and cross-checks dependencies against a different advisory database for broader coverage |
| 🧾 **Syft** | Generates a software bill of materials (SBOM, `syft-json`) of the repo's packages — an auditable catalog that is fed to Grype and downloadable from the report |
| 🐳 **Hadolint** | Dockerfile best-practices and security linting |

- Scan any public GitHub repository by URL
- Pin to a specific release tag or branch with `--release`
- **Trivy + Grype dual CVE scanning** — findings are deduplicated on a canonical key and each row is labelled with its source (`Trivy`, `Grype`, or `Trivy + Grype` when both engines agree); GHSA ids from Grype are aliased to their CVE so the two engines reconcile
- **SBOM generation (Syft)** — every scan produces a `syft-json` SBOM (`raw/sbom.syft.json`), downloadable from the report and fed to Grype to widen package coverage; `--no-sbom` reverts Grype to directory mode
- **Overall risk score** plus per-scanner PASS / WARN / FAIL verdicts
- **Diff mode** (`--compare DIR`) — compare against a prior report and surface what changed
- **Per-repo config & cache** — repeat scans are served from cache; `--force` runs fresh
- Skip individual scanners: `--no-vt`, `--no-semgrep`, `--no-trivy`, `--no-grype`, `--no-hadolint`; skip SBOM generation with `--no-sbom`
- **Interactive HTML report** with light/dark theme toggle and a fluid layout that fills any screen width (375px – 2560px)
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

## Repository layout

```
check.sh                          # entry point — run ./check.sh <repo-url>
lib/
  scanner.merge.jq                # Trivy + Grype dedup / merge (canonical-key grouping)
  scanner.grype-normalize.jq      # Grype → common schema (GHSA→CVE aliasing)
docker/
  Dockerfile.vt                   # vt-cli:local image (VirusTotal CLI)
```

---

## Usage

```bash
# Basic scan (default branch HEAD)
./check.sh https://github.com/owner/repo

# Scan a specific release tag
./check.sh https://github.com/owner/repo --release v2.4.0

# Compare against a previous report (diff mode)
./check.sh https://github.com/owner/repo --compare reports/20260101_120000_owner_repo

# Force a fresh scan, bypassing the cache
./check.sh https://github.com/owner/repo --force

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
| `--compare DIR` | Compare against a prior report directory (adds a diff section) |
| `--force` | Bypass the scan cache and run a full fresh scan |
| `--semgrep-min-severity LEVEL` | Minimum Semgrep severity to show: `info`\|`low`\|`medium`\|`high` (default: `medium`) |
| `--no-vt` | Skip VirusTotal scan |
| `--no-semgrep` | Skip Semgrep scan |
| `--no-trivy` | Skip Trivy scan |
| `--no-grype` | Skip Grype scan |
| `--no-sbom` | Skip Syft SBOM generation; Grype scans in directory mode |
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
    │     └─ tar + sha256 → vt-cli (Docker, built from docker/Dockerfile.vt)
    │         ├─ Cache hit  → fetch existing analysis
    │         └─ Cache miss → upload file, wait for results (5 min timeout)
    │         └─ Report: file metadata + per-engine malicious detections
    │
    ├─ 🔎 Semgrep
    │     └─ docker run semgrep/semgrep
    │         ├─ Level 1: --config=auto (language-aware)
    │         ├─ Level 2: language-specific rulesets (js, py, go, java …)
    │         └─ Level 3: bundled p/default (always runs as fallback)
    │
    ├─ 🛡️ Trivy + 🧾 Syft + 📦 Grype
    │     ├─ docker run aquasec/trivy fs --scanners vuln,secret,misconfig
    │     ├─ docker run anchore/syft dir:. -o syft-json → raw/sbom.syft.json
    │     ├─ docker run anchore/grype sbom:raw/sbom.syft.json (dir:. if --no-sbom / SBOM fails)
    │     └─ merge → dedup on canonical key (id+pkg+version), GHSA→CVE aliased,
    │                 each finding labelled Trivy / Grype / Trivy + Grype
    │
    ├─ 🐳 Hadolint
    │     └─ docker run hadolint/hadolint (all Dockerfiles in repo)
    │
    ├─ 🧮 Risk score + per-scanner verdicts
    │
    └─ 📄 Generate reports/.../report.html  +  report.json
```

### Verdict logic

| Status | Condition |
|---|---|
| ✅ PASS | No critical issues across all scanners |
| ⚠️ WARN | Non-critical findings (HIGH CVEs, Semgrep warnings, Hadolint warnings) |
| ❌ FAIL | Malware detected **or** CRITICAL CVEs **or** secrets in source |

---

## Running the tests

The repository ships two offline regression suites that cover the Trivy + Grype
merge/dedup logic and the Grype diagnostics layer. They run entirely **offline**
(no Docker, no network) and require only `jq` and `bash`:

```bash
bash tests/merge_vulns.test.sh   # Trivy + Grype merge / dedup (canonical-key grouping)
bash tests/grype_diag.test.sh    # Grype package counts, DB-age, inconclusive triggers
```

Each suite prints a per-assertion `PASS`/`FAIL` line and a final tally, exiting
non-zero if any assertion fails.

---

## Report structure

```
reports/
└── 20260319_195100_owner_repo/
    ├── report.html       ← main report (open in browser)
    ├── report.json       ← machine-readable data (jq-queryable)
    ├── raw/              ← scanner data artifacts (linked from report)
    │   ├── semgrep.json, trivy_fs.json, grype.json, hadolint.json
    │   ├── sbom.syft.json (Syft SBOM; absent with --no-sbom)
    │   ├── vulns_merged.json, virustotal.txt, …
    └── logs/             ← run diagnostics (internal; not linked)
        ├── semgrep.log (scanner stderr), semgrep-run.log, trivy-run.log, …
        └── semgrep.env, trivy.env, grype.env, …
```

Open the report:
```bash
open reports/*/report.html          # macOS
xdg-open reports/*/report.html      # Linux
```

---

## Report highlights

- **Light & dark themes** — toggle in the header, preference persisted across runs; module cards per scanner
- **Dependencies table** (Trivy + Grype): one deduplicated CVE list with a `Source` column (`Trivy` / `Grype` / `Trivy + Grype`), severity, CVSS, fixed-in version, and a diagnostics line when Grype is inconclusive; the **Syft SBOM** (`raw/sbom.syft.json`) is offered as a download alongside the raw scanner artifacts
- **VirusTotal block**: file hashes (SHA256/MD5/SHA1), size, type, reputation, scan dates + per-engine malicious verdict table
- **Semgrep table**: numbered rows, severity mapped to HIGH/MEDIUM/LOW/INFO, clickable GitHub links to exact lines
- **Trivy secrets**: file links pointing directly to the affected file in the repo
- **Hadolint**: lists all Dockerfile issues with rule codes, severity, and line numbers
- **Fluid layout** — fills any screen width from 375px to 2560px; long file paths truncate with a hover tooltip, long messages wrap
- **Accessibility** — keyboard focus indicators on all interactive elements; external links include `rel="noopener noreferrer"`
- **XSS-safe** — all scanner output (file paths, rule IDs, detection names) is set via DOM `textContent` (never `innerHTML`)

---

## Docker images (auto-built on first run)

| Image | Dockerfile | Purpose |
|---|---|---|
| `vt-cli:local` | `docker/Dockerfile.vt` | VirusTotal CLI (Go binary); base images digest-pinned for supply-chain safety |

All images are built automatically on first use (~1–3 min each) and cached by Docker for subsequent runs. `hadolint/hadolint` and `semgrep/semgrep` are pulled from Docker Hub.

---

## Notes

- **VirusTotal free tier**: 4 requests/min, 500 req/day. Large repos (>650 MB archive) are skipped automatically.
- **VirusTotal upload**: repos not found in VT's cache are uploaded automatically and analysed. Upload + analysis has a 5-minute ceiling; if VT is slow, the scan is skipped with an `error` badge (not a false pass).
- **VirusTotal freshness**: each run downloads a fresh archive from GitHub. If the SHA256 differs from a previous upload, VT treats it as a new file and starts a fresh scan — some engines may time out on the first run. Results stabilise if the same file is re-checked.
- **Semgrep**: uses a 3-level fallback (auto → language-specific rulesets → bundled p/default) to maximise rule coverage regardless of network availability.
- **Hadolint**: automatically finds all `Dockerfile*` files in the repository. Skipped (SKIP badge) if none are found.
- **Trivy + Grype**: both fetch their vulnerability databases on each run. They use different advisory sources, so coverage differs per ecosystem (e.g. Trivy parses `bun.lock`, which Grype does not yet). The report dedups overlapping findings and labels each row by source.
- **Grype "inconclusive"**: in directory mode Grype only sees dependencies it can pin from committed lockfiles/manifests. A repo with no resolvable manifests yields 0 Grype findings — the report flags this as inconclusive rather than a clean pass.
- All scanners run independently — a failure in one does not stop others.
- **Saving a PDF**: open `report.html` in a browser and use Print → Save as PDF — the report ships a print stylesheet for clean output.

---

## License

This project is licensed under the **MIT License** © 2026 Danil Grechishkin — see the [`LICENSE`](LICENSE) file for the full text.
