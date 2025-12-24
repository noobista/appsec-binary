# appsec-binary

Static security analysis orchestrator for **APK** and **IPA** binaries.

This tool is designed to outperform single-engine scanners by running multiple analyzers (where available) and producing a **normalized**, **deduplicated**, **color-coded** console summary plus machine-readable outputs.

> Scope: **Static analysis only**. It will not “prove” runtime controls (SSL pinning effectiveness, jailbreak/root detection behavior, auth/session issues). Use dynamic testing for those.

---

## Features

- One command: analyze an `APK/AAB/XAPK` or `IPA`
- Runs multiple engines (best-effort, based on what is installed):
  - **MobSF** (Docker) optional
  - Android: unzip + `apktool` + `jadx` + `apkleaks` + `quark` (optional)
  - iOS: unzip + `codesign` entitlements extraction (macOS) optional
  - **Secret scanning** (pattern-based MVP)
- Outputs:
  - `report.json` (normalized findings)
  - `summary.txt` (top findings)
  - `raw/` (engine outputs)
- Console output is **severity color-coded**
- `--verbose` shows executed commands and debugging logs

---

## Requirements

- Python 3.10+
- Optional engines:
  - Docker (for MobSF)
  - Android: `apktool`, `jadx`, `apkleaks`, `quark`
  - iOS: `codesign` (macOS only)

---

## Install

```bash
git clone https://github.com/<your-username>/appsec-binary.git
cd appsec-binary
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

