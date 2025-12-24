# Installation Guide

## Requirements

- Python 3.10+
- Optional tools (auto-detected):
  - Docker (for MobSF)
  - apktool
  - jadx
  - APKLeaks
  - Quark Engine
  - macOS `codesign` (for iOS entitlements)

---

## Setup

```bash
git clone https://github.com/<your-username>/appsec-binary.git
cd appsec-binary

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
