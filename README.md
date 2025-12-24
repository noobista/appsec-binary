# appsec-binary

**appsec-binary** is a command-line static security analysis orchestrator for **Android (APK/AAB/XAPK)** and **iOS (IPA)** application binaries.

It is designed to go beyond single-engine scanners by **combining multiple best-in-class static analysis tools**, normalizing findings, and presenting **clear, color-coded security results** suitable for professional assessments.

> Scope: Static analysis only. Runtime behaviors (SSL pinning effectiveness, jailbreak/root detection, session handling, etc.) require dynamic testing.

---

## Key Capabilities

- One command to analyze mobile app binaries
- Multi-engine static analysis (best-effort based on installed tools)
- Android and iOS support
- Hardcoded secret detection
- Normalized JSON output for reporting and automation
- Color-coded console output by severity
- Verbose mode for full traceability

---

## Engines Used (Optional, Auto-Detected)

### Common
- MobSF (Docker-based, optional)
- Custom secret scanner (pattern-based MVP)

### Android
- apktool
- jadx
- APKLeaks
- Quark Engine

### iOS
- IPA extraction
- codesign entitlements analysis (macOS only)

Missing tools are skipped gracefully.

---

## Installation

See [`docs/installation.md`](docs/installation.md)

---

## Usage

```bash
python3 appsec_binary.py /path/to/app.apk
python3 appsec_binary.py /path/to/app.ipa

# Verbose output
python3 appsec_binary.py /path/to/app.apk -v

# Skip MobSF
python3 appsec_binary.py /path/to/app.apk --no-mobsf
