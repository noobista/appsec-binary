# appsec-binary

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![CI](https://github.com/<your-username>/appsec-binary/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Android%20%7C%20iOS-lightgrey)

**appsec-binary** is a command-line **static mobile application security analysis orchestrator** for **Android (APK/AAB/XAPK)** and **iOS (IPA)** binaries.

It combines multiple best-in-class static analysis tools, correlates findings, and presents **clear, color-coded security output** suitable for professional assessments, audits, and CI pipelines.

> This tool is designed for **security engineers**, **red teamers**, and **mobile app security testers** who want **signal over noise**.

---

## Why appsec-binary exists

Most tools:
- Run a single engine
- Dump hundreds of low-quality findings
- Provide little context or correlation

**appsec-binary**:
- Orchestrates **multiple engines**
- Normalizes output
- Highlights **real attack surface**
- Produces outputs that are actually usable in reports

---

## Core Features

- One command to analyze a mobile app binary
- Multi-engine static analysis (auto-detects installed tools)
- Android and iOS support
- Hardcoded secret detection
- Severity-based, color-coded console output
- Normalized JSON output for automation
- Verbose mode for audit traceability

---

## Supported Engines

### Common
- MobSF (Docker, optional)
- Built-in secret scanner

### Android
- apktool
- jadx
- APKLeaks
- Quark Engine

### iOS
- IPA extraction
- Entitlements analysis (`codesign`, macOS only)

Missing tools are skipped cleanly.

---

## Screenshots

> Add real screenshots once you run the tool.

