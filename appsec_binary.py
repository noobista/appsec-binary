#!/usr/bin/env python3
"""
appsec-binary: APK/IPA static analysis orchestrator (static-only)

What it does:
- Runs multiple static analyzers (optional) and correlates findings:
  - MobSF (via Docker) [optional]
  - Android: unzip + apktool + jadx + apkleaks + quark (as available)
  - iOS: unzip + codesign entitlements (macOS) [optional]
  - Secret scanning (entropy/pattern-based) over extracted/decompiled trees
- Writes:
  - report.json (normalized findings)
  - summary.txt (top findings)
  - raw/<engine outputs>

Color-coded console output:
- CRITICAL/HIGH/MEDIUM/LOW/INFO are colored.
- Use --no-color to disable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import time
import zipfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Optional

import requests

LOG = logging.getLogger("appsec-binary")

# -----------------------------
# ANSI color helpers (no deps)
# -----------------------------

ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "light_red": "\033[91m",
    "yellow": "\033[33m",
    "green": "\033[32m",
    "cyan": "\033[36m",
    "gray": "\033[90m",
}

SEV_COLOR = {
    "CRITICAL": "light_red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "cyan",
}

def supports_color() -> bool:
    if not sys.stdout.isatty():
        return False
    term = os.environ.get("TERM", "")
    if term in ("dumb", ""):
        return False
    return True

def c(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{ANSI.get(color,'')}{text}{ANSI['reset']}"

# -----------------------------
# Utilities
# -----------------------------

def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def run_cmd(cmd: list[str], cwd: Optional[Path] = None, timeout: int = 1800) -> subprocess.CompletedProcess:
    LOG.debug("RUN: %s", " ".join(cmd))
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
        timeout=timeout,
    )

def which_or_none(name: str) -> Optional[str]:
    return shutil.which(name)

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def write_text(p: Path, s: str) -> None:
    p.write_text(s, encoding="utf-8", errors="ignore")

# -----------------------------
# Findings model
# -----------------------------

@dataclass
class Finding:
    engine: str
    title: str
    severity: str  # INFO/LOW/MEDIUM/HIGH/CRITICAL
    evidence: str
    impact: str
    location: str = ""
    recommendation: str = ""
    cwe: str = ""
    masvs: str = ""
    confidence: str = "MEDIUM"  # LOW/MEDIUM/HIGH (best-effort)

@dataclass
class RunResult:
    file: str
    sha256: str
    platform: str  # android/ios
    started_at: float
    finished_at: float
    findings: list[Finding]
    raw_outputs: dict[str, Any]

# -----------------------------
# Engine: MobSF
# -----------------------------

def mobsf_start_docker() -> None:
    if not which_or_none("docker"):
        raise RuntimeError("docker not found; install Docker or run with --no-mobsf")

    ps = run_cmd(["docker", "ps", "--format", "{{.Names}}"])
    if "mobsf" in ps.stdout.splitlines():
        return

    LOG.info("Starting MobSF docker container (name=mobsf)")
    cp = run_cmd([
        "docker", "run", "-d",
        "--name", "mobsf",
        "-p", "8000:8000",
        "opensecurity/mobile-security-framework-mobsf:latest"
    ])
    if cp.returncode != 0:
        raise RuntimeError(f"Failed to start MobSF: {cp.stderr}")

def mobsf_wait(url: str, timeout_sec: int = 120) -> None:
    start = time.time()
    while time.time() - start < timeout_sec:
        try:
            r = requests.get(url, timeout=3)
            if r.status_code in (200, 302):
                return
        except Exception:
            pass
        time.sleep(2)
    raise RuntimeError(f"MobSF not reachable at {url}")

def mobsf_scan(app: Path, out_raw: Path, url: str, api_key: str) -> dict[str, Any]:
    headers = {"Authorization": api_key}
    with app.open("rb") as f:
        files = {"file": (app.name, f)}
        r = requests.post(f"{url}/api/v1/upload", files=files, headers=headers, timeout=180)
    r.raise_for_status()
    up = r.json()

    scan_type = "apk" if app.suffix.lower() in (".apk", ".aab", ".xapk") else "ipa"
    r = requests.post(
        f"{url}/api/v1/scan",
        data={"scan_type": scan_type, "file_name": up["file_name"], "hash": up["hash"]},
        headers=headers,
        timeout=900,
    )
    r.raise_for_status()

    r = requests.post(
        f"{url}/api/v1/report_json",
        data={"hash": up["hash"]},
        headers=headers,
        timeout=180,
    )
    r.raise_for_status()
    report = r.json()

    ensure_dir(out_raw)
    write_text(out_raw / "mobsf_report.json", json.dumps(report, indent=2))
    return report

def mobsf_extract_findings(report: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []

    score = report.get("security_score")
    if score is not None:
        findings.append(Finding(
            engine="mobsf",
            title="MobSF security score",
            severity="INFO",
            evidence=f"security_score={score}",
            impact="Low-signal metric; use to prioritize deeper review, not as proof of security.",
            confidence="LOW",
        ))

    for bucket, sev in [("critical", "CRITICAL"), ("high", "HIGH"), ("warning", "MEDIUM")]:
        items = report.get(bucket)
        if isinstance(items, list) and items:
            for it in items[:80]:
                if isinstance(it, str):
                    title = it
                elif isinstance(it, dict):
                    title = it.get("title") or it.get("issue") or it.get("name") or str(it)
                else:
                    title = str(it)

                findings.append(Finding(
                    engine="mobsf",
                    title=str(title),
                    severity=sev,
                    evidence=f"bucket={bucket}",
                    impact="Tool-reported risk; validate evidence in MobSF report and confirm reachability.",
                    confidence="MEDIUM",
                ))
    return findings

# -----------------------------
# Engine: Android helpers
# -----------------------------

def android_unpack(app: Path, out_raw: Path) -> dict[str, Any]:
    out_dir = out_raw / "apk_unzipped"
    ensure_dir(out_dir)
    with zipfile.ZipFile(app, "r") as z:
        z.extractall(out_dir)
    return {"unzipped_dir": str(out_dir)}

def android_apktool(app: Path, out_raw: Path) -> dict[str, Any]:
    if not which_or_none("apktool"):
        return {"skipped": "apktool not found"}
    out_dir = out_raw / "apktool"
    ensure_dir(out_dir)
    cp = run_cmd(["apktool", "d", "-f", str(app), "-o", str(out_dir)], timeout=1800)
    write_text(out_raw / "apktool.stdout", cp.stdout)
    write_text(out_raw / "apktool.stderr", cp.stderr)
    return {"out_dir": str(out_dir), "returncode": cp.returncode}

def android_jadx(app: Path, out_raw: Path) -> dict[str, Any]:
    if not which_or_none("jadx"):
        return {"skipped": "jadx not found"}
    out_dir = out_raw / "jadx"
    ensure_dir(out_dir)
    cp = run_cmd(["jadx", "-d", str(out_dir), str(app)], timeout=1800)
    write_text(out_raw / "jadx.stdout", cp.stdout)
    write_text(out_raw / "jadx.stderr", cp.stderr)
    return {"out_dir": str(out_dir), "returncode": cp.returncode}

def android_apkleaks(app: Path, out_raw: Path) -> dict[str, Any]:
    if not which_or_none("apkleaks"):
        return {"skipped": "apkleaks not found"}
    cp = run_cmd(["apkleaks", "-f", str(app)], timeout=1800)
    write_text(out_raw / "apkleaks.txt", cp.stdout + "\n" + cp.stderr)
    return {"returncode": cp.returncode}

def android_quark(app: Path, out_raw: Path) -> dict[str, Any]:
    if not which_or_none("quark"):
        return {"skipped": "quark not found"}
    report_path = out_raw / "quark_report.json"
    cp = run_cmd(["quark", "-a", str(app), "--report", str(report_path)], timeout=1800)
    write_text(out_raw / "quark.stdout", cp.stdout)
    write_text(out_raw / "quark.stderr", cp.stderr)
    return {"returncode": cp.returncode, "report": str(report_path)}

# -----------------------------
# Engine: iOS helpers
# -----------------------------

def ios_unpack(app: Path, out_raw: Path) -> dict[str, Any]:
    out_dir = out_raw / "ipa_unzipped"
    ensure_dir(out_dir)
    with zipfile.ZipFile(app, "r") as z:
        z.extractall(out_dir)
    return {"unzipped_dir": str(out_dir)}

def ios_codesign_entitlements(app_unzipped: Path, out_raw: Path) -> dict[str, Any]:
    if not which_or_none("codesign"):
        return {"skipped": "codesign not found (full iOS entitlements check requires macOS)"}

    payload = app_unzipped / "Payload"
    app_dirs = list(payload.glob("*.app"))
    if not app_dirs:
        return {"skipped": "No .app found in Payload"}
    app_bundle = app_dirs[0]

    cp = run_cmd(["codesign", "-d", "--entitlements", ":-", str(app_bundle)], timeout=300)
    write_text(out_raw / "entitlements.xml", cp.stdout + "\n" + cp.stderr)
    return {"app_bundle": str(app_bundle), "returncode": cp.returncode}

# -----------------------------
# Secret scanning (pattern-based MVP)
# -----------------------------

SECRET_PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}", "CWE-798"),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "CWE-798"),
    ("JWT", r"eyJ[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]+", "CWE-522"),
    ("Generic API Key/Secret", r"(?i)(api[_-]?key|secret|token|client[_-]?secret)\s*[:=]\s*['\"][0-9a-zA-Z\-_]{16,}['\"]", "CWE-798"),
]

def scan_secrets(root: Path, out_raw: Path) -> list[Finding]:
    import re
    findings: list[Finding] = []
    text_ext = {
        ".xml", ".json", ".plist", ".txt", ".properties", ".yaml", ".yml",
        ".js", ".ts", ".java", ".kt", ".swift", ".m", ".mm", ".gradle", ".config"
    }

    for p in root.rglob("*"):
        if not p.is_file():
            continue

        # Avoid scanning giant binaries
        if p.suffix.lower() not in text_ext and p.stat().st_size > 2_000_000:
            continue

        try:
            s = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for name, pat, cwe in SECRET_PATTERNS:
            for m in re.finditer(pat, s):
                snippet = s[max(0, m.start()-40): m.end()+40].replace("\n", " ")
                findings.append(Finding(
                    engine="secrets",
                    title=f"Potential hardcoded secret: {name}",
                    severity="HIGH",
                    evidence=f"{p}: ...{snippet}...",
                    impact="Hardcoded secrets can be extracted from the app package and used to access backend services or third-party APIs.",
                    location=str(p),
                    recommendation="Remove secrets from client apps; rotate exposed credentials; use short-lived tokens and backend-mediated access.",
                    cwe=cwe,
                    confidence="HIGH",
                ))

    ensure_dir(out_raw)
    write_text(out_raw / "secrets_findings.json", json.dumps([asdict(f) for f in findings], indent=2))
    return findings

# -----------------------------
# Orchestrator
# -----------------------------

def detect_platform(app: Path) -> str:
    ext = app.suffix.lower()
    if ext in (".apk", ".aab", ".xapk"):
        return "android"
    if ext == ".ipa":
        return "ios"
    raise ValueError(f"Unsupported file type: {ext}")

def print_engine_status(name: str, status: str, color_enabled: bool) -> None:
    col = "green" if status == "OK" else "gray" if status.startswith("SKIP") else "yellow"
    print(f"{c('[ENGINE]', 'bold', color_enabled)} {name}: {c(status, col, color_enabled)}")

def print_finding(f: Finding, color_enabled: bool) -> None:
    sev_col = SEV_COLOR.get(f.severity.upper(), "gray")
    sev_tag = c(f"[{f.severity.upper():8}]", sev_col, color_enabled)
    eng = c(f.engine, "dim", color_enabled)
    print(f"{sev_tag} {eng} {f.title}")
    if f.location:
        print(f"  {c('location:', 'dim', color_enabled)} {f.location}")
    print(f"  {c('evidence:', 'dim', color_enabled)} {f.evidence[:220]}")

def main() -> int:
    ap = argparse.ArgumentParser(description="appsec-binary: APK/IPA static analysis orchestrator (MVP)")
    ap.add_argument("app", help="Path to APK/AAB/XAPK/IPA")
    ap.add_argument("-o", "--out", default="appsec_reports", help="Output directory")
    ap.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    ap.add_argument("--no-color", action="store_true", help="Disable colored output")
    ap.add_argument("--no-mobsf", action="store_true", help="Skip MobSF")
    ap.add_argument("--mobsf-url", default="http://127.0.0.1:8000", help="MobSF URL")
    ap.add_argument("--mobsf-api-key", default=os.environ.get("MOBSF_API_KEY", ""), help="MobSF API key or env MOBSF_API_KEY")
    ap.add_argument("--no-docker", action="store_true", help="Do not start MobSF docker automatically")
    ap.add_argument("--top", type=int, default=25, help="Show top N findings on console (default: 25)")
    args = ap.parse_args()

    color_enabled = supports_color() and not args.no_color

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s"
    )

    app = Path(args.app).expanduser().resolve()
    if not app.exists():
        print(c("[-] File not found:", "red", color_enabled), app)
        return 1

    platform = detect_platform(app)
    h = sha256_file(app)
    run_id = f"{app.stem}_{h[:12]}"
    out_root = Path(args.out) / run_id
    raw = out_root / "raw"
    ensure_dir(raw)

    started = time.time()
    findings: list[Finding] = []
    raw_outputs: dict[str, Any] = {}

    print(c("Analyzing:", "bold", color_enabled), app.name, c(f"({platform})", "dim", color_enabled))
    print(c("Output:", "bold", color_enabled), out_root)
    print()

    # MobSF
    if args.no_mobsf:
        print_engine_status("MobSF", "SKIP (disabled)", color_enabled)
    elif not args.mobsf_api_key:
        print_engine_status("MobSF", "SKIP (MOBSF_API_KEY missing)", color_enabled)
    else:
        try:
            if not args.no_docker:
                mobsf_start_docker()
            mobsf_wait(args.mobsf_url)
            report = mobsf_scan(app, raw / "mobsf", args.mobsf_url, args.mobsf_api_key)
            raw_outputs["mobsf"] = {"report": "raw/mobsf/mobsf_report.json"}
            findings.extend(mobsf_extract_findings(report))
            print_engine_status("MobSF", "OK", color_enabled)
        except Exception as e:
            print_engine_status("MobSF", f"WARN ({e})", color_enabled)

    # Platform engines
    if platform == "android":
        raw_outputs["unpack"] = android_unpack(app, raw)
        print_engine_status("unzip", "OK", color_enabled)

        raw_outputs["apktool"] = android_apktool(app, raw)
        print_engine_status("apktool", "OK" if "out_dir" in raw_outputs["apktool"] else f"SKIP ({raw_outputs['apktool'].get('skipped')})", color_enabled)

        raw_outputs["jadx"] = android_jadx(app, raw)
        print_engine_status("jadx", "OK" if "out_dir" in raw_outputs["jadx"] else f"SKIP ({raw_outputs['jadx'].get('skipped')})", color_enabled)

        raw_outputs["apkleaks"] = android_apkleaks(app, raw)
        print_engine_status("apkleaks", "OK" if "returncode" in raw_outputs["apkleaks"] else f"SKIP ({raw_outputs['apkleaks'].get('skipped')})", color_enabled)

        raw_outputs["quark"] = android_quark(app, raw)
        print_engine_status("quark", "OK" if "report" in raw_outputs["quark"] else f"SKIP ({raw_outputs['quark'].get('skipped')})", color_enabled)

        # Secret scan root preference: JADX > apktool > unzip
        jadx_dir = raw / "jadx"
        apktool_dir = raw / "apktool"
        unzip_dir = raw / "apk_unzipped"
        secret_root = jadx_dir if jadx_dir.exists() else apktool_dir if apktool_dir.exists() else unzip_dir

        secret_findings = scan_secrets(secret_root, raw)
        findings.extend(secret_findings)
        print_engine_status("secrets", "OK" if secret_findings else "OK (0 findings)", color_enabled)

    else:
        ios_unpack_res = ios_unpack(app, raw)
        raw_outputs["unpack"] = ios_unpack_res
        print_engine_status("unzip", "OK", color_enabled)

        unzipped = Path(ios_unpack_res["unzipped_dir"])
        raw_outputs["entitlements"] = ios_codesign_entitlements(unzipped, raw)
        if "app_bundle" in raw_outputs["entitlements"]:
            print_engine_status("codesign-entitlements", "OK", color_enabled)
        else:
            print_engine_status("codesign-entitlements", f"SKIP ({raw_outputs['entitlements'].get('skipped')})", color_enabled)

        secret_findings = scan_secrets(unzipped, raw)
        findings.extend(secret_findings)
        print_engine_status("secrets", "OK" if secret_findings else "OK (0 findings)", color_enabled)

    finished = time.time()

    # Save normalized report
    ensure_dir(out_root)

    result = RunResult(
        file=str(app),
        sha256=h,
        platform=platform,
        started_at=started,
        finished_at=finished,
        findings=findings,
        raw_outputs=raw_outputs,
    )

    report_payload = {
        "meta": {
            "file": result.file,
            "sha256": result.sha256,
            "platform": result.platform,
            "started_at": result.started_at,
            "finished_at": result.finished_at,
            "duration_sec": round(result.finished_at - result.started_at, 2),
        },
        "findings": [asdict(f) for f in result.findings],
        "raw_outputs": result.raw_outputs,
    }

    write_text(out_root / "report.json", json.dumps(report_payload, indent=2))

    # Console + summary
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    sorted_findings = sorted(findings, key=lambda f: sev_order.get(f.severity.upper(), 0), reverse=True)

    # summary.txt (top 50)
    lines: list[str] = []
    for f in sorted_findings[:50]:
        lines.append(f"[{f.severity.upper()}] ({f.engine}) {f.title}")
        if f.location:
            lines.append(f"  location: {f.location}")
        lines.append(f"  evidence: {f.evidence[:400]}")
    write_text(out_root / "summary.txt", "\n".join(lines) + "\n")

    print()
    print(c("Findings:", "bold", color_enabled), len(findings), c(f"(duration {round(finished-started,2)}s)", "dim", color_enabled))
    if not sorted_findings:
        print(c("No findings produced by enabled engines.", "gray", color_enabled))
    else:
        print(c(f"Top {min(args.top, len(sorted_findings))}:", "bold", color_enabled))
        for f in sorted_findings[:args.top]:
            print_finding(f, color_enabled)

    print()
    print(c("Saved:", "bold", color_enabled), out_root / "report.json")
    print(c("Saved:", "bold", color_enabled), out_root / "summary.txt")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
