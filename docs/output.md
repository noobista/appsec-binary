# Output Format

## Directory Structure

appsec_reports/<appname>_<hash>/
├─ report.json
├─ summary.txt
└─ raw/


---

## report.json

Machine-readable normalized output.

Each finding includes:

- engine
- title
- severity (INFO / LOW / MEDIUM / HIGH / CRITICAL)
- evidence
- impact
- location (if available)
- recommendation (if available)
- CWE (best-effort)
- confidence

Designed for:
- Report generation
- CI/CD ingestion
- Future SARIF export

---

## summary.txt

Human-readable top findings, ordered by severity.

Used for:
- Quick triage
- Management summaries
- Manual validation planning

---

## Console Output

- Color-coded by severity
- Engine execution status shown
- `--verbose` prints command execution and debug logs

Colors auto-disable when output is redirected.
