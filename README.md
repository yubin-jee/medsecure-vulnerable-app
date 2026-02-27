# SecureFlow

Automated security remediation pipeline for healthcare applications. Ingests CodeQL alerts, dispatches fixes to [Devin](https://devin.ai), verifies PRs pass checks, and notifies the right people at each step.

Built for **MedSecure** — a healthcare company with 41 unpatched CodeQL vulnerabilities creating HIPAA compliance risk.

## How It Works

```
CodeQL finds vulnerabilities
        ↓
SecureFlow prioritizes by severity (critical → high → medium → low)
        ↓
Devin creates PRs with fixes (max 3 concurrent sessions)
        ↓
CodeQL re-runs on each PR
        ↓
  ┌─ Passing → notify #engineering for review
  ├─ Failing → send Devin a retry with specific alert details
  └─ Out-of-scope alert → flag for human review in #security
        ↓
Dashboard tracks the full lifecycle + HIPAA business impact
```

## Quick Start

```bash
# Install dependencies
pip3 install requests python-dotenv fastapi uvicorn jinja2

# Configure credentials
cp orchestrator/.env.example orchestrator/.env
# Edit .env with your GitHub PAT, Devin API key, and Slack webhook URL

# Run the pipeline (single pass)
cd orchestrator && python3 main.py --mode once

# Run continuously (polls every 30s)
cd orchestrator && python3 main.py --mode continuous

# Start the dashboard
cd .. && python3 dashboard/app.py
# Open http://localhost:8080
```

## Project Structure

```
secureflow/
├── orchestrator/
│   ├── main.py          # Pipeline entry point (once/continuous/status modes)
│   ├── ingest.py        # Fetches CodeQL alerts from GitHub API
│   ├── prioritize.py    # Groups alerts by rule+file, sorts by severity
│   ├── dispatch.py      # Creates Devin sessions with crafted prompts
│   ├── monitor.py       # Polls Devin API for session status
│   ├── checks.py        # Verifies PR CodeQL results, sends retries
│   ├── notify.py        # Slack notifications (Block Kit)
│   ├── state.py         # JSON state persistence
│   └── config.py        # Configuration from .env
├── dashboard/
│   ├── app.py           # FastAPI web server + business impact computation
│   └── templates/
│       └── dashboard.html
└── src/                 # MedSecure patient portal (intentionally vulnerable)
    ├── routes/
    │   ├── patients.js  # SQL injection, missing rate limiting
    │   ├── auth.js      # SQL injection, hardcoded credentials
    │   ├── reports.js   # Command injection, path traversal, SSRF
    │   ├── admin.js     # XSS, open redirect
    │   └── api.js       # SQL injection, ReDoS, unsafe deserialization
    └── utils/
        └── database.js
```

## Dashboard

The dashboard has two sections:

**Remediation Pipeline** — Five cards showing where every alert sits in the lifecycle: Detected → Devin Working → PR Created → Engineer Review → Resolved.

**Business Impact** — Healthcare-specific metrics with hover tooltips showing the math:
- **HIPAA Risk Exposure** — Estimated fines based on HIPAA Tier 3/4 penalty schedules for unpatched known vulnerabilities
- **Mean Time to Fix** — Devin's average vs industry benchmark (58 days)
- **Breach Risk Reduced** — Dollar value of risk eliminated, weighted by vulnerability type (IBM 2024 Healthcare Breach Report, $408/record)

Below that, the operations section shows action items, burndown chart, active sessions, and the remediation queue.

## Slack Notifications

Notifications are routed to the right audience:
- `#security` — Initial scan report, failed sessions, human review needed
- `#engineering` — Per-PR review requests with fix details and direct links
- `#all` — Weekly burndown digest for management

## Configuration

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | GitHub Personal Access Token with `repo` and `security_events` scopes |
| `GITHUB_OWNER` | Repository owner (e.g., `yubin-jee`) |
| `GITHUB_REPO` | Repository name (e.g., `medsecure-vulnerable-app`) |
| `DEVIN_API_KEY` | Devin API key |
| `SLACK_WEBHOOK_SECURITY` | Webhook for #security channel |
| `SLACK_WEBHOOK_ENGINEERING` | Webhook for #engineering channel |
| `SLACK_WEBHOOK_URL` | Fallback webhook if channel-specific ones aren't set |
| `MAX_CONCURRENT_SESSIONS` | Max parallel Devin sessions (default: 3) |
| `POLL_INTERVAL_SECONDS` | Polling interval in continuous mode (default: 30) |
| `DEMO_MODE` | When `true`, prioritizes a curated set of vulnerability types for demo variety |

## Demo Notes

The demo video uses a few standard techniques to showcase the full system in a controlled environment:

**Curated alert set (DEMO_MODE).** When `DEMO_MODE=true` is set in `.env`, the prioritization engine boosts a curated set of 5 vulnerability types (command injection, SSRF, path traversal, remote property injection, SQL injection) to the front of the dispatch queue. This ensures the first batch of Devin sessions showcases a variety of fix strategies rather than just the highest-severity alerts. Set `DEMO_MODE=false` or remove it to revert to normal critical-first prioritization.

**GitHub Actions workflow.** A [`secureflow.yml`](.github/workflows/secureflow.yml) workflow is included to demonstrate CI/CD integration — SecureFlow can run as a scheduled GitHub Action triggered by new CodeQL alerts. For the demo, the pipeline was run locally (`python3 main.py`) because the dashboard reads from a local `state.json` file and the two environments (GitHub Actions runner and local machine) don't share state. In production, this would be solved by persisting state to a shared store (database, S3, etc.) rather than a local JSON file.

**Live data, real APIs.** All data shown in the demo is real — actual CodeQL alerts from GitHub, actual Devin sessions creating actual PRs, actual Slack notifications. Nothing is mocked or pre-recorded.
