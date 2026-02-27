        1 # SecureFlow
        2
        3 Automated security remediation pipeline for healthcare applications. Ingests CodeQL
          alerts, dispatches fixes to [Devin](https://devin.ai), verifies PRs pass checks, and
           notifies the right people at each step.
        4
        5 Built for **MedSecure** — a healthcare company with 41 unpatched CodeQL vulnerabilit
          ies creating HIPAA compliance risk.
        6
        7 ## How It Works
        8
        9 ```
       10 CodeQL finds vulnerabilities
       11         ↓
       12 SecureFlow prioritizes by severity (critical → high → medium → low)
       13         ↓
       14 Devin creates PRs with fixes (max 3 concurrent sessions)
       15         ↓
       16 CodeQL re-runs on each PR
       17         ↓
       18   ┌─ Passing → notify #engineering for review
       19   ├─ Failing → send Devin a retry with specific alert details
       20   └─ Out-of-scope alert → flag for human review in #security
       21         ↓
       22 Dashboard tracks the full lifecycle + HIPAA business impact
       23 ```
       24
       25 ## Quick Start
       26
       27 ```bash
       28 # Install dependencies
       29 pip3 install requests python-dotenv fastapi uvicorn jinja2
       30
       31 # Configure credentials
       32 cp orchestrator/.env.example orchestrator/.env
       33 # Edit .env with your GitHub PAT, Devin API key, and Slack webhook URL
       34
       35 # Run the pipeline (single pass)
       36 cd orchestrator && python3 main.py --mode once
       37
       38 # Run continuously (polls every 30s)
       39 cd orchestrator && python3 main.py --mode continuous
       40
       41 # Start the dashboard
       42 cd .. && python3 dashboard/app.py
       43 # Open http://localhost:8080
       44 ```
       45
       46 ## Project Structure
       47
       48 ```
       49 secureflow/
       50 ├── orchestrator/
       51 │   ├── main.py          # Pipeline entry point (once/continuous/status modes)
       52 │   ├── ingest.py        # Fetches CodeQL alerts from GitHub API
       53 │   ├── prioritize.py    # Groups alerts by rule+file, sorts by severity
       54 │   ├── dispatch.py      # Creates Devin sessions with crafted prompts
       55 │   ├── monitor.py       # Polls Devin API for session status
       56 │   ├── checks.py        # Verifies PR CodeQL results, sends retries
       57 │   ├── notify.py        # Slack notifications (Block Kit)
       58 │   ├── state.py         # JSON state persistence
       59 │   └── config.py        # Configuration from .env
       60 ├── dashboard/
       61 │   ├── app.py           # FastAPI web server + business impact computation
       62 │   └── templates/
       63 │       └── dashboard.html
       64 └── demo-vulnerable-app/ # MedSecure patient portal (intentionally vulnerable)
       65     └── src/
       66         ├── routes/
       67         │   ├── patients.js  # SQL injection, missing rate limiting
       68         │   ├── auth.js      # SQL injection, hardcoded credentials
       69         │   ├── reports.js   # Command injection, path traversal, SSRF
       70         │   ├── admin.js     # XSS, open redirect
       71         │   └── api.js       # SQL injection, ReDoS, unsafe deserialization
       72         └── utils/
       73             └── database.js
       74 ```
       75
       76 ## Dashboard
       77
       78 The dashboard has two sections:
       79
       80 **Remediation Pipeline** — Five cards showing where every alert sits in the lifecycl
          e: Detected → Devin Working → PR Created → Engineer Review → Resolved.
       81
       82 **Business Impact** — Healthcare-specific metrics with hover tooltips showing the ma
          th:
       83 - **HIPAA Risk Exposure** — Estimated fines based on HIPAA Tier 3/4 penalty schedule
          s for unpatched known vulnerabilities
       84 - **Mean Time to Fix** — Devin's average vs industry benchmark (58 days)
       85 - **Breach Risk Reduced** — Dollar value of risk eliminated, weighted by vulnerabili
          ty type (IBM 2024 Healthcare Breach Report, $408/record)
       86
       87 Below that, the operations section shows action items, burndown chart, active sessio
          ns, and the remediation queue.
       88
       89 ## Slack Notifications
       90
       91 Notifications are routed to the right audience:
       92 - `#security` — Initial scan report, failed sessions, human review needed
       93 - `#engineering` — Per-PR review requests with fix details and direct links
       94 - `#all` — Weekly burndown digest for management
       95
       96 ## Configuration
       97
       98 | Variable | Description |
       99 |----------|-------------|
      100 | `GITHUB_TOKEN` | GitHub Personal Access Token with `repo` and `security_events` sc
          opes |
      101 | `GITHUB_OWNER` | Repository owner (e.g., `yubin-jee`) |
      102 | `GITHUB_REPO` | Repository name (e.g., `medsecure-vulnerable-app`) |
      103 | `DEVIN_API_KEY` | Devin API key |
      104 | `SLACK_WEBHOOK_SECURITY` | Webhook for #security channel |
      105 | `SLACK_WEBHOOK_ENGINEERING` | Webhook for #engineering channel |
      106 | `SLACK_WEBHOOK_URL` | Fallback webhook if channel-specific ones aren't set |
      107 | `MAX_CONCURRENT_SESSIONS` | Max parallel Devin sessions (default: 3) |
      108 | `POLL_INTERVAL_SECONDS` | Polling interval in continuous mode (default: 30) |
