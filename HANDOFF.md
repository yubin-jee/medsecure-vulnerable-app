# SecureFlow — Project Status & Handoff Document

## What This Is

A take-home project for Cognition (Devin) Solutions Engineer role. The task: pick a client scenario and build a working automation using Devin + Devin API. We chose **Client C: MedSecure** — "Our security backlog is a compliance risk." CodeQL flags dozens of issues weekly, engineers ignore them, audits flag the company.

**SecureFlow** is an automated security remediation pipeline: CodeQL finds vulnerabilities → orchestrator prioritizes and dispatches to Devin → Devin creates PRs with fixes → team reviews → alerts resolved. Closed loop.

---

## Architecture

```
GitHub Repo (medsecure-vulnerable-app)
    │
    ├── CodeQL scans on push → produces alerts
    │
    ▼
SecureFlow Orchestrator (Python)
    │
    ├── Step 1: INGEST — polls GitHub API for open CodeQL alerts
    ├── Step 2: PRIORITIZE — groups by rule+file, sorts critical-first
    ├── Step 3: DISPATCH — creates Devin sessions (max 3 concurrent)
    ├── Step 4: MONITOR — polls Devin API for session status
    ├── Step 4.5: CHECKS — verifies PR CodeQL status, retries failures
    ├── Step 5: NOTIFY — sends Slack notifications
    └── Saves state.json for dashboard
    │
    ▼
Dashboard (FastAPI + Jinja2)    Slack Notifications
    localhost:8080               webhook messages
```

---

## File Structure

```
~/secureflow/
├── orchestrator/
│   ├── .env                 # Credentials (GitHub PAT, Devin API key, Slack webhook)
│   ├── .env.example
│   ├── config.py            # Config dataclass, reads .env
│   ├── ingest.py            # Fetches CodeQL alerts from GitHub API
│   ├── prioritize.py        # Groups alerts into batches, sorts by severity
│   ├── dispatch.py          # Creates Devin sessions with crafted prompts
│   ├── monitor.py           # Polls Devin session status, normalizes statuses
│   ├── checks.py            # Checks PR CodeQL results, sends retry messages
│   ├── notify.py            # Slack Block Kit notifications
│   ├── state.py             # JSON state persistence
│   ├── main.py              # Pipeline orchestrator (once/continuous/status modes)
│   ├── requirements.txt
│   └── state.json           # Current state (auto-generated)
├── dashboard/
│   ├── app.py               # FastAPI web server
│   └── templates/
│       └── dashboard.html   # Dark-themed dashboard UI
└── demo-vulnerable-app/     # Pushed to GitHub as yubin-jee/medsecure-vulnerable-app
    ├── .github/workflows/codeql.yml
    ├── package.json
    └── src/
        ├── app.js
        ├── routes/
        │   ├── patients.js  # SQL injection x6
        │   ├── auth.js      # SQL injection x3, hardcoded creds, weak crypto
        │   ├── reports.js   # Command injection x3, path traversal x2, SSRF
        │   ├── admin.js     # XSS x2, open redirect, prototype pollution
        │   └── api.js       # SQL injection, ReDoS, log injection, unsafe deser
        └── utils/
            └── database.js  # SQLite setup + seed data
```

---

## Current State (as of Feb 24 evening)

### What's Working
- **GitHub repo**: `yubin-jee/medsecure-vulnerable-app` — public, CodeQL enabled
- **CodeQL**: 41 alerts generated (40 still open, 1 fixed). 5 critical, 32 high, 4 medium
- **Orchestrator**: Runs end-to-end. Has processed 14 of 41 alerts across 6 sessions
- **Devin sessions**: 6 created total. 4 finished with PRs, 2 still running
- **PRs created**: 7 PRs (PR #1-7), all open. PR #2 was closed
- **Slack**: Initial scan notification sent successfully. PR completion notifications working
- **Dashboard**: Serves on localhost:8080, shows metrics/chart/sessions/queue
- **Retry logic**: checks.py written to detect failing CodeQL checks and send Devin retry messages

### What's NOT Working / Needs Attention

1. **Dashboard can only be tested outside Claude Code sandbox** — the sandbox blocks outbound HTTP from Python. All `python3 main.py` and `python3 dashboard/app.py` commands must be run in a separate terminal.

2. **Some PRs have failing CodeQL checks** — PRs #1, #5, #6 had CodeQL failures. The retry logic (checks.py) was written but needs to be tested by running the orchestrator again. PR #7 was created as a retry for PR #1.

3. **Dashboard needs FastAPI/uvicorn/jinja2 installed** — `pip3 install fastapi uvicorn jinja2` must be run outside the sandbox.

4. **Python 3.9 on this machine** — all files use `from __future__ import annotations` to handle modern type syntax.

5. **Batch info for early sessions is incomplete** — sessions from the first run (batch-003, batch-005, batch-012) don't have batch_info in state.json because that feature was added later. The dashboard will show empty descriptions for those.

---

## Credentials (in .env)

```
GITHUB_TOKEN=<set in .env>
GITHUB_OWNER=yubin-jee
GITHUB_REPO=medsecure-vulnerable-app
DEVIN_API_KEY=<set in .env>
SLACK_WEBHOOK_URL=<set in .env>
```

Sandbox allowlist domains (in ~/.claude/apple/dangerous_allowed_domains.csv):
- api.github.com, github.com, api.devin.ai, hooks.slack.com, pypi.org, files.pythonhosted.org

---

## How to Run

```bash
# Install deps (must be outside Claude Code sandbox)
pip3 install requests python-dotenv fastapi uvicorn jinja2

# Run orchestrator (processes next batch of alerts)
cd ~/secureflow/orchestrator && python3 main.py --mode once

# Run orchestrator continuously (polls every 30s)
cd ~/secureflow/orchestrator && python3 main.py --mode continuous

# Check status without running pipeline
cd ~/secureflow/orchestrator && python3 main.py --mode status

# Start dashboard
cd ~/secureflow && python3 dashboard/app.py
# Then open http://localhost:8080
```

---

## Demo Checklist

### Must-Have for Video
- [ ] Dashboard showing real data (alerts, sessions, PRs, queue)
- [ ] Run orchestrator live to show alerts being ingested and dispatched
- [ ] Show Devin creating a PR in real-time (or show a completed one)
- [ ] Show Slack notification arriving
- [ ] Show the retry flow — failing PR → Devin gets sent back → fixes it
- [ ] Show the burndown chart moving (run orchestrator multiple times)
- [ ] Walk through the code briefly (show the prompt engineering in dispatch.py)

### Nice-to-Have
- [ ] Show continuous mode running in background
- [ ] Show what happens when all critical alerts are resolved
- [ ] Polish dashboard further (loading states, error states)
- [ ] Add a "dismiss as false positive" button in dashboard
- [ ] Show the weekly digest Slack notification

### Things to Fix Before Recording
1. **Run orchestrator 2-3 more times** to process more batches and populate the burndown chart with more data points
2. **Verify the retry flow works** — run `main.py --mode once` and check if PRs with failing checks get retried
3. **Merge a passing PR** to show the full lifecycle (alert → fix → PR → merge → alert closed)
4. **Check dashboard rendering** — make sure the session table shows descriptions properly for all sessions
5. **Test Slack notifications** — verify PR-ready and retry notifications come through

---

## Video Script (5-10 min)

### 0:00-1:30 — The Problem
"MedSecure has 40+ CodeQL security alerts piling up. Their security team files them, engineering ignores them because they're not sprint work. Last audit flagged them. Here's what their GitHub security tab looks like..." [show the alerts]

### 1:30-3:00 — The Solution
"SecureFlow connects three systems: GitHub's CodeQL scanner, Devin for automated fixes, and your team's Slack. Here's how it works..." [show architecture, walk through the pipeline steps]

### 3:00-5:30 — Live Demo
"Let me run the orchestrator..." [run main.py, show it ingesting alerts, prioritizing, dispatching to Devin]
"Devin is now working on 3 fixes simultaneously. Let's look at one that already finished..." [show a PR Devin created]
"And here's the Slack notification the security team gets..." [show Slack]

### 5:30-7:00 — The Dashboard
"The dashboard gives the security team and management a single view..." [walk through metrics, burndown, sessions, queue]
"Notice the Action Required banner — these are PRs ready for engineer review. The team doesn't have to go hunting."

### 7:00-8:00 — Handling Failures
"What happens when Devin's fix isn't perfect? Here's PR #1 — CodeQL still flags 1 remaining alert. SecureFlow detected this automatically, sent Devin back to fix it, and PR #7 is the retry. This is the closed loop."

### 8:00-9:00 — Why Devin
"Other AI coding tools give you suggestions. Devin actually does the work — it clones the repo, reads the code, writes the fix, runs tests, and creates a PR. And because it's API-driven, we can build this entire pipeline around it."

### 9:00-10:00 — Next Steps
"Phase 1 is what you've seen — burn down the existing backlog. Phase 2: run SecureFlow on every new PR, so vulnerabilities never pile up again. Phase 3: expand beyond CodeQL to Snyk, Semgrep, or any SAST tool. And Phase 4: integrate with your ticketing system so security findings automatically become tracked work."

---

## What Makes This Project Strong

1. **End-to-end working system** — not a mockup. Real repo, real CodeQL alerts, real Devin sessions, real PRs, real Slack messages.

2. **Closed-loop retry** — most demos would stop at "Devin creates a PR." We go further: if the PR still has failing checks, we automatically send Devin back to fix the remaining issues.

3. **Human-in-the-loop design** — the automation handles the toil, but humans review every PR. The dashboard and Slack notifications keep the right people informed without creating noise.

4. **Prioritization** — doesn't just throw all 41 alerts at Devin. Groups related issues, sorts by severity, rate-limits concurrent sessions. Shows engineering judgment, not just API calls.

5. **Demo-friendly** — the vulnerable app has intentional, well-categorized vulnerabilities that CodeQL reliably detects. The dashboard is visually compelling. The Slack messages use Block Kit formatting.

---

## What's Lacking / Could Be Improved

1. **Dashboard polish** — the queue section was recently rewritten and may need visual tweaks. Session descriptions for early batches (before batch_info was added to state) show empty.

2. **No authentication** — dashboard is open. In production you'd add auth.

3. **No persistent database** — uses JSON file. Fine for demo, not for production.

4. **Retry logic untested** — checks.py was written but the full retry cycle (detect failure → message Devin → Devin pushes fix → check passes) hasn't been verified end-to-end.

5. **Burndown chart has few data points** — needs more orchestrator runs to show a compelling trend line.

6. **No "dismiss as false positive" flow** — would be a nice addition to show in the dashboard.

7. **Continuous mode not demoed** — the `--mode continuous` polling loop works but hasn't been stress-tested.

---

## Context for Next Claude Session

The user (Yubin) is building this for a Cognition (Devin) Solutions Engineer take-home. Everything is at `~/secureflow/`. The GitHub repo is `yubin-jee/medsecure-vulnerable-app`. The orchestrator has been run ~3 times, creating 6 Devin sessions and 7 PRs. The main remaining work is:

1. Testing and polish — run the orchestrator more times, verify the retry flow, get the burndown chart populated
2. Dashboard visual polish — Yubin called the queue section "ugly" and it was rewritten but needs verification
3. Recording the Loom video — 5-10 minutes, presenting to MedSecure's VP of Engineering
4. Submitting at https://you.ashbyhq.com/cognition/assignment/b9c7bdfc-4f37-4cc4-bcb6-e3072e375078

The sandbox blocks all outbound HTTP from Python — all `python3` commands must run in a separate terminal. Claude Code can only use `curl` for API calls.

Key architectural decisions to know:
- Batches group alerts by (rule_id + file_path) so Devin fixes related issues together
- Max 3 concurrent Devin sessions to avoid overwhelming the team with PRs
- Status normalization: Devin returns "working" which we map to "running"
- State persistence via state.json — tracks sessions, processed alerts, history, batch metadata
- Dashboard reads state.json + live GitHub data; auto-refreshes every 30s
