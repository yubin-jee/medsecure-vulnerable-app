# Dashboard WOW Features Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a pipeline flow visualization and healthcare business impact metrics to the SecureFlow dashboard, making the "closing the loop" story immediately visible.

**Architecture:** Two new dashboard sections added to the existing FastAPI + Jinja2 template. All computation happens in `dashboard/app.py` using data already available from state.json and the GitHub API. No new dependencies, no orchestrator changes.

**Tech Stack:** Python (FastAPI), Jinja2 templates, CSS (existing dark theme), Chart.js (already loaded)

---

### Task 1: Add pipeline stage computation to dashboard backend

**Files:**
- Modify: `dashboard/app.py:40-68` (add new functions after `enrich_sessions`)

**Step 1: Add the `compute_pipeline_stages` function to `dashboard/app.py`**

Add this function after the `enrich_sessions` function (after line 68):

```python
def compute_pipeline_stages(alert_summary, session_dicts, queued_batches):
    """Compute alert counts for each pipeline stage."""
    total_open = alert_summary.get("total", 0)

    # Count alerts in each session status
    devin_working = 0
    pr_created = 0
    engineer_review = 0
    resolved = 0

    for s in session_dicts:
        alert_count = len(s.get("alert_numbers", []))
        status = s.get("status", "")
        if status in ("running", "working", "blocked"):
            devin_working += alert_count
        elif status == "finished" and s.get("pr_url"):
            pr_created += alert_count
        elif status == "needs_human_review":
            engineer_review += alert_count
        elif status in ("merged", "closed"):
            resolved += alert_count

    # "Detected" = total open alerts minus those already in the pipeline
    in_pipeline = devin_working + pr_created + engineer_review
    detected = max(0, total_open - in_pipeline)

    return {
        "detected": detected,
        "devin_working": devin_working,
        "pr_created": pr_created,
        "engineer_review": engineer_review,
        "resolved": resolved,
    }
```

**Step 2: Verify the function handles edge cases**

The function uses `max(0, ...)` for detected to avoid negative counts when state and live data are slightly out of sync. No test file exists in this project (it's a demo), so verify by reading the logic.

**Step 3: Commit**

```bash
git add dashboard/app.py
git commit -m "feat(dashboard): add pipeline stage computation"
```

---

### Task 2: Add business impact computation to dashboard backend

**Files:**
- Modify: `dashboard/app.py` (add constants at top, add new function after `compute_pipeline_stages`)

**Step 1: Add healthcare constants after the imports (after line 31, before the `app = FastAPI(...)` line)**

```python
# Healthcare business impact constants
# HIPAA penalty tiers (inflation-adjusted 2024, per 42 USC 1320d-5 / HITECH Act)
HIPAA_TIER3_PER_VIOLATION = 13_785   # willful neglect, corrected within 30 days
HIPAA_TIER4_PER_VIOLATION = 68_928   # willful neglect, NOT corrected within 30 days
# IBM Cost of a Data Breach 2024 — healthcare sector
BREACH_COST_PER_RECORD = 408
ESTIMATED_RECORDS_AT_RISK = 50_000   # MedSecure patient database estimate
AVG_BREACH_COST_HEALTHCARE = 9_770_000
# Industry average MTTR for code vulnerabilities
INDUSTRY_AVG_MTTR_DAYS = 58
# Vulnerability type weights — higher weight = more direct PHI exposure risk
VULN_RISK_WEIGHTS = {
    "SQL Injection": 1.5,
    "Command Injection": 1.5,
    "Hardcoded Credentials": 1.5,
    "Weak Cryptography": 1.3,
    "Insufficient Key Size": 1.3,
    "Stored XSS": 1.2,
    "Cross-Site Scripting (XSS)": 1.2,
    "Server-Side Request Forgery": 1.2,
    "Path Traversal": 1.2,
    "Unsafe Deserialization": 1.2,
}
DEFAULT_VULN_WEIGHT = 1.0
```

**Step 2: Add the `compute_business_impact` function after `compute_pipeline_stages`**

```python
def compute_business_impact(alert_summary, session_dicts, batch_info):
    """Compute healthcare-specific business impact metrics."""
    by_sev = alert_summary.get("by_severity", {})
    critical_open = by_sev.get("critical", 0)
    high_open = by_sev.get("high", 0)

    # Metric 1: HIPAA Risk Exposure
    # Critical alerts treated as Tier 4 (willful neglect, not corrected)
    # High alerts treated as Tier 3 (willful neglect, corrected within 30 days)
    hipaa_exposure = (
        critical_open * HIPAA_TIER4_PER_VIOLATION
        + high_open * HIPAA_TIER3_PER_VIOLATION
    )

    # Metric 2: MTTR — average time from session creation to PR creation
    mttr_minutes = None
    session_times = []
    for s in session_dicts:
        if s.get("pr_url") and s.get("created_at") and s.get("updated_at"):
            try:
                from datetime import datetime
                created = datetime.fromisoformat(s["created_at"].replace("Z", "+00:00"))
                updated = datetime.fromisoformat(s["updated_at"].replace("Z", "+00:00"))
                delta = (updated - created).total_seconds() / 60
                if delta > 0:
                    session_times.append(delta)
            except (ValueError, TypeError):
                pass
    if session_times:
        mttr_minutes = round(sum(session_times) / len(session_times))

    # Metric 3: Breach Risk Reduction
    # What proportion of the total vulnerability surface have we eliminated?
    resolved_alerts = 0
    total_tracked = alert_summary.get("total", 0)
    weighted_resolved = 0.0
    weighted_total = 0.0

    for s in session_dicts:
        alert_count = len(s.get("alert_numbers", []))
        # Look up the category from batch_info to determine weight
        info = batch_info.get(s.get("batch_id", ""), {})
        category = info.get("category", "")
        weight = VULN_RISK_WEIGHTS.get(category, DEFAULT_VULN_WEIGHT)

        weighted_total += alert_count * weight
        if s.get("status") in ("merged", "closed", "finished"):
            resolved_alerts += alert_count
            weighted_resolved += alert_count * weight

    # Add unprocessed alerts to total with default weight
    unprocessed = max(0, total_tracked - sum(
        len(s.get("alert_numbers", [])) for s in session_dicts
    ))
    weighted_total += unprocessed * DEFAULT_VULN_WEIGHT

    # Risk reduction as proportion of estimated breach exposure
    if weighted_total > 0:
        risk_reduced = round(
            (weighted_resolved / weighted_total) * AVG_BREACH_COST_HEALTHCARE
        )
    else:
        risk_reduced = 0

    return {
        "hipaa_exposure": hipaa_exposure,
        "mttr_minutes": mttr_minutes,
        "industry_mttr_days": INDUSTRY_AVG_MTTR_DAYS,
        "risk_reduced": risk_reduced,
        "resolved_alerts": resolved_alerts,
    }
```

**Step 3: Commit**

```bash
git add dashboard/app.py
git commit -m "feat(dashboard): add healthcare business impact computation"
```

---

### Task 3: Wire new computations into the dashboard route

**Files:**
- Modify: `dashboard/app.py:71-117` (the `dashboard()` route handler)

**Step 1: Add pipeline_stages and business_impact to the template context**

In the `dashboard()` function, after the line `session_dicts = enrich_sessions(...)` (line 103) and before the `return templates.TemplateResponse(...)` (line 105), add:

```python
    # Compute pipeline stages for flow visualization
    pipeline_stages = compute_pipeline_stages(alert_summary, session_dicts, queued_batches)

    # Compute business impact metrics
    batch_info = state.get("batch_info", {})
    business_impact = compute_business_impact(alert_summary, session_dicts, batch_info)
```

Then add these two new keys to the template context dict (inside the `TemplateResponse` call):

```python
            "pipeline_stages": pipeline_stages,
            "business_impact": business_impact,
```

**Step 2: Commit**

```bash
git add dashboard/app.py
git commit -m "feat(dashboard): wire pipeline stages and business impact into template"
```

---

### Task 4: Add pipeline flow bar CSS to the template

**Files:**
- Modify: `dashboard/templates/dashboard.html:8-201` (inside the `<style>` block)

**Step 1: Add pipeline flow bar styles**

Add the following CSS before the closing `</style>` tag (before line 201):

```css
        /* Pipeline flow bar */
        .pipeline {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: var(--bg-2);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 20px 24px;
            margin-bottom: 20px;
            position: relative;
        }
        .pipeline-stage {
            display: flex;
            flex-direction: column;
            align-items: center;
            flex: 1;
            position: relative;
            z-index: 1;
        }
        .pipeline-stage .stage-num {
            font-size: 28px;
            font-weight: 700;
            line-height: 1;
        }
        .pipeline-stage .stage-lbl {
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-2);
            margin-top: 6px;
        }
        .pipeline-stage .stage-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-bottom: 8px;
        }
        .pipeline-arrow {
            color: var(--border);
            font-size: 18px;
            flex-shrink: 0;
            padding: 0 4px;
            margin-top: -14px;
        }
        .stage-neutral .stage-num { color: var(--text-1); }
        .stage-neutral .stage-dot { background: var(--text-2); }
        .stage-blue .stage-num { color: var(--blue); }
        .stage-blue .stage-dot { background: var(--blue); animation: blink 1.4s infinite; }
        .stage-purple .stage-num { color: var(--purple); }
        .stage-purple .stage-dot { background: var(--purple); }
        .stage-orange .stage-num { color: var(--orange); }
        .stage-orange .stage-dot { background: var(--orange); }
        .stage-green .stage-num { color: var(--green); }
        .stage-green .stage-dot { background: var(--green); }

        /* Business impact card */
        .impact-metrics {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
            margin-bottom: 20px;
        }
        .impact-metric {
            background: var(--bg-2);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 16px;
            text-align: center;
        }
        .impact-metric .im-num { font-size: 28px; font-weight: 700; }
        .impact-metric .im-lbl {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.4px;
            color: var(--text-2);
            margin-bottom: 4px;
        }
        .impact-metric .im-sub {
            font-size: 10px;
            color: var(--text-2);
            margin-top: 4px;
            line-height: 1.4;
        }
        .impact-metric .im-compare {
            font-size: 11px;
            color: var(--text-2);
            margin-top: 6px;
        }
        .impact-metric .im-compare span { color: var(--text-1); }
```

**Step 2: Commit**

```bash
git add dashboard/templates/dashboard.html
git commit -m "feat(dashboard): add CSS for pipeline flow bar and business impact card"
```

---

### Task 5: Add pipeline flow bar HTML to the template

**Files:**
- Modify: `dashboard/templates/dashboard.html:246-248` (between the metrics div closing and the action items section)

**Step 1: Add the pipeline flow bar HTML**

Insert the following HTML after the closing `</div>` of the metrics section (after line 246, before the `<!-- Action items -->` comment on line 249):

```html
        <!-- Pipeline Flow -->
        <div class="pipeline">
            <div class="pipeline-stage stage-neutral">
                <div class="stage-dot"></div>
                <div class="stage-num">{{ pipeline_stages.detected }}</div>
                <div class="stage-lbl">Detected</div>
            </div>
            <div class="pipeline-arrow">&#9654;</div>
            <div class="pipeline-stage stage-blue">
                <div class="stage-dot"></div>
                <div class="stage-num">{{ pipeline_stages.devin_working }}</div>
                <div class="stage-lbl">Devin Working</div>
            </div>
            <div class="pipeline-arrow">&#9654;</div>
            <div class="pipeline-stage stage-purple">
                <div class="stage-dot"></div>
                <div class="stage-num">{{ pipeline_stages.pr_created }}</div>
                <div class="stage-lbl">PR Created</div>
            </div>
            <div class="pipeline-arrow">&#9654;</div>
            <div class="pipeline-stage stage-orange">
                <div class="stage-dot"></div>
                <div class="stage-num">{{ pipeline_stages.engineer_review }}</div>
                <div class="stage-lbl">Engineer Review</div>
            </div>
            <div class="pipeline-arrow">&#9654;</div>
            <div class="pipeline-stage stage-green">
                <div class="stage-dot"></div>
                <div class="stage-num">{{ pipeline_stages.resolved }}</div>
                <div class="stage-lbl">Resolved</div>
            </div>
        </div>
```

**Step 2: Commit**

```bash
git add dashboard/templates/dashboard.html
git commit -m "feat(dashboard): add pipeline flow bar HTML"
```

---

### Task 6: Add business impact card HTML to the template

**Files:**
- Modify: `dashboard/templates/dashboard.html` (insert after the pipeline flow bar, before the action items section)

**Step 1: Add business impact metrics HTML**

Insert this HTML right after the pipeline flow bar `</div>` and before the `<!-- Action items -->` comment:

```html
        <!-- Business Impact -->
        <div class="impact-metrics">
            <div class="impact-metric">
                <div class="im-lbl">HIPAA Risk Exposure</div>
                <div class="im-num" style="color: var(--red);">
                    ${{ "{:,.0f}".format(business_impact.hipaa_exposure) }}
                </div>
                <div class="im-sub">potential fines for unpatched known vulnerabilities</div>
                <div class="im-sub" style="margin-top: 6px; font-style: italic;">
                    Based on HIPAA Tier 3/4 penalty schedules (HITECH Act)
                </div>
            </div>
            <div class="impact-metric">
                <div class="im-lbl">Mean Time to Fix</div>
                {% if business_impact.mttr_minutes is not none %}
                <div class="im-num" style="color: var(--green);">
                    ~{{ business_impact.mttr_minutes }} min
                </div>
                {% else %}
                <div class="im-num" style="color: var(--text-2);">&mdash;</div>
                {% endif %}
                <div class="im-compare">
                    Industry avg: <span>{{ business_impact.industry_mttr_days }} days</span>
                </div>
                <div class="im-sub">Devin resolves vulnerabilities in minutes, not weeks</div>
            </div>
            <div class="impact-metric">
                <div class="im-lbl">Breach Risk Reduced</div>
                <div class="im-num" style="color: var(--green);">
                    ${{ "{:,.0f}".format(business_impact.risk_reduced) }}
                </div>
                <div class="im-sub">
                    {{ business_impact.resolved_alerts }} vulnerabilities eliminated
                </div>
                <div class="im-sub" style="margin-top: 6px; font-style: italic;">
                    Based on IBM 2024 Healthcare Breach Report ($408/record)
                </div>
            </div>
        </div>
```

**Step 2: Commit**

```bash
git add dashboard/templates/dashboard.html
git commit -m "feat(dashboard): add business impact metrics card HTML"
```

---

### Task 7: Visual verification and polish

**Files:**
- Possibly modify: `dashboard/templates/dashboard.html` (minor CSS tweaks)
- Possibly modify: `dashboard/app.py` (edge case fixes)

**Step 1: Start the dashboard and verify visually**

Run in a separate terminal (outside Claude Code sandbox):

```bash
cd ~/secureflow && python3 dashboard/app.py
```

Then open http://localhost:8080 and verify:
- Pipeline flow bar renders with 5 stages, arrows between them, correct colors
- Counts are populated (not all zeros)
- "Devin Working" stage has pulsing blue dot when sessions are running
- Business impact card shows 3 metrics side by side
- HIPAA exposure shows a red dollar figure
- MTTR shows green number with industry comparison
- Breach risk reduced shows green dollar figure
- Everything fits within 1360px max-width and looks good at standard laptop widths
- Dark theme colors are consistent with existing dashboard

**Step 2: Fix any visual issues found**

Common issues to watch for:
- Pipeline bar too tall or too short — adjust padding
- Numbers formatting (too many decimal places, missing commas)
- MTTR showing `None` instead of dash when no completed sessions
- Mobile responsiveness (not critical for demo but shouldn't break)

**Step 3: Final commit**

```bash
git add -A
git commit -m "feat(dashboard): polish pipeline flow bar and business impact card"
```
