# Dashboard WOW Features Design

## Context

SecureFlow is an automated security remediation pipeline for MedSecure, a healthcare company with 41 CodeQL alerts piling up. The take-home rubric emphasizes "closing the loop between the security team that cares about the findings and the engineering team that needs to review the fixes."

The current dashboard shows operational metrics (alert counts, sessions, PRs, burndown). What's missing: a visual representation of the handoff workflow and healthcare-specific business impact that makes a VP of Engineering lean forward.

## Feature 1: Pipeline Flow Bar

### Purpose

Visually tell the "closing the loop" story. One glance shows the full alert lifecycle and where every alert sits in the remediation process.

### Design

A horizontal bar of 5 connected stages placed below the existing metrics row, full width:

```
[ Detected ] ---> [ Devin Working ] ---> [ PR Created ] ---> [ Engineer Review ] ---> [ Resolved ]
     12                  6                     4                    2                      17
```

### Stages

| Stage | What it means | Count source | Color |
|-------|--------------|--------------|-------|
| Detected | CodeQL found it, not yet assigned | total open - dispatched - resolved | white/neutral |
| Devin Working | Active Devin session | running sessions' alert count | blue (pulsing) |
| PR Created | Fix submitted, awaiting review | finished sessions with open PRs | purple |
| Engineer Review | Needs human judgment | needs_human_review sessions | orange |
| Resolved | PR merged, alert closed | merged/verified sessions | green |

### Visual details

- Each stage is a rounded rectangle connected by arrow (chevron or line)
- Active stages get a colored dot; "Devin Working" pulses to show it's live
- Matches existing dark theme (bg-2, border colors, etc.)
- Counts are large numbers; stage names are small uppercase labels

### Data source

All data already exists in state.json + live GitHub alert data. Computation happens in `dashboard/app.py` by categorizing sessions/alerts into stages.

## Feature 2: Business Impact Card

### Purpose

Translate security work into numbers a healthcare VP of Engineering cares about: regulatory fines, speed, and financial risk.

### Design

A card with 3 metrics displayed in a row (same style as existing top metrics), titled "Business Impact":

### Metric 1: HIPAA Risk Exposure

The fear metric. Shows estimated fine exposure for unpatched known vulnerabilities.

- **Formula**: Count critical/high alerts still open. Critical alerts = Tier 4 willful neglect exposure ($68,928/violation). High alerts = Tier 3 exposure ($13,785/violation). Sum across open alerts.
- **Display**: Large red dollar figure, e.g. `$1.4M`
- **Subtitle**: "potential HIPAA exposure" with small text: "based on penalty tiers for known unpatched vulnerabilities"
- **Behavior**: Number decreases as Devin resolves alerts. This is the motivating metric.

Reference data:
- HIPAA Tier 3 (willful neglect, corrected <30 days): $13,785 - $68,928 per violation
- HIPAA Tier 4 (willful neglect, NOT corrected <30 days): $68,928 - $2,067,813 per violation
- Largest HIPAA settlement: Anthem $16M, Premera $6.85M (both cited unpatched vulns)

### Metric 2: Mean Time to Remediation (MTTR)

The speed metric. Shows Devin's advantage over manual remediation.

- **Formula**: Average time from Devin session creation to PR creation (from session timestamps in state.json)
- **Display**: Side-by-side comparison: `~22 min` (Devin, in green) vs `58 days` (industry avg, in muted text)
- **Subtitle**: "avg time to fix"
- **Source for industry avg**: Veritone/various AppSec reports on mean time to remediate code vulnerabilities

### Metric 3: Breach Risk Reduction

The savings metric. Dollar value of risk eliminated by fixing vulnerabilities.

- **Formula**: For each resolved alert, calculate risk reduction based on vulnerability type and IBM's $408/record healthcare breach cost. Weight by vulnerability type:
  - SQL Injection / Command Injection: 1.5x weight (direct PHI/ePHI database access)
  - Broken Authentication: 1.5x weight
  - Stored XSS: 1.2x weight
  - Other: 1.0x weight
- **Base calculation**: Each resolved alert reduces estimated annual breach probability. Use simplified model: `(alerts_resolved / total_alerts) * estimated_breach_cost_exposure`
- **Display**: Green dollar figure, e.g. `$2.3M risk reduced`
- **Subtitle**: "based on IBM 2024 Healthcare Breach Report ($408/record)"
- **Behavior**: Number grows as alerts get fixed. This is the reward metric.

Reference data:
- Average healthcare breach cost: $9.77M (IBM 2024)
- Cost per record (healthcare): $408
- Healthcare = #1 most expensive industry for breaches, 14th consecutive year

### Layout

Place as a new row below the pipeline flow bar, above the burndown chart. Three metrics side by side in the existing card/metric style.

## Implementation Notes

### Files to modify

- `dashboard/app.py` — Add computation functions for pipeline stage counts and business impact metrics. Pass new data to template context.
- `dashboard/templates/dashboard.html` — Add pipeline flow bar HTML/CSS and business impact card.

### Files unchanged

- All orchestrator modules (no changes needed)
- state.json schema (no new fields needed)

### Assumptions to make configurable

Define constants in app.py (or a new constants section):

```python
# Business impact assumptions (healthcare)
HOURS_PER_MANUAL_FIX = 3.5  # not used in final design but useful reference
HIPAA_TIER3_MIN = 13_785    # per violation
HIPAA_TIER4_MIN = 68_928    # per violation
BREACH_COST_PER_RECORD = 408  # IBM 2024
INDUSTRY_AVG_MTTR_DAYS = 58
ESTIMATED_RECORDS_AT_RISK = 50_000  # MedSecure patient database estimate

# Vulnerability type weights for risk calculation
VULN_WEIGHTS = {
    "sql-injection": 1.5,
    "command-injection": 1.5,
    "broken-auth": 1.5,
    "stored-xss": 1.2,
    "default": 1.0,
}
```

### No new dependencies

Uses only existing Chart.js, Jinja2, and CSS. No new libraries needed.
