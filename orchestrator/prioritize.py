"""
SecureFlow Orchestrator - Prioritization Engine

Groups and prioritizes CodeQL alerts for efficient remediation.
Batches related alerts together so Devin can fix them in a single session.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from ingest import CodeQLAlert

logger = logging.getLogger(__name__)

# Severity ordering for prioritization
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class AlertBatch:
    """A group of related alerts to be fixed in a single Devin session."""
    batch_id: str
    alerts: list[CodeQLAlert]
    priority: int  # lower = higher priority
    category: str  # e.g., "sql-injection", "xss", "command-injection"
    file_path: str  # primary file affected
    description: str

    @property
    def severity(self) -> str:
        """Return the highest severity in the batch."""
        severities = [a.security_severity for a in self.alerts]
        return min(severities, key=lambda s: SEVERITY_ORDER.get(s, 99))

    @property
    def alert_count(self) -> int:
        return len(self.alerts)

    def to_dict(self) -> dict:
        return {
            "batch_id": self.batch_id,
            "alert_count": self.alert_count,
            "priority": self.priority,
            "category": self.category,
            "severity": self.severity,
            "file_path": self.file_path,
            "description": self.description,
            "alert_numbers": [a.number for a in self.alerts],
        }


def group_alerts(alerts: list[CodeQLAlert], demo_mode: bool = False) -> list[AlertBatch]:
    """
    Group alerts by rule type and file path.

    Strategy: alerts with the same rule_id in the same file get batched together.
    This lets Devin fix all SQL injections in patients.js in one session,
    rather than opening 5 separate sessions.

    When demo_mode is True, a curated set of high-variety vulnerability types
    is boosted to the top of the priority list so the first dispatch showcases
    different fix strategies (command injection, SSRF, path traversal, etc.).
    """
    groups: dict[str, list[CodeQLAlert]] = {}

    for alert in alerts:
        # Group key: rule_id + file_path
        key = f"{alert.rule_id}::{alert.file_path}"
        if key not in groups:
            groups[key] = []
        groups[key].append(alert)

    batches = []
    for idx, (key, group_alerts_list) in enumerate(groups.items()):
        rule_id, file_path = key.split("::", 1)

        # Determine category from rule_id
        category = categorize_rule(rule_id)

        # Priority based on highest severity in the group
        highest_severity = min(
            SEVERITY_ORDER.get(a.security_severity, 99) for a in group_alerts_list
        )

        batch = AlertBatch(
            batch_id=f"batch-{idx + 1:03d}",
            alerts=group_alerts_list,
            priority=highest_severity,
            category=category,
            file_path=file_path,
            description=build_batch_description(group_alerts_list),
        )
        batches.append(batch)

    if demo_mode:
        batches = _apply_demo_priority(batches)
    else:
        # Sort by priority (critical first)
        batches.sort(key=lambda b: b.priority)

    logger.info(
        f"Grouped {len(alerts)} alerts into {len(batches)} batches. "
        f"Priority breakdown: "
        + ", ".join(f"{b.batch_id} ({b.severity})" for b in batches[:5])
    )
    return batches


# --- Demo mode priority boost ---
# These rule+file combos produce a variety of fix strategies that showcase
# Devin's capabilities. Only active when DEMO_MODE=true in .env.
# Remove DEMO_MODE from .env to revert to normal critical-first ordering.
_DEMO_BOOST = [
    ("js/command-line-injection", "src/routes/reports.js"),
    ("js/request-forgery", "src/routes/reports.js"),
    ("js/remote-property-injection", "src/routes/admin.js"),
    ("js/path-injection", "src/routes/reports.js"),
    ("js/sql-injection", "src/routes/patients.js"),
]


def _apply_demo_priority(batches: list[AlertBatch]) -> list[AlertBatch]:
    """Reorder batches so the curated demo set comes first."""
    boosted = []
    rest = []
    for batch in batches:
        rule_id = batch.alerts[0].rule_id if batch.alerts else ""
        key = (rule_id, batch.file_path)
        if key in _DEMO_BOOST:
            # Assign demo priority based on position in the boost list
            batch.priority = -len(_DEMO_BOOST) + _DEMO_BOOST.index(key)
            boosted.append(batch)
        else:
            rest.append(batch)

    # Sort boosted by their assigned order, rest by normal severity
    boosted.sort(key=lambda b: b.priority)
    rest.sort(key=lambda b: b.priority)
    logger.info(
        f"Demo mode: boosted {len(boosted)} batches to front of queue."
    )
    return boosted + rest


def categorize_rule(rule_id: str) -> str:
    """Map CodeQL rule IDs to human-readable categories."""
    categories = {
        "sql-injection": "SQL Injection",
        "xss": "Cross-Site Scripting (XSS)",
        "command-line-injection": "Command Injection",
        "command-injection": "Command Injection",
        "path-injection": "Path Traversal",
        "hardcoded-credentials": "Hardcoded Credentials",
        "insecure-randomness": "Insecure Randomness",
        "weak-cryptographic-algorithm": "Weak Cryptography",
        "reflected-xss": "Reflected XSS",
        "stored-xss": "Stored XSS",
        "open-redirect": "Open Redirect",
        "ssrf": "Server-Side Request Forgery",
        "regex-injection": "ReDoS",
        "unsafe-deserialization": "Unsafe Deserialization",
        "information-exposure": "Information Exposure",
        "insufficient-key-size": "Insufficient Key Size",
        "clear-text-logging": "Cleartext Logging",
    }

    rule_lower = rule_id.lower()
    for key, label in categories.items():
        if key in rule_lower:
            return label

    return rule_id


def build_batch_description(alerts: list[CodeQLAlert]) -> str:
    """Build a human-readable description for a batch of alerts."""
    if len(alerts) == 1:
        a = alerts[0]
        return (
            f"{a.rule_name} in {a.file_path}:{a.start_line} — "
            f"{a.message[:100] if a.message else a.rule_description[:100]}"
        )

    rule_name = alerts[0].rule_name
    file_path = alerts[0].file_path
    lines = sorted(set(a.start_line for a in alerts))
    line_str = ", ".join(str(l) for l in lines[:5])
    if len(lines) > 5:
        line_str += f" (+{len(lines) - 5} more)"

    return f"{len(alerts)} {rule_name} issues in {file_path} at lines {line_str}"
