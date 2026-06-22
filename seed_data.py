"""Seed the database with synthetic scans/findings for a richer demo dashboard.

Inserts an illustrative spread of scans so the Productivity Metrics dashboard
shows varied severities, vulnerability types, and a risk trend over time. This
is demo/local data only — real scans come from the live LLM review flow on the
Review page. Re-running wipes and reseeds (idempotent), using a fixed random
seed so the result is reproducible.

Usage:  python seed_data.py
"""

import random
from datetime import datetime, timedelta, timezone

from app import models, scoring
from app.database import SessionLocal, init_db
from app.schemas import FindingBase

random.seed(42)

# (vulnerability type, typical severity) — a realistic spread across OWASP-style issues
VULN_POOL = [
    ("SQL Injection", "critical"),
    ("Command Injection", "critical"),
    ("Hardcoded Secret", "high"),
    ("Insecure Deserialization", "high"),
    ("Server-Side Request Forgery (SSRF)", "high"),
    ("Missing Authentication", "high"),
    ("Cross-Site Scripting (XSS)", "medium"),
    ("Path Traversal", "medium"),
    ("Weak Cryptography", "medium"),
    ("Open Redirect", "low"),
    ("Verbose Error Message", "low"),
]
LANGUAGES = ["python", "java", "javascript", "sql", "go"]
NUM_SCANS = 18


def build_findings():
    """Pick a varied, weighted handful of findings for one scan."""
    n = random.choices([0, 1, 2, 3, 4, 5], weights=[1, 3, 4, 4, 3, 2])[0]
    picks = random.sample(VULN_POOL, k=min(n, len(VULN_POOL)))
    findings = []
    for vuln_type, severity in picks:
        line = random.randint(1, 80)
        findings.append(
            FindingBase(
                vuln_type=vuln_type,
                severity=severity,
                line_start=line,
                line_end=line + random.randint(0, 3),
                description=f"Potential {vuln_type.lower()} detected in the submitted code.",
                suggested_fix=f"Remediate the {vuln_type.lower()} per secure-coding guidelines.",
            )
        )
    return findings


def main():
    init_db()
    db = SessionLocal()
    try:
        # Idempotent reseed: clear existing rows so re-running doesn't pile up.
        db.query(models.Finding).delete()
        db.query(models.Scan).delete()
        db.commit()

        now = datetime.now(timezone.utc)
        for i in range(NUM_SCANS):
            findings = build_findings()
            risk = scoring.compute_risk_score(findings)
            created = now - timedelta(
                days=(NUM_SCANS - i) * 2, hours=random.randint(0, 12)
            )
            scan = models.Scan(
                language=random.choice(LANGUAGES),
                source=random.choice(["paste", "upload"]),
                lines_of_code=random.randint(20, 400),
                risk_score=risk,
                latency_ms=random.randint(900, 4200),
                created_at=created,
            )
            for f in findings:
                scan.findings.append(
                    models.Finding(
                        vuln_type=f.vuln_type,
                        severity=f.severity.value,
                        line_start=f.line_start,
                        line_end=f.line_end,
                        description=f.description,
                        suggested_fix=f.suggested_fix,
                    )
                )
            db.add(scan)
        db.commit()

        total_findings = db.query(models.Finding).count()
        print(f"Seeded {NUM_SCANS} scans with {total_findings} findings.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
