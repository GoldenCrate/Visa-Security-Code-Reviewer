"""Synthetic demo-data seeding.

Shared by the ``seed_data.py`` CLI and by optional startup seeding (enable with
``SEED_DEMO=true``, e.g. on a public demo deploy where the dashboard should
look populated). Demo data only — real scans come from the live LLM review flow.
The seed is reproducible (fixed random seed) and idempotent (wipes then reseeds).
"""

import random
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app import models, scoring
from app.schemas import FindingBase

# (vulnerability type, typical severity) — a realistic OWASP-style spread
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


def seed(db: Session, num_scans: int = NUM_SCANS) -> int:
    """Wipe and reseed the database with synthetic scans. Returns finding count."""
    db.query(models.Finding).delete()
    db.query(models.Scan).delete()
    db.commit()

    random.seed(42)
    now = datetime.now(timezone.utc)
    for i in range(num_scans):
        findings = build_findings()
        risk = scoring.compute_risk_score(findings)
        created = now - timedelta(days=(num_scans - i) * 2, hours=random.randint(0, 12))
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
    return db.query(models.Finding).count()


def maybe_seed_if_empty(db: Session) -> bool:
    """Seed only when there are no scans yet. Returns True if it seeded."""
    if db.query(models.Scan).count() == 0:
        seed(db)
        return True
    return False
