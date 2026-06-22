from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app import models, scoring, schemas
from app.config import settings
from app.database import get_db

router = APIRouter()


@router.get("/metrics", response_model=schemas.MetricsResponse)
def get_metrics(db: Session = Depends(get_db)):
    scans = db.query(models.Scan).order_by(models.Scan.id.asc()).all()
    findings = db.query(models.Finding).all()

    total_scans = len(scans)
    total_findings = len(findings)
    total_lines = sum(s.lines_of_code for s in scans)
    avg_latency = (
        sum(s.latency_ms for s in scans) / total_scans if total_scans else 0.0
    )
    time_saved = scoring.compute_time_saved(total_findings, settings.mins_per_finding)

    by_severity: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_type[f.vuln_type] = by_type.get(f.vuln_type, 0) + 1

    risk_trend = [
        {
            "scan_id": s.id,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "risk_score": s.risk_score,
        }
        for s in scans
    ]

    return schemas.MetricsResponse(
        total_scans=total_scans,
        total_findings=total_findings,
        total_lines_reviewed=total_lines,
        avg_latency_ms=avg_latency,
        time_saved_minutes=time_saved,
        findings_by_severity=by_severity,
        findings_by_type=by_type,
        risk_trend=risk_trend,
    )
