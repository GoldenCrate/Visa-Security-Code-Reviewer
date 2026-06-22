from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models, schemas, scoring, llm_reviewer
from app.database import get_db

router = APIRouter()


@router.post("/scans", response_model=schemas.ScanOut)
def create_scan(payload: schemas.ScanRequest, db: Session = Depends(get_db)):
    findings, latency_ms = llm_reviewer.review_code(
        payload.code, payload.language.value
    )
    risk = scoring.compute_risk_score(findings)
    scan = models.Scan(
        language=payload.language.value,
        source=payload.source.value,
        lines_of_code=len(payload.code.splitlines()),
        risk_score=risk,
        latency_ms=latency_ms,
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
    db.refresh(scan)
    return scan


@router.get("/scans", response_model=list[schemas.ScanOut])
def list_scans(db: Session = Depends(get_db)):
    return db.query(models.Scan).order_by(models.Scan.id.desc()).all()


@router.get("/scans/{scan_id}", response_model=schemas.ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(models.Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
