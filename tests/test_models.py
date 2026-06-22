from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models import Scan, Finding


def _session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


def test_scan_persists_with_findings():
    session = _session()
    scan = Scan(language="python", source="paste", lines_of_code=3,
                risk_score=20.0, latency_ms=120)
    scan.findings.append(Finding(
        vuln_type="SQL Injection", severity="high",
        line_start=1, line_end=1, description="d", suggested_fix="f",
    ))
    session.add(scan)
    session.commit()

    loaded = session.query(Scan).first()
    assert loaded.id is not None
    assert loaded.risk_score == 20.0
    assert len(loaded.findings) == 1
    assert loaded.findings[0].vuln_type == "SQL Injection"
    session.close()
