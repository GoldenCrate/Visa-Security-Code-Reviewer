from sqlalchemy import (
    Column, Integer, String, Float, DateTime, ForeignKey, Text, func,
)
from sqlalchemy.orm import relationship

from app.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    language = Column(String(32), nullable=False)
    source = Column(String(16), nullable=False)
    lines_of_code = Column(Integer, nullable=False, default=0)
    risk_score = Column(Float, nullable=False, default=0.0)
    latency_ms = Column(Integer, nullable=False, default=0)

    findings = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    vuln_type = Column(String(128), nullable=False)
    severity = Column(String(16), nullable=False)
    line_start = Column(Integer, nullable=False, default=0)
    line_end = Column(Integer, nullable=False, default=0)
    description = Column(Text, nullable=False)
    suggested_fix = Column(Text, nullable=False)

    scan = relationship("Scan", back_populates="findings")
