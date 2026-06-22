from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class Language(str, Enum):
    python = "python"
    java = "java"
    javascript = "javascript"
    sql = "sql"
    go = "go"


class Source(str, Enum):
    paste = "paste"
    upload = "upload"


class FindingBase(BaseModel):
    vuln_type: str
    severity: Severity
    line_start: int
    line_end: int
    description: str
    suggested_fix: str


class FindingOut(FindingBase):
    id: int
    model_config = {"from_attributes": True}


class ScanRequest(BaseModel):
    language: Language
    source: Source = Source.paste
    code: str = Field(min_length=1)


class ScanOut(BaseModel):
    id: int
    created_at: datetime
    language: Language
    source: Source
    lines_of_code: int
    risk_score: float
    latency_ms: int
    findings: list[FindingOut]
    model_config = {"from_attributes": True}


class RiskTrendItem(BaseModel):
    scan_id: int
    created_at: str | None
    risk_score: float


class MetricsResponse(BaseModel):
    total_scans: int
    total_findings: int
    total_lines_reviewed: int
    avg_latency_ms: float
    time_saved_minutes: float
    findings_by_severity: dict[str, int]
    findings_by_type: dict[str, int]
    risk_trend: list[RiskTrendItem]
