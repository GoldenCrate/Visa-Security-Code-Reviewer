from app.schemas import FindingBase, Severity

SEVERITY_WEIGHTS = {
    Severity.critical: 40.0,
    Severity.high: 20.0,
    Severity.medium: 10.0,
    Severity.low: 5.0,
}


def compute_risk_score(findings: list[FindingBase]) -> float:
    if not findings:
        return 0.0
    total = sum(SEVERITY_WEIGHTS[f.severity] for f in findings)
    return min(100.0, total)


def compute_time_saved(num_findings: int, mins_per_finding: float) -> float:
    return float(num_findings) * float(mins_per_finding)
