from app.schemas import FindingBase, Severity
from app.scoring import compute_risk_score, compute_time_saved


def _finding(severity):
    return FindingBase(
        vuln_type="x",
        severity=severity,
        line_start=1,
        line_end=1,
        description="d",
        suggested_fix="f",
    )


def test_risk_score_zero_when_no_findings():
    assert compute_risk_score([]) == 0.0


def test_risk_score_sums_weights():
    findings = [_finding(Severity.medium), _finding(Severity.low)]
    # medium=10 + low=5 = 15
    assert compute_risk_score(findings) == 15.0


def test_risk_score_capped_at_100():
    findings = [_finding(Severity.critical) for _ in range(5)]  # 5 * 40 = 200
    assert compute_risk_score(findings) == 100.0


def test_time_saved_multiplies_count_by_rate():
    assert compute_time_saved(4, 15.0) == 60.0


def test_time_saved_zero_when_no_findings():
    assert compute_time_saved(0, 15.0) == 0.0
