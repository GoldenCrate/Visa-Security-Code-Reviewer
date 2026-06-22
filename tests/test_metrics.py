import app.llm_reviewer as llm_reviewer
from app.schemas import FindingBase


def _fake_review(code, language, client=None):
    findings = [
        FindingBase(vuln_type="SQL Injection", severity="high",
                    line_start=1, line_end=1, description="d", suggested_fix="f"),
        FindingBase(vuln_type="Hardcoded Secret", severity="low",
                    line_start=2, line_end=2, description="d", suggested_fix="f"),
    ]
    return findings, 100


def test_metrics_empty_state(client):
    resp = client.get("/metrics")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_scans"] == 0
    assert body["total_findings"] == 0
    assert body["time_saved_minutes"] == 0.0
    assert body["findings_by_severity"] == {}


def test_metrics_aggregates_scans(client, monkeypatch):
    monkeypatch.setattr(llm_reviewer, "review_code", _fake_review)
    client.post("/scans", json={"language": "python", "code": "a=1\nb=2"})
    resp = client.get("/metrics")
    body = resp.json()
    assert body["total_scans"] == 1
    assert body["total_findings"] == 2
    assert body["total_lines_reviewed"] == 2
    assert body["avg_latency_ms"] == 100.0
    assert body["time_saved_minutes"] == 30.0          # 2 findings * 15 mins
    assert body["findings_by_severity"] == {"high": 1, "low": 1}
    assert body["findings_by_type"] == {"SQL Injection": 1, "Hardcoded Secret": 1}
    assert len(body["risk_trend"]) == 1
    assert body["risk_trend"][0]["risk_score"] == 25.0  # high(20) + low(5)
