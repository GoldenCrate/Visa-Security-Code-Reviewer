import app.llm_reviewer as llm_reviewer
from app.schemas import FindingBase


def _fake_review(code, language, client=None):
    findings = [
        FindingBase(
            vuln_type="SQL Injection", severity="high",
            line_start=1, line_end=1,
            description="User input concatenated into query.",
            suggested_fix="Use parameterized queries.",
        )
    ]
    return findings, 42


def test_create_scan_persists_and_returns_findings(client, monkeypatch):
    monkeypatch.setattr(llm_reviewer, "review_code", _fake_review)
    resp = client.post(
        "/scans",
        json={"language": "python", "source": "paste",
              "code": "q = 'SELECT * FROM t WHERE id=' + x"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] >= 1
    assert body["risk_score"] == 20.0          # one 'high' finding = 20
    assert body["latency_ms"] == 42
    assert body["lines_of_code"] == 1
    assert len(body["findings"]) == 1
    assert body["findings"][0]["vuln_type"] == "SQL Injection"


def test_get_scan_by_id(client, monkeypatch):
    monkeypatch.setattr(llm_reviewer, "review_code", _fake_review)
    created = client.post(
        "/scans",
        json={"language": "python", "code": "print(1)"},
    ).json()
    resp = client.get(f"/scans/{created['id']}")
    assert resp.status_code == 200
    assert resp.json()["id"] == created["id"]


def test_get_missing_scan_returns_404(client):
    resp = client.get("/scans/9999")
    assert resp.status_code == 404


def test_list_scans_returns_most_recent_first(client, monkeypatch):
    monkeypatch.setattr(llm_reviewer, "review_code", _fake_review)
    client.post("/scans", json={"language": "python", "code": "a=1"})
    client.post("/scans", json={"language": "go", "code": "b:=2"})
    resp = client.get("/scans")
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 2
    assert rows[0]["id"] > rows[1]["id"]
