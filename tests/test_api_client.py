import streamlit_app.api_client as api_client


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def test_submit_scan_posts_to_scans(monkeypatch):
    captured = {}

    def fake_post(url, json, timeout):
        captured["url"] = url
        captured["json"] = json
        return _FakeResponse({"id": 1, "findings": []})

    monkeypatch.setattr(api_client.requests, "post", fake_post)
    result = api_client.submit_scan("print(1)", "python", "paste")
    assert captured["url"].endswith("/scans")
    assert captured["json"] == {"code": "print(1)", "language": "python", "source": "paste"}
    assert result == {"id": 1, "findings": []}


def test_get_metrics_gets_metrics(monkeypatch):
    def fake_get(url, timeout):
        return _FakeResponse({"total_scans": 0})

    monkeypatch.setattr(api_client.requests, "get", fake_get)
    assert api_client.get_metrics() == {"total_scans": 0}
