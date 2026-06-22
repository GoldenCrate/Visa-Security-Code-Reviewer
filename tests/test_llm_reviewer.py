from app.llm_reviewer import build_user_prompt, parse_findings, review_code
from app.schemas import Severity


def test_build_user_prompt_includes_code_and_language():
    prompt = build_user_prompt("print(1)", "python")
    assert "print(1)" in prompt
    assert "python" in prompt


def test_parse_findings_plain_json():
    raw = (
        '{"findings": [{"vuln_type": "Hardcoded Secret", "severity": "high", '
        '"line_start": 3, "line_end": 3, "description": "API key in source.", '
        '"suggested_fix": "Load from env."}]}'
    )
    findings = parse_findings(raw)
    assert len(findings) == 1
    assert findings[0].severity == Severity.high
    assert findings[0].vuln_type == "Hardcoded Secret"


def test_parse_findings_strips_markdown_fence():
    raw = (
        "```json\n"
        '{"findings": [{"vuln_type": "SQL Injection", "severity": "critical", '
        '"line_start": 1, "line_end": 1, "description": "d", "suggested_fix": "f"}]}\n'
        "```"
    )
    findings = parse_findings(raw)
    assert len(findings) == 1
    assert findings[0].severity == Severity.critical


def test_parse_findings_empty_list():
    findings = parse_findings('{"findings": []}')
    assert findings == []


class _FakeContentBlock:
    def __init__(self, text):
        self.text = text


class _FakeMessage:
    def __init__(self, text):
        self.content = [_FakeContentBlock(text)]


class _FakeMessages:
    def __init__(self, text):
        self._text = text

    def create(self, **kwargs):
        return _FakeMessage(self._text)


class _FakeClient:
    def __init__(self, text):
        self.messages = _FakeMessages(text)


def test_review_code_returns_findings_and_latency():
    fake = _FakeClient(
        '{"findings": [{"vuln_type": "SQL Injection", "severity": "high", '
        '"line_start": 2, "line_end": 2, "description": "d", "suggested_fix": "f"}]}'
    )
    findings, latency_ms = review_code("SELECT 1", "sql", client=fake)
    assert len(findings) == 1
    assert findings[0].vuln_type == "SQL Injection"
    assert isinstance(latency_ms, int)
    assert latency_ms >= 0
