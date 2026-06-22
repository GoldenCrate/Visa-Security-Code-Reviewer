import pytest
from pydantic import ValidationError
from app.schemas import (
    Severity, Language, Source,
    FindingBase, ScanRequest,
)


def test_finding_base_accepts_valid_severity():
    f = FindingBase(
        vuln_type="SQL Injection",
        severity="high",
        line_start=1,
        line_end=2,
        description="User input concatenated into query.",
        suggested_fix="Use parameterized queries.",
    )
    assert f.severity == Severity.high
    assert f.vuln_type == "SQL Injection"


def test_finding_base_rejects_bad_severity():
    with pytest.raises(ValidationError):
        FindingBase(
            vuln_type="x",
            severity="catastrophic",
            line_start=1,
            line_end=1,
            description="d",
            suggested_fix="f",
        )


def test_scan_request_requires_nonempty_code():
    with pytest.raises(ValidationError):
        ScanRequest(language="python", source="paste", code="")


def test_scan_request_defaults_source_to_paste():
    req = ScanRequest(language=Language.python, code="print(1)")
    assert req.source == Source.paste
