# AI Security Code Reviewer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a full-stack tool that reviews code for security vulnerabilities with an LLM (Anthropic Claude), persists every scan to a database, and surfaces a productivity-metrics dashboard.

**Architecture:** A FastAPI backend owns all logic — REST API, SQLAlchemy/MySQL persistence, and LLM orchestration. A Streamlit app is a thin client that consumes the API over HTTP. Detection is LLM-only: an engineered security prompt returns structured JSON findings that are validated with Pydantic.

**Tech Stack:** Python, FastAPI, SQLAlchemy, MySQL (SQLite for tests/local), Anthropic Claude (`claude-haiku-4-5`), Pydantic, Streamlit, pytest, GitHub Actions.

---

## File Structure

```
Visa-Security-Code-Reviewer/
├── .github/workflows/ci.yml      # CI: run pytest on push
├── .env.example                  # documented env vars
├── requirements.txt
├── pytest.ini
├── README.md
├── app/                          # FastAPI backend
│   ├── __init__.py
│   ├── config.py                 # env-backed settings
│   ├── database.py               # engine, SessionLocal, Base, get_db
│   ├── models.py                 # Scan, Finding ORM models
│   ├── schemas.py                # Pydantic models + enums
│   ├── scoring.py                # pure functions (risk score, time saved)
│   ├── llm_reviewer.py           # prompt + Claude call + parser
│   ├── main.py                   # FastAPI app + router registration
│   └── api/
│       ├── __init__.py
│       ├── health.py             # GET /health
│       ├── scans.py              # POST /scans, GET /scans, GET /scans/{id}
│       └── metrics.py            # GET /metrics
├── streamlit_app/
│   ├── __init__.py
│   ├── api_client.py             # thin HTTP client to the backend
│   ├── app.py                    # Review page (entry point)
│   └── pages/
│       └── 2_metrics.py          # Metrics dashboard page
└── tests/
    ├── __init__.py
    ├── conftest.py               # in-memory SQLite + TestClient fixtures
    ├── test_schemas.py
    ├── test_scoring.py
    ├── test_models.py
    ├── test_llm_reviewer.py
    ├── test_health.py
    ├── test_scans.py
    ├── test_metrics.py
    └── test_api_client.py
```

**Naming contract (used across all tasks):**
- Enums: `Severity` (critical/high/medium/low), `Language` (python/java/javascript/sql/go), `Source` (paste/upload).
- Pydantic: `FindingBase`, `FindingOut`, `ScanRequest`, `ScanOut`, `MetricsResponse`.
- Scoring: `compute_risk_score(findings) -> float`, `compute_time_saved(num_findings, mins_per_finding) -> float`.
- LLM: `build_user_prompt(code, language) -> str`, `parse_findings(raw_text) -> list[FindingBase]`, `review_code(code, language, client=None) -> tuple[list[FindingBase], int]`.
- DB: `Base`, `engine`, `SessionLocal`, `get_db`, `init_db()`; models `Scan`, `Finding`.

---

## Task 1: Project scaffolding

**Files:**
- Create: `requirements.txt`
- Create: `pytest.ini`
- Create: `app/__init__.py`, `app/api/__init__.py`, `tests/__init__.py`, `streamlit_app/__init__.py`
- Create: `app/config.py`
- Create: `.env.example`
- Modify: `.gitignore` (append local DB artifacts)

- [ ] **Step 1: Create `requirements.txt`**

```
fastapi==0.115.0
uvicorn[standard]==0.30.6
sqlalchemy==2.0.35
pydantic==2.9.2
pydantic-settings==2.5.2
anthropic==0.39.0
pymysql==1.1.1
cryptography==43.0.1
requests==2.32.3
streamlit==1.39.0
altair==5.4.1
pandas==2.2.3
pytest==8.3.3
httpx==0.27.2
```

- [ ] **Step 2: Create `pytest.ini`**

```ini
[pytest]
pythonpath = .
testpaths = tests
```

- [ ] **Step 3: Create empty package files**

Create these four files, each containing a single comment line:

`app/__init__.py`, `app/api/__init__.py`, `tests/__init__.py`, `streamlit_app/__init__.py`

```python
# package marker
```

- [ ] **Step 4: Create `app/config.py`**

```python
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    anthropic_api_key: str = ""
    database_url: str = "sqlite:///./app.db"
    mins_per_finding: float = 15.0
    claude_model: str = "claude-haiku-4-5"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
```

- [ ] **Step 5: Create `.env.example`**

```
ANTHROPIC_API_KEY=your-anthropic-key-here
DATABASE_URL=mysql+pymysql://user:password@localhost:3306/security_reviewer
MINS_PER_FINDING=15
CLAUDE_MODEL=claude-haiku-4-5
API_URL=http://localhost:8000
```

- [ ] **Step 6: Append local DB artifacts to `.gitignore`**

Append these lines to the existing `.gitignore`:

```
# Local database artifacts
app.db
*.sqlite3
```

- [ ] **Step 7: Install dependencies**

Run: `pip install -r requirements.txt`
Expected: installs without errors.

- [ ] **Step 8: Verify config imports**

Run: `python -c "from app.config import settings; print(settings.claude_model)"`
Expected: prints `claude-haiku-4-5`

- [ ] **Step 9: Commit**

```bash
git add requirements.txt pytest.ini app/__init__.py app/api/__init__.py tests/__init__.py streamlit_app/__init__.py app/config.py .env.example .gitignore
git commit -m "chore: scaffold project structure and config"
```

---

## Task 2: Pydantic schemas and enums

**Files:**
- Create: `app/schemas.py`
- Test: `tests/test_schemas.py`

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_schemas.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.schemas'`

- [ ] **Step 3: Write the implementation**

```python
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


class MetricsResponse(BaseModel):
    total_scans: int
    total_findings: int
    total_lines_reviewed: int
    avg_latency_ms: float
    time_saved_minutes: float
    findings_by_severity: dict[str, int]
    findings_by_type: dict[str, int]
    risk_trend: list[dict]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_schemas.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add app/schemas.py tests/test_schemas.py
git commit -m "feat: add Pydantic schemas and enums"
```

---

## Task 3: Scoring pure functions

**Files:**
- Create: `app/scoring.py`
- Test: `tests/test_scoring.py`

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_scoring.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.scoring'`

- [ ] **Step 3: Write the implementation**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_scoring.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Commit**

```bash
git add app/scoring.py tests/test_scoring.py
git commit -m "feat: add risk score and time-saved scoring functions"
```

---

## Task 4: Database and ORM models

**Files:**
- Create: `app/database.py`
- Create: `app/models.py`
- Test: `tests/test_models.py`

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.database'`

- [ ] **Step 3: Write `app/database.py`**

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings

connect_args = (
    {"check_same_thread": False}
    if settings.database_url.startswith("sqlite")
    else {}
)
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
```

- [ ] **Step 4: Write `app/models.py`**

```python
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
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_models.py -v`
Expected: PASS (1 passed)

- [ ] **Step 6: Commit**

```bash
git add app/database.py app/models.py tests/test_models.py
git commit -m "feat: add SQLAlchemy database setup and Scan/Finding models"
```

---

## Task 5: LLM reviewer (prompt + parser + Claude call)

**Files:**
- Create: `app/llm_reviewer.py`
- Test: `tests/test_llm_reviewer.py`

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_llm_reviewer.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.llm_reviewer'`

- [ ] **Step 3: Write the implementation**

```python
import json
import time

from anthropic import Anthropic

from app.config import settings
from app.schemas import FindingBase

SYSTEM_PROMPT = (
    "You are a senior application security engineer reviewing code for "
    "vulnerabilities (injection, hardcoded secrets, insecure deserialization, "
    "broken auth, unsafe input handling, and similar OWASP issues). "
    "Respond with ONLY a JSON object of the form "
    '{"findings": [{"vuln_type": str, "severity": one of '
    '["critical","high","medium","low"], "line_start": int, "line_end": int, '
    '"description": str, "suggested_fix": str}]}. '
    "If you find no issues, return {\"findings\": []}. Do not include prose."
)


def build_user_prompt(code: str, language: str) -> str:
    return (
        f"Review the following {language} code for security vulnerabilities:\n\n"
        f"```{language}\n{code}\n```"
    )


def parse_findings(raw_text: str) -> list[FindingBase]:
    text = raw_text.strip()
    if text.startswith("```"):
        parts = text.split("```")
        # parts[1] is the fenced block, possibly prefixed with a language tag
        block = parts[1]
        if block.lstrip().startswith("json"):
            block = block.lstrip()[len("json"):]
        text = block.strip()
    data = json.loads(text)
    return [FindingBase(**item) for item in data.get("findings", [])]


def review_code(code: str, language: str, client=None) -> tuple[list[FindingBase], int]:
    client = client or Anthropic(api_key=settings.anthropic_api_key)
    start = time.perf_counter()
    message = client.messages.create(
        model=settings.claude_model,
        max_tokens=2000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": build_user_prompt(code, language)}],
    )
    latency_ms = int((time.perf_counter() - start) * 1000)
    raw_text = message.content[0].text
    return parse_findings(raw_text), latency_ms
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_llm_reviewer.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Commit**

```bash
git add app/llm_reviewer.py tests/test_llm_reviewer.py
git commit -m "feat: add LLM reviewer with prompt builder, parser, and Claude call"
```

---

## Task 6: FastAPI app + health endpoint + test fixtures

**Files:**
- Create: `app/api/health.py`
- Create: `app/main.py`
- Create: `tests/conftest.py`
- Test: `tests/test_health.py`

- [ ] **Step 1: Write `tests/conftest.py`**

```python
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db_session):
    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
```

- [ ] **Step 2: Write the failing test**

```python
def test_health_returns_ok(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_health.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.main'` (or `app.api.health`)

- [ ] **Step 4: Write `app/api/health.py`**

```python
from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
def health():
    return {"status": "ok"}
```

- [ ] **Step 5: Write `app/main.py`**

```python
from fastapi import FastAPI

from app.database import init_db
from app.api import health

init_db()

app = FastAPI(title="Visa Security Code Reviewer", version="1.0.0")
app.include_router(health.router)
```

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest tests/test_health.py -v`
Expected: PASS (1 passed)

- [ ] **Step 7: Commit**

```bash
git add app/api/health.py app/main.py tests/conftest.py tests/test_health.py
git commit -m "feat: add FastAPI app, health endpoint, and test fixtures"
```

---

## Task 7: Scans endpoints

**Files:**
- Create: `app/api/scans.py`
- Modify: `app/main.py` (register scans router)
- Test: `tests/test_scans.py`

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_scans.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.api.scans'`

- [ ] **Step 3: Write `app/api/scans.py`**

```python
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app import models, schemas, scoring, llm_reviewer
from app.database import get_db

router = APIRouter()


@router.post("/scans", response_model=schemas.ScanOut)
def create_scan(payload: schemas.ScanRequest, db: Session = Depends(get_db)):
    findings, latency_ms = llm_reviewer.review_code(
        payload.code, payload.language.value
    )
    risk = scoring.compute_risk_score(findings)
    scan = models.Scan(
        language=payload.language.value,
        source=payload.source.value,
        lines_of_code=len(payload.code.splitlines()),
        risk_score=risk,
        latency_ms=latency_ms,
    )
    for f in findings:
        scan.findings.append(
            models.Finding(
                vuln_type=f.vuln_type,
                severity=f.severity.value,
                line_start=f.line_start,
                line_end=f.line_end,
                description=f.description,
                suggested_fix=f.suggested_fix,
            )
        )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@router.get("/scans", response_model=list[schemas.ScanOut])
def list_scans(db: Session = Depends(get_db)):
    return db.query(models.Scan).order_by(models.Scan.id.desc()).all()


@router.get("/scans/{scan_id}", response_model=schemas.ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(models.Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
```

- [ ] **Step 4: Register the router in `app/main.py`**

Replace the contents of `app/main.py` with:

```python
from fastapi import FastAPI

from app.database import init_db
from app.api import health, scans

init_db()

app = FastAPI(title="Visa Security Code Reviewer", version="1.0.0")
app.include_router(health.router)
app.include_router(scans.router)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_scans.py -v`
Expected: PASS (4 passed)

- [ ] **Step 6: Commit**

```bash
git add app/api/scans.py app/main.py tests/test_scans.py
git commit -m "feat: add scan create/list/get endpoints"
```

---

## Task 8: Metrics endpoint

**Files:**
- Create: `app/api/metrics.py`
- Modify: `app/main.py` (register metrics router)
- Test: `tests/test_metrics.py`

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_metrics.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.api.metrics'`

- [ ] **Step 3: Write `app/api/metrics.py`**

```python
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app import models, scoring, schemas
from app.config import settings
from app.database import get_db

router = APIRouter()


@router.get("/metrics", response_model=schemas.MetricsResponse)
def get_metrics(db: Session = Depends(get_db)):
    scans = db.query(models.Scan).order_by(models.Scan.id.asc()).all()
    findings = db.query(models.Finding).all()

    total_scans = len(scans)
    total_findings = len(findings)
    total_lines = sum(s.lines_of_code for s in scans)
    avg_latency = (
        sum(s.latency_ms for s in scans) / total_scans if total_scans else 0.0
    )
    time_saved = scoring.compute_time_saved(total_findings, settings.mins_per_finding)

    by_severity: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_type[f.vuln_type] = by_type.get(f.vuln_type, 0) + 1

    risk_trend = [
        {
            "scan_id": s.id,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "risk_score": s.risk_score,
        }
        for s in scans
    ]

    return schemas.MetricsResponse(
        total_scans=total_scans,
        total_findings=total_findings,
        total_lines_reviewed=total_lines,
        avg_latency_ms=avg_latency,
        time_saved_minutes=time_saved,
        findings_by_severity=by_severity,
        findings_by_type=by_type,
        risk_trend=risk_trend,
    )
```

- [ ] **Step 4: Register the router in `app/main.py`**

Replace the contents of `app/main.py` with:

```python
from fastapi import FastAPI

from app.database import init_db
from app.api import health, scans, metrics

init_db()

app = FastAPI(title="Visa Security Code Reviewer", version="1.0.0")
app.include_router(health.router)
app.include_router(scans.router)
app.include_router(metrics.router)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_metrics.py -v`
Expected: PASS (2 passed)

- [ ] **Step 6: Run the full suite**

Run: `pytest -v`
Expected: ALL PASS

- [ ] **Step 7: Commit**

```bash
git add app/api/metrics.py app/main.py tests/test_metrics.py
git commit -m "feat: add metrics aggregation endpoint"
```

---

## Task 9: Streamlit client (API client + Review page + Metrics page)

**Files:**
- Create: `streamlit_app/api_client.py`
- Create: `streamlit_app/app.py`
- Create: `streamlit_app/pages/2_metrics.py`
- Test: `tests/test_api_client.py`

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_api_client.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'streamlit_app.api_client'`

- [ ] **Step 3: Write `streamlit_app/api_client.py`**

```python
import os

import requests

API_URL = os.environ.get("API_URL", "http://localhost:8000")


def submit_scan(code: str, language: str, source: str = "paste") -> dict:
    resp = requests.post(
        f"{API_URL}/scans",
        json={"code": code, "language": language, "source": source},
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()


def list_scans() -> list:
    resp = requests.get(f"{API_URL}/scans", timeout=30)
    resp.raise_for_status()
    return resp.json()


def get_metrics() -> dict:
    resp = requests.get(f"{API_URL}/metrics", timeout=30)
    resp.raise_for_status()
    return resp.json()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_api_client.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Write `streamlit_app/app.py` (Review page)**

```python
import streamlit as st

from streamlit_app.api_client import submit_scan

st.set_page_config(page_title="AI Security Code Reviewer", page_icon="🛡️", layout="wide")

st.title("🛡️ AI Security Code Reviewer")
st.caption("Paste or upload code; an LLM reviews it for security vulnerabilities.")

SEVERITY_COLORS = {
    "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵",
}

language = st.selectbox("Language", ["python", "java", "javascript", "sql", "go"])

tab_paste, tab_upload = st.tabs(["Paste code", "Upload file"])
code = ""
source = "paste"

with tab_paste:
    pasted = st.text_area("Code", height=260, placeholder="Paste code here...")
    if pasted:
        code = pasted
        source = "paste"

with tab_upload:
    uploaded = st.file_uploader("Source file", type=["py", "java", "js", "sql", "go", "txt"])
    if uploaded is not None:
        code = uploaded.read().decode("utf-8", errors="replace")
        source = "upload"
        st.code(code, language=language)

if st.button("Review code", type="primary", disabled=not code):
    with st.spinner("Reviewing with Claude..."):
        try:
            result = submit_scan(code, language, source)
        except Exception as exc:  # surface API/connection errors to the user
            st.error(f"Review failed: {exc}")
        else:
            st.metric("Risk score", f"{result['risk_score']:.0f} / 100")
            findings = result["findings"]
            if not findings:
                st.success("No vulnerabilities found.")
            for f in findings:
                icon = SEVERITY_COLORS.get(f["severity"], "⚪")
                with st.expander(
                    f"{icon} {f['severity'].upper()} — {f['vuln_type']} "
                    f"(lines {f['line_start']}-{f['line_end']})"
                ):
                    st.write(f["description"])
                    st.markdown("**Suggested fix:**")
                    st.write(f["suggested_fix"])
```

- [ ] **Step 6: Write `streamlit_app/pages/2_metrics.py` (Metrics dashboard)**

```python
import altair as alt
import pandas as pd
import streamlit as st

from streamlit_app.api_client import get_metrics

st.set_page_config(page_title="Productivity Metrics", page_icon="📊", layout="wide")

st.title("📊 Productivity Metrics")

try:
    m = get_metrics()
except Exception as exc:
    st.error(f"Could not load metrics: {exc}")
    st.stop()

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total scans", m["total_scans"])
c2.metric("Vulnerabilities caught", m["total_findings"])
c3.metric("Reviewer-time saved (min)", f"{m['time_saved_minutes']:.0f}")
c4.metric("Lines reviewed", m["total_lines_reviewed"])

st.caption(
    "Time saved = vulnerabilities caught × an assumed manual-triage time per "
    "finding (configurable via MINS_PER_FINDING). Finding counts are real data."
)

st.subheader("Findings by severity")
sev = m["findings_by_severity"]
if sev:
    sev_df = pd.DataFrame({"severity": list(sev.keys()), "count": list(sev.values())})
    st.altair_chart(
        alt.Chart(sev_df).mark_bar().encode(x="severity", y="count", color="severity"),
        use_container_width=True,
    )
else:
    st.info("No findings yet — run a scan on the Review page.")

st.subheader("Findings by type")
by_type = m["findings_by_type"]
if by_type:
    type_df = pd.DataFrame({"type": list(by_type.keys()), "count": list(by_type.values())})
    st.altair_chart(
        alt.Chart(type_df).mark_bar().encode(x="count", y=alt.Y("type", sort="-x")),
        use_container_width=True,
    )

st.subheader("Risk trend")
trend = m["risk_trend"]
if trend:
    trend_df = pd.DataFrame(trend)
    st.altair_chart(
        alt.Chart(trend_df).mark_line(point=True).encode(
            x="scan_id:O", y="risk_score:Q"
        ),
        use_container_width=True,
    )
```

- [ ] **Step 7: Manual smoke test (two terminals)**

Terminal A — run the backend:
`uvicorn app.main:app --reload`
Then open `http://localhost:8000/docs` and confirm the Swagger UI lists `/scans`, `/metrics`, `/health`.

Terminal B — run the frontend (requires a real `ANTHROPIC_API_KEY` in `.env`):
`streamlit run streamlit_app/app.py`
Paste a snippet with an obvious issue (e.g. `query = "SELECT * FROM users WHERE id=" + user_id`), click **Review code**, confirm findings render, then open the **Productivity Metrics** page and confirm the KPIs and charts populate.

- [ ] **Step 8: Commit**

```bash
git add streamlit_app/api_client.py streamlit_app/app.py streamlit_app/pages/2_metrics.py tests/test_api_client.py
git commit -m "feat: add Streamlit client with review page and metrics dashboard"
```

---

## Task 10: GitHub Actions CI

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write `.github/workflows/ci.yml`**

```yaml
name: CI

on:
  push:
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run tests
        env:
          DATABASE_URL: "sqlite:///./ci.db"
        run: pytest -v
```

- [ ] **Step 2: Verify the suite passes locally exactly as CI will**

Run: `DATABASE_URL="sqlite:///./ci.db" pytest -v`
Expected: ALL PASS

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: run pytest on push and pull request"
```

---

## Task 11: README and project documentation

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write `README.md`**

```markdown
# Visa Security Code Reviewer

**A full-stack AI tool that reviews code for security vulnerabilities using an LLM, with a FastAPI backend, MySQL storage, and a productivity-metrics dashboard.**

This project models the work of Visa's Cybersecurity — Product Security Engineering team: hands-on generative AI, full-stack development (backend + APIs + frontend), infusing AI into engineering practices, and quantifying the productivity gain with metrics.

## Architecture

A FastAPI backend owns all logic — REST API, SQLAlchemy/MySQL persistence, and LLM orchestration. A Streamlit app is a thin client that consumes the API over HTTP. Detection is LLM-only: an engineered security prompt returns structured JSON findings validated with Pydantic.

```
Streamlit client  ──HTTP──>  FastAPI  ──>  Claude (claude-haiku-4-5)
                                  │
                                  └──> MySQL (scans + findings)
```

## Tech Stack

| Layer | Tool |
|---|---|
| Backend / API | FastAPI (auto Swagger docs at `/docs`) |
| LLM | Anthropic Claude (`claude-haiku-4-5`), LLM-only detection |
| Database | MySQL via SQLAlchemy (SQLite for tests/local) |
| Frontend | Streamlit (thin API client) |
| Testing | pytest (schemas, scoring, parser, API endpoints) |
| CI | GitHub Actions (pytest on every push) |

## API Endpoints

- `POST /scans` — submit code, returns scan + findings
- `GET /scans` / `GET /scans/{id}` — scan history
- `GET /metrics` — aggregated dashboard data
- `GET /health` — liveness

## Metrics

The dashboard reports vulnerabilities caught (by severity and type), scan activity, a risk trend, and **reviewer-time saved**. Time saved = real finding counts × one stated, configurable assumption (`MINS_PER_FINDING`).

## Running locally

1. `pip install -r requirements.txt`
2. Copy `.env.example` to `.env` and set `ANTHROPIC_API_KEY` (and `DATABASE_URL` for MySQL).
3. Backend: `uvicorn app.main:app --reload` (Swagger at http://localhost:8000/docs)
4. Frontend: `streamlit run streamlit_app/app.py`

## Testing

`pytest -v` — runs against in-memory SQLite; no API key or DB server required (the Claude client and DB session are mocked/overridden).

## Known scope cuts / future work

- No authentication / multi-user (single-user demo)
- No GitHub PR integration (paste/upload only)
- Hybrid detection (static analysis + LLM), exportable reports, more languages
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add project README"
```

---

## Self-Review (completed during planning)

**Spec coverage:** Every spec section maps to a task — schemas/enums (T2), scoring incl. time-saved assumption (T3), data model (T4), LLM-only detection (T5), API endpoints incl. health/scans/metrics (T6–T8), Streamlit thin client paste+upload+metrics (T9), pytest/TDD (throughout), GitHub Actions CI (T10), README with honesty framing + scope cuts (T11). MySQL via SQLAlchemy with SQLite test override (T1/T4/conftest).

**Placeholder scan:** No TBD/TODO; every code step contains complete code and exact commands.

**Type consistency:** `FindingBase`/`FindingOut`/`ScanOut`/`MetricsResponse`, `compute_risk_score`/`compute_time_saved(num_findings, mins_per_finding)`, `review_code(...) -> (findings, latency_ms)`, and `init_db()`/`get_db` names are used identically across tasks. Severity weights (critical 40 / high 20 / medium 10 / low 5) make the test expectations (one high = 20; high+low = 25; 2 findings × 15 min = 30) internally consistent.
