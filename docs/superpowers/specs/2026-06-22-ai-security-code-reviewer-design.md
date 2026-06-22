# AI Security Code Reviewer — Design Spec

**Date:** 2026-06-22
**Author:** Leo Chan
**Repo:** https://github.com/GoldenCrate/Visa-Security-Code-Reviewer
**Target role:** Visa Cybersecurity — Product Security Engineering (full-stack + Generative AI)

---

## 1. Purpose

A full-stack web tool where a developer pastes or uploads a code snippet, an LLM
reviews it for security vulnerabilities, and the tool returns structured findings
(vulnerability type, severity, affected lines, suggested fix). Every scan is
persisted, and a metrics dashboard turns that history into a productivity story —
vulnerabilities caught, reviewer-time saved, scan activity, and a risk trend.

This project is built to mirror the deliverables of Visa's Product Security
Engineering role, which emphasises: payment/product security, hands-on generative
AI, full-stack development (backend + APIs + frontend UI), infusing AI into
engineering productivity, and **showcasing productivity improvement with metrics**.

## 2. Job-posting alignment

| Posting requirement | How this project demonstrates it |
|---|---|
| Hands-on generative AI / LLMs | LLM-only vulnerability detection via an engineered security-review prompt |
| Full-stack (backend, DB, APIs, frontend) | FastAPI backend + MySQL + REST API + Streamlit client |
| API creation **and consumption** | FastAPI exposes the API; Streamlit consumes it over HTTP |
| Infusing AI into coding standards/practices | The tool *is* an AI assistant for code quality/security |
| Showcase productivity improvement via metrics | Metrics dashboard: time saved, findings, activity, risk trend |
| Test-Driven Development | pytest, tests written first for scoring + parser + API |
| Continuous Integration | GitHub Actions runs tests on every push |
| Payment/product security domain | Whole tool is a security vulnerability reviewer |

## 3. Architecture

Front/back split so the backend carries the real engineering weight.

- **Backend — FastAPI (Python).** REST API, all business logic, LLM orchestration,
  MySQL persistence. Auto-generated Swagger docs at `/docs`.
- **LLM — Anthropic Claude (`claude-haiku-4-5`).** LLM-only detection; carefully
  engineered security-review prompt returns structured JSON findings.
- **Database — MySQL** via SQLAlchemy ORM. Tests run against in-memory SQLite so CI
  needs no DB server (deliberate testability choice).
- **Frontend — Streamlit**, a thin client that *consumes* the FastAPI API over HTTP.

### Data flow

```
Streamlit  --POST /scans-->  FastAPI validates  -->  Claude returns JSON findings
   ^                                                        |
   |                                              persist scan + findings (MySQL)
   |                                                        |
   +--------------- render result <-------------- return scan + findings

Metrics page --GET /metrics--> FastAPI aggregates --> Streamlit renders charts
```

## 4. Components

Each unit has one purpose, a clear interface, and is independently testable.

- `llm_reviewer.py` — builds the prompt, calls Claude, parses/validates the response
  into a Pydantic `Finding` model. Mockable in tests (no live API calls in CI).
- `scoring.py` — pure functions: `compute_risk_score(findings)` and
  `compute_time_saved(findings, mins_per_finding)`. No I/O → trivially unit-testable.
- `models.py` — SQLAlchemy ORM models: `Scan`, `Finding`.
- `api/` — FastAPI routers: scans, metrics, health.
- `streamlit_app/` — Review page + Metrics dashboard, both calling the API.

## 5. Data model

**Scan**
- `id` (PK)
- `created_at` (timestamp)
- `language` (enum: python, java, javascript, sql, go)
- `source` (enum: paste, upload)
- `lines_of_code` (int)
- `risk_score` (float, 0–100)
- `latency_ms` (int)

**Finding**
- `id` (PK)
- `scan_id` (FK → Scan)
- `vuln_type` (string, e.g. SQL Injection, Hardcoded Secret)
- `severity` (enum: critical, high, medium, low)
- `line_start` (int)
- `line_end` (int)
- `description` (text)
- `suggested_fix` (text)

## 6. API endpoints

- `POST /scans` — submit code (`{language, source, code}`) → returns scan + findings
- `GET /scans/{id}` — retrieve a single scan with findings
- `GET /scans` — list scan history
- `GET /metrics` — aggregated dashboard data (all four metric groups)
- `GET /health` — liveness check

## 7. Languages reviewed

Language-agnostic (LLM-only), exposed via a selector:
**Python, Java, JavaScript, SQL, Go.** (Java included as a nod to the team's stack.)

## 8. Metrics dashboard

All four metric groups, computed from persisted scan history:

1. **Reviewer-time saved** — `total_findings × mins_per_finding` (one stated,
   configurable assumption; the finding counts are real data).
2. **Findings over time** — vulnerabilities caught, broken down by severity and by
   vulnerability type.
3. **Scan activity** — number of scans, total lines of code reviewed, average
   turnaround (latency) per scan.
4. **Severity & risk trend** — risk score per scan and the trend line over time.

Honesty framing (for README and interview): metrics derive from real scan data plus
one clearly-labelled assumption (`mins_per_finding`), which is a single tunable config
value.

## 9. Testing & CI/CD

- **pytest, TDD-first.** Coverage targets:
  - `scoring.py` pure functions (risk score, time saved)
  - LLM-response parser in `llm_reviewer.py` (with a mocked Claude client)
  - API endpoints via FastAPI `TestClient`
- **GitHub Actions** — runs the test suite on every push (modern CI equivalent of the
  posting's Jenkins reference). Tests use in-memory SQLite; no secrets needed in CI.

## 10. Deployment

- Backend → Render or Railway, with a managed MySQL instance.
- Streamlit → Streamlit Community Cloud, configured with the backend URL.
- README with architecture diagram, a Swagger screenshot, and the metrics narrative.

## 11. Scope cuts (deliberate YAGNI)

- **No authentication / multi-user.** Single-user demo. Noted in README as a next step.
- **No GitHub PR integration.** Paste/upload input only.
- **No real-team usage metrics.** Derived from scan history + one stated assumption.

## 12. Out of scope / future work

- Auth + per-user scan history
- GitHub PR/diff integration for in-pipeline review
- Additional languages and rule/static-analysis hybrid detection
- Exportable PDF security reports
