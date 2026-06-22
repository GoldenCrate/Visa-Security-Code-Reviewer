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
