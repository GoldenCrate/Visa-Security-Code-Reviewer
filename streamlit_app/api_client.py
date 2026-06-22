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
