"""HTTP API with the agent monkeypatched: no LLM, no network."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import agent as agent_module
from app.api import create_app
from app.config import Settings


def make_client(**overrides) -> TestClient:
    settings = Settings(_env_file=None, **{"llm_api_key": "test", "rate_limit_per_hour": 0, **overrides})
    return TestClient(create_app(settings))


@pytest.fixture()
def client() -> TestClient:
    return make_client()


def test_health_and_read_endpoints(client):
    health = client.get("/health").json()
    assert health["status"] == "ok" and health["scenarios"] == 5 and health["llm_configured"]
    assert len(client.get("/tactics").json()) == 15
    assert [s["id"] for s in client.get("/scenarios").json()][0] == "SCN-001"
    one = client.get("/scenarios/scn-002").json()
    assert one["validation"]["valid"] and one["yaml"].startswith("id: SCN-002")
    assert client.get("/scenarios/SCN-999").status_code == 404
    assert client.get("/coverage").json()["totals"]["tactics"] == 15


def test_index_served(client):
    res = client.get("/")
    assert res.status_code == 200 and "Cyber Range Scenario Assistant" in res.text


def test_tools_endpoint(client):
    res = client.post("/tools", json={"tool": "gap_analysis", "args": {"required_techniques": ["T1595"]}})
    assert res.status_code == 200
    body = res.json()
    assert body["result"]["threat_profile"]["missing"][0]["id"] == "T1595"
    assert body["ui"]["gaps"] and body["ui"]["matrix"]
    built = client.post(
        "/tools", json={"tool": "build_scenario", "args": {"title": "API", "techniques": ["T1486"]}}
    )
    assert built.json()["ui"]["yaml"].startswith("id: SCN-006")


def test_tools_endpoint_errors(client):
    assert client.post("/tools", json={"tool": "nope"}).status_code == 400
    bad = client.post("/tools", json={"tool": "build_scenario", "args": {"title": "x"}})
    assert bad.status_code == 400 and "invalid arguments" in bad.json()["error"]
    assert client.post("/tools", json={}).status_code == 422


def test_ask_with_monkeypatched_agent(client, monkeypatch):
    seen = {}

    def fake_agent(question, ctx, settings):
        seen["question"] = question
        return {"answer": "done", "trace": [], "ui": {"matrix": None}}

    monkeypatch.setattr(agent_module, "run_agent", fake_agent)
    res = client.post("/ask", json={"question": "Plan a phishing exercise"})
    assert res.status_code == 200 and res.json()["answer"] == "done"
    assert seen["question"] == "Plan a phishing exercise"
    assert client.post("/ask", json={"question": ""}).status_code == 422


def test_ask_502_when_llm_fails(client, monkeypatch):
    def broken(*args, **kwargs):
        raise agent_module.LLMError("down")

    monkeypatch.setattr(agent_module, "run_agent", broken)
    res = client.post("/ask", json={"question": "hi"})
    assert res.status_code == 502 and "unreachable" in res.json()["error"]


def test_ask_503_without_api_key(monkeypatch):
    client = make_client(llm_api_key="")
    res = client.post("/ask", json={"question": "hi"})
    assert res.status_code == 503


def test_ask_rate_limit_per_ip(monkeypatch):
    monkeypatch.setattr(agent_module, "run_agent", lambda q, c, s: {"answer": "ok", "trace": [], "ui": {}})
    client = make_client(rate_limit_per_hour=2)
    codes = [client.post("/ask", json={"question": "hi"}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    res = client.post("/ask", json={"question": "hi"})
    assert int(res.headers["retry-after"]) > 0


def test_rate_limit_uses_forwarded_for_only_when_trusted(monkeypatch):
    monkeypatch.setattr(agent_module, "run_agent", lambda q, c, s: {"answer": "ok", "trace": [], "ui": {}})
    trusted = make_client(rate_limit_per_hour=1, trust_forwarded_for=True)
    assert (
        trusted.post("/ask", json={"question": "a"}, headers={"X-Forwarded-For": "1.1.1.1"}).status_code
        == 200
    )
    assert (
        trusted.post("/ask", json={"question": "a"}, headers={"X-Forwarded-For": "2.2.2.2"}).status_code
        == 200
    )
    assert (
        trusted.post("/ask", json={"question": "a"}, headers={"X-Forwarded-For": "1.1.1.1"}).status_code
        == 429
    )
    untrusted = make_client(rate_limit_per_hour=1)
    assert (
        untrusted.post("/ask", json={"question": "a"}, headers={"X-Forwarded-For": "1.1.1.1"}).status_code
        == 200
    )
    assert (
        untrusted.post("/ask", json={"question": "a"}, headers={"X-Forwarded-For": "2.2.2.2"}).status_code
        == 429
    )
