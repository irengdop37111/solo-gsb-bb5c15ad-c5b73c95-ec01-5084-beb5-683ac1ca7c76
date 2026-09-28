"""Integration tests for the FastAPI layer."""

from __future__ import annotations

import hashlib
import json

from fastapi.testclient import TestClient

from app import config
from app.main import app

client = TestClient(app)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_redact_endpoint_full_flow():
    payload = {
        "data": {
            "users": [
                {"name": "alice", "email": "a@x.io", "password": "p1"},
                {"name": "bob", "email": "b@x.io", "password": "p2"},
            ],
            "meta": {"keep": True},
        },
        "rules": [
            {"pointer": "/users/*/password", "action": "remove"},
            {"pointer": "/users/*/email", "action": "mask", "name": "emails"},
            {"pointer": "/**/name", "action": "sha256"},
        ],
    }
    resp = client.post("/redact", json=payload)
    assert resp.status_code == 200, resp.text
    body = resp.json()

    redacted = body["redacted"]
    assert redacted["meta"] == {"keep": True}
    for user in redacted["users"]:
        assert "password" not in user
        assert user["email"] == "***REDACTED***"
        assert len(user["name"]) == 64

    audit = body["audit"]
    pointers = {e["pointer"] for e in audit}
    assert pointers == {
        "/users/0/name",
        "/users/1/name",
        "/users/0/email",
        "/users/1/email",
        "/users/0/password",
        "/users/1/password",
    }
    # Every entry carries the originating rule.
    for entry in audit:
        assert {"pointer", "action", "rule"} <= set(entry)
        assert {"index", "pointer", "action"} <= set(entry["rule"])
    email_entries = [e for e in audit if e["pointer"].endswith("/email")]
    assert all(e["rule"]["name"] == "emails" for e in email_entries)


def test_invalid_pointer_returns_422():
    resp = client.post(
        "/redact",
        json={"data": {"a": 1}, "rules": [{"pointer": "a", "action": "mask"}]},
    )
    assert resp.status_code == 422
    assert "pointer" in json.dumps(resp.json())


def test_invalid_action_returns_422():
    resp = client.post(
        "/redact",
        json={"data": {"a": 1}, "rules": [{"pointer": "/a", "action": "explode"}]},
    )
    assert resp.status_code == 422


def test_missing_data_returns_422():
    resp = client.post("/redact", json={"rules": []})
    assert resp.status_code == 422


def test_extra_field_returns_422():
    resp = client.post(
        "/redact",
        json={"data": {}, "rules": [], "bogus": 1},
    )
    assert resp.status_code == 422


def test_salt_env_changes_hash(monkeypatch):
    data = {"data": {"k": "v"}, "rules": [{"pointer": "/k", "action": "sha256"}]}

    monkeypatch.setattr(config, "get_salt", lambda: "")
    unsalted = client.post("/redact", json=data).json()["redacted"]["k"]

    monkeypatch.setattr(config, "get_salt", lambda: "s3cret")
    salted = client.post("/redact", json=data).json()["redacted"]["k"]

    expected = hashlib.sha256(
        json.dumps("v", separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    assert unsalted == expected
    assert salted != unsalted


def test_globstar_array_deletion_no_offset():
    # Delete one array element and mask inside others in one request;
    # later pointers must resolve against the ORIGINAL list.
    payload = {
        "data": {"items": [{"v": "a"}, {"v": "b"}, {"v": "c"}]},
        "rules": [
            {"pointer": "/items/0", "action": "remove"},
            {"pointer": "/items/*/v", "action": "mask"},
        ],
    }
    body = client.post("/redact", json=payload).json()
    assert body["redacted"]["items"] == [{"v": "***REDACTED***"}, {"v": "***REDACTED***"}]
    assert {e["pointer"] for e in body["audit"]} == {
        "/items/0",
        "/items/1/v",
        "/items/2/v",
    }


def test_openapi_available():
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    assert "/redact" in resp.json()["paths"]
