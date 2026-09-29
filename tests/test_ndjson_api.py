"""Integration tests for POST /redact/ndjson."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from app.main import app
from app import ndjson

client = TestClient(app)

POLICY = {
    "rules": [
        {"pointer": "/email", "action": "mask"},
        {"pointer": "/password", "action": "remove"},
    ]
}


def _create_policy(name="pii"):
    resp = client.put(f"/policies/{name}", json=POLICY)
    assert resp.status_code == 201, resp.text
    return resp


def _parse_ndjson(raw: bytes):
    return [json.loads(line) for line in raw.split(b"\n") if line]


def test_redacts_lines_with_policy_version_headers():
    created = _create_policy()
    body = b'{"email":"a@x.io","password":"p","name":"a"}\n{"email":"b@x.io"}\n'
    resp = client.post(
        "/redact/ndjson?name=pii",
        content=body,
        headers={"Content-Type": "application/x-ndjson"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("application/x-ndjson")
    assert resp.headers["policy-name"] == "pii"
    assert resp.headers["policy-version"] == "1"
    assert resp.headers["etag"] == created.headers["etag"]

    rows = _parse_ndjson(resp.content)
    assert [r["line"] for r in rows] == [1, 2]
    assert rows[0]["redacted"] == {"email": "***REDACTED***", "name": "a"}
    assert rows[1]["redacted"] == {"email": "***REDACTED***"}
    for row in rows:
        for entry in row["audit"]:
            assert entry["policy"] == {"name": "pii", "version": 1}


def test_blank_lines_skipped_but_count_as_physical_lines():
    _create_policy()
    # Lines: 1 blank, 2 JSON, 3 blank (CRLF), 4 JSON, 5 blank
    body = b'\n{"email":"a"}\r\n\r\n{"email":"b"}\n\n'
    resp = client.post(
        "/redact/ndjson?name=pii",
        content=body,
        headers={"Content-Type": "application/x-ndjson"},
    )
    assert resp.status_code == 200
    rows = _parse_ndjson(resp.content)
    assert [r["line"] for r in rows] == [2, 4]


def test_final_line_without_newline_is_processed():
    _create_policy()
    resp = client.post(
        "/redact/ndjson?name=pii",
        content=b'{"email":"a"}',
        headers={"Content-Type": "application/x-ndjson"},
    )
    rows = _parse_ndjson(resp.content)
    assert [r["line"] for r in rows] == [1]


def test_whitespace_only_line_is_invalid_json_not_skipped():
    _create_policy()
    resp = client.post(
        "/redact/ndjson?name=pii",
        content=b"   \n\t\r\n{}\n",
        headers={"Content-Type": "application/x-ndjson"},
    )
    rows = _parse_ndjson(resp.content)
    assert rows[0] == {"line": 1, "error": "invalid_json"}
    assert rows[1] == {"line": 2, "error": "invalid_json"}
    assert rows[2]["line"] == 3


def test_bad_lines_do_not_block_later_lines():
    _create_policy()
    body = (
        b'{"email":"a"}\n'
        b"{not json}\n"
        b"\xff\xfe\x00invalid\n"
        b'{"email":"b"}\n'
    )
    resp = client.post(
        "/redact/ndjson?name=pii",
        content=body,
        headers={"Content-Type": "application/x-ndjson"},
    )
    rows = _parse_ndjson(resp.content)
    assert rows[0]["line"] == 1 and "redacted" in rows[0]
    assert rows[1] == {"line": 2, "error": "invalid_json"}
    assert rows[2] == {"line": 3, "error": "invalid_utf8"}
    assert rows[3]["line"] == 4 and "redacted" in rows[3]
    # Error rows carry nothing but line + error code.
    assert set(rows[1]) == {"line", "error"}
    assert set(rows[2]) == {"line", "error"}


def test_invalid_utf8_takes_precedence_over_json():
    _create_policy()
    resp = client.post(
        "/redact/ndjson?name=pii",
        content=b"\xff{}\n",
        headers={"Content-Type": "application/x-ndjson"},
    )
    rows = _parse_ndjson(resp.content)
    assert rows == [{"line": 1, "error": "invalid_utf8"}]


def test_line_too_long_reported_once_then_resyncs(monkeypatch):
    # Shrink the limit so a 1 MiB line does not have to be built in the test.
    monkeypatch.setattr(ndjson, "MAX_LINE_BYTES", 32)
    _create_policy()
    long_line = b"x" * 5000
    body = long_line + b"\n" + b'{"email":"z"}\n'
    resp = client.post(
        "/redact/ndjson?name=pii",
        content=body,
        headers={"Content-Type": "application/x-ndjson"},
    )
    assert resp.status_code == 200
    rows = _parse_ndjson(resp.content)
    assert rows[0] == {"line": 1, "error": "line_too_long"}
    assert rows[1]["line"] == 2 and rows[1]["redacted"]["email"] == "***REDACTED***"


def test_line_too_long_unterminated_final_line(monkeypatch):
    monkeypatch.setattr(ndjson, "MAX_LINE_BYTES", 16)
    _create_policy()
    resp = client.post(
        "/redact/ndjson?name=pii",
        content=b"q" * 4096,
        headers={"Content-Type": "application/x-ndjson"},
    )
    rows = _parse_ndjson(resp.content)
    assert rows == [{"line": 1, "error": "line_too_long"}]


def test_unknown_policy_is_404():
    resp = client.post(
        "/redact/ndjson?name=ghost",
        content=b"{}\n",
        headers={"Content-Type": "application/x-ndjson"},
    )
    assert resp.status_code == 404


def test_unknown_version_is_404():
    _create_policy()
    resp = client.post(
        "/redact/ndjson?name=pii&version=99",
        content=b"{}\n",
        headers={"Content-Type": "application/x-ndjson"},
    )
    assert resp.status_code == 404


def test_pinned_version_is_immutable():
    _create_policy()
    etag1 = client.get("/policies/pii").headers["etag"]
    client.put(
        "/policies/pii",
        json={"rules": [{"pointer": "/email", "action": "remove"}]},
        headers={"If-Match": etag1},
    )
    body = b'{"email":"a"}\n'
    # No pin -> latest (v2 removes the key).
    resp = client.post(
        "/redact/ndjson?name=pii",
        content=body,
        headers={"Content-Type": "application/x-ndjson"},
    )
    assert resp.headers["policy-version"] == "2"
    assert _parse_ndjson(resp.content)[0]["redacted"] == {}

    # Pinned v1 -> mask behaviour forever.
    resp = client.post(
        "/redact/ndjson?name=pii&version=1",
        content=body,
        headers={"Content-Type": "application/x-ndjson"},
    )
    assert resp.headers["policy-version"] == "1"
    assert _parse_ndjson(resp.content)[0]["redacted"] == {"email": "***REDACTED***"}


def test_wrong_content_type_is_415():
    _create_policy()
    resp = client.post(
        "/redact/ndjson?name=pii",
        content=b"{}\n",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 415


def test_empty_body_is_empty_response():
    _create_policy()
    resp = client.post(
        "/redact/ndjson?name=pii",
        content=b"",
        headers={"Content-Type": "application/x-ndjson"},
    )
    assert resp.status_code == 200
    assert resp.content == b""


def test_scalar_json_lines_are_valid():
    _create_policy()
    resp = client.post(
        "/redact/ndjson?name=pii",
        content=b"123\n\"str\"\nnull\n[1,2]\n",
        headers={"Content-Type": "application/x-ndjson"},
    )
    rows = _parse_ndjson(resp.content)
    assert [r["redacted"] for r in rows] == [123, "str", None, [1, 2]]


def test_many_lines_stream_processed_fully():
    _create_policy()
    n = 3000
    body = b"".join(b'{"email":"e%d"}\n' % i for i in range(n))
    resp = client.post(
        "/redact/ndjson?name=pii",
        content=body,
        headers={"Content-Type": "application/x-ndjson"},
    )
    assert resp.status_code == 200
    rows = _parse_ndjson(resp.content)
    assert len(rows) == n
    assert rows[0]["line"] == 1
    assert rows[-1]["line"] == n
    assert rows[-1]["redacted"] == {"email": "***REDACTED***"}
