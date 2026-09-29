"""Tests for the chunked NDJSON framer and POST /redact/ndjson."""

from __future__ import annotations

import asyncio
import json
import tracemalloc

import pytest
from fastapi.testclient import TestClient

from app import config
from app.main import app
from app.ndjson import DEFAULT_MAX_LINE_BYTES, LineEvent, iter_ndjson_lines

client = TestClient(app)

MiB = 1024 * 1024


# --------------------------------------------------------------------------- #
# Framer unit tests
# --------------------------------------------------------------------------- #


def _collect(data: bytes, chunk_size: int = 4096, max_bytes: int = DEFAULT_MAX_LINE_BYTES):
    """Feed ``data`` in fixed chunks and materialize the emitted events."""

    async def chunks():
        for i in range(0, len(data), chunk_size):
            yield data[i : i + chunk_size]

    async def run():
        return [event async for event in iter_ndjson_lines(chunks(), max_bytes=max_bytes)]

    return asyncio.run(run())


def test_basic_lines_and_physical_numbering():
    events = _collect(b'{"a":1}\n\n{"b":2}\n')
    assert events == [
        LineEvent(1, "line", b'{"a":1}'),
        # physical line 2 is blank -> skipped but its number spent
        LineEvent(3, "line", b'{"b":2}'),
    ]


def test_crlf_strips_cr():
    events = _collect(b'{"a":1}\r\n{"b":2}\r\n')
    assert events == [
        LineEvent(1, "line", b'{"a":1}'),
        LineEvent(2, "line", b'{"b":2}'),
    ]


def test_crlf_split_across_chunks():
    # The \r and \n land in different chunks, including 1-byte chunks.
    events = _collect(b'{"a":1}\r\n{"b":2}', chunk_size=7)
    assert [e.payload for e in events] == [b'{"a":1}', b'{"b":2}']
    events = _collect(b'a\r\nb\n', chunk_size=1)
    assert events == [LineEvent(1, "line", b"a"), LineEvent(2, "line", b"b")]


def test_no_trailing_newline_yields_final_line():
    assert _collect(b'{"a":1}\n{"b":2}') == [
        LineEvent(1, "line", b'{"a":1}'),
        LineEvent(2, "line", b'{"b":2}'),
    ]


def test_single_line_without_newline():
    assert _collect(b"hello") == [LineEvent(1, "line", b"hello")]


def test_empty_body_yields_nothing():
    assert _collect(b"") == []
    # A body of only blank lines emits no events but lines are still counted.
    assert _collect(b"\n\n\n") == []


def test_blank_lines_mixed_with_crlf():
    events = _collect(b"\nx\r\n\n\ny\n")
    assert events == [
        LineEvent(2, "line", b"x"),
        LineEvent(5, "line", b"y"),
    ]


def test_dangling_cr_at_eof_is_content():
    # CR not followed by LF is ordinary JSON content (and makes it invalid).
    assert _collect(b'{"a":1}\n{"b":2}\r') == [
        LineEvent(1, "line", b'{"a":1}'),
        LineEvent(2, "line", b'{"b":2}\r'),
    ]


def test_line_exactly_max_bytes_is_accepted():
    assert _collect(b"x" * MiB + b"\n") == [LineEvent(1, "line", b"x" * MiB)]
    # ... including without a trailing newline.
    assert _collect(b"x" * MiB) == [LineEvent(1, "line", b"x" * MiB)]
    # CRLF terminator is not part of the byte budget.
    assert _collect(b"x" * MiB + b"\r\n") == [LineEvent(1, "line", b"x" * MiB)]


def test_line_over_limit_reports_once_and_resumes():
    data = b"y" * (MiB + 50) + b"\nnext\n"
    events = _collect(data)
    assert events == [
        LineEvent(1, "too_long"),
        LineEvent(2, "line", b"next"),
    ]


def test_line_over_limit_without_terminator():
    events = _collect(b"y" * (MiB + 1))
    assert events == [LineEvent(1, "too_long")]


def test_overlong_cr_split_does_not_falsely_trigger():
    # A max-length line whose CR half of CRLF arrives alone in a chunk must
    # not trip the (max+1) tolerance, and the CR must be stripped.
    events = _collect(b"x" * MiB + b"\r\nnext\n", chunk_size=MiB)
    assert events == [
        LineEvent(1, "line", b"x" * MiB),
        LineEvent(2, "line", b"next"),
    ]


def test_multiple_overlong_lines_each_reported():
    data = b"a" * (MiB + 10) + b"\nshort\n" + b"b" * (MiB + 10) + b"\ntail"
    events = _collect(data)
    assert events == [
        LineEvent(1, "too_long"),
        LineEvent(2, "line", b"short"),
        LineEvent(3, "too_long"),
        LineEvent(4, "line", b"tail"),
    ]


def test_overlong_spanning_byte_sized_chunks():
    # Pathological 1-byte chunks: overrun is noticed on the (max+1)th byte and
    # every following byte (up to the newline) is drained.
    events = _collect(b"a" * (MiB + 7) + b"\nok\n", chunk_size=1)
    assert events == [
        LineEvent(1, "too_long"),
        LineEvent(2, "line", b"ok"),
    ]


def test_custom_max_bytes():
    events = _collect(b"abcde\nfg\n", max_bytes=3)
    assert events == [
        LineEvent(1, "too_long"),
        LineEvent(2, "line", b"fg"),
    ]


def test_memory_does_not_grow_with_file_size():
    # Streaming hundreds of MiB must not accumulate lines/buffers: peak heap
    # stays in the order of a single line, nowhere near the file size.
    total_bytes = 200 * MiB

    async def run():
        async def chunks():
            # Each chunk is one maximum-length physical line (~200 MiB total).
            block = b"x" * MiB + b"\n"
            for _ in range(total_bytes // len(block)):
                yield block

        tracemalloc.start()
        count = 0
        async for event in iter_ndjson_lines(chunks()):
            count += 1
            assert event.payload == b"x" * MiB
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return count, peak

    count, peak = asyncio.run(run())
    assert count == total_bytes // (MiB + 1)
    assert peak < 8 * MiB  # a ~200 MiB file costs only a few MiB of memory


# --------------------------------------------------------------------------- #
# HTTP integration tests
# --------------------------------------------------------------------------- #


def _create_policy(name: str = "pii", rules=None, etag=None):
    rules = rules or [
        {"pointer": "/users/*/email", "action": "mask"},
        {"pointer": "/users/*/password", "action": "remove"},
    ]
    headers = {}
    if etag is not None:
        headers["If-Match"] = etag
    resp = client.put(f"/policies/{name}", json={"rules": rules}, headers=headers)
    return resp


def _ndjson_post(body: bytes, name: str = "pii", version=None, **extra_headers):
    url = f"/redact/ndjson?name={name}"
    if version is not None:
        url += f"&version={version}"
    headers = {"Content-Type": "application/x-ndjson"}
    headers.update(extra_headers)
    return client.post(url, content=body, headers=headers)


def test_ndjson_happy_path():
    _create_policy()
    body = (
        b'{"users":[{"email":"a@x.io","password":"p","name":"a"}]}\n'
        b"\n"  # blank line: skipped, but shifts the next physical line number
        b'{"users":[{"email":"b@x.io","password":"q"}]}\r\n'
        b'{"no": "match"}\n'
    )
    resp = _ndjson_post(body)
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "application/x-ndjson"
    assert resp.headers["x-policy-name"] == "pii"
    assert resp.headers["x-policy-version"] == "1"

    rows = [json.loads(line) for line in resp.text.splitlines()]
    assert [r["line"] for r in rows] == [1, 3, 4]

    first = rows[0]["redacted"]
    assert first["users"][0]["email"] == "***REDACTED***"
    assert "password" not in first["users"][0]
    assert first["users"][0]["name"] == "a"
    # Audit entries reuse the existing semantics incl. the policy stamp.
    assert {e["pointer"] for e in rows[0]["audit"]} == {
        "/users/0/email",
        "/users/0/password",
    }
    assert all(e["policy"] == {"name": "pii", "version": 1} for e in rows[0]["audit"])
    assert rows[2]["redacted"] == {"no": "match"}
    assert rows[2]["audit"] == []


def test_ndjson_policy_version_pinned_and_header(monkeypatch):
    created = _create_policy()
    v1_etag = created.headers["ETag"]
    _create_policy(
        rules=[
            {"pointer": "/users/*/email", "action": "sha256"},
            {"pointer": "/users/*/password", "action": "remove"},
        ],
        etag=v1_etag,
    )

    body = b'{"users":[{"email":"a@x.io"}]}'
    # No version -> current (v2, sha256).
    resp = _ndjson_post(body)
    assert resp.headers["x-policy-version"] == "2"
    row = json.loads(resp.text)
    assert len(row["redacted"]["users"][0]["email"]) == 64

    # Pin v1 -> mask.
    resp = _ndjson_post(body, version=1)
    assert resp.status_code == 200
    assert resp.headers["x-policy-version"] == "1"
    row = json.loads(resp.text)
    assert row["redacted"]["users"][0]["email"] == "***REDACTED***"
    assert row["audit"][0]["policy"] == {"name": "pii", "version": 1}


def test_ndjson_missing_policy_returns_404():
    resp = _ndjson_post(b"{}\n", name="ghost")
    assert resp.status_code == 404
    assert resp.json()["detail"]["error"] == "policy_not_found"


def test_ndjson_missing_version_returns_404():
    _create_policy()
    resp = _ndjson_post(b"{}\n", version=99)
    assert resp.status_code == 404


def test_ndjson_wrong_content_type_returns_415():
    _create_policy()
    resp = client.post(
        "/redact/ndjson?name=pii", content=b"{}\n", headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 415


def test_ndjson_bad_version_param_returns_422():
    _create_policy()
    resp = client.post(
        "/redact/ndjson?name=pii&version=0",
        content=b"{}\n",
        headers={"Content-Type": "application/x-ndjson"},
    )
    assert resp.status_code == 422


def test_ndjson_invalid_json_does_not_stop_stream():
    _create_policy()
    body = b'{"users":[]}\n{not json}\n{"users":[{"email":"c@x.io"}]}\n'
    resp = _ndjson_post(body)
    assert resp.status_code == 200
    rows = [json.loads(line) for line in resp.text.splitlines()]
    assert [r["line"] for r in rows] == [1, 2, 3]
    assert rows[1] == {"line": 2, "error": "invalid_json"}
    assert rows[2]["redacted"]["users"][0]["email"] == "***REDACTED***"


def test_ndjson_invalid_utf8_does_not_stop_stream():
    _create_policy()
    body = b'{"ok":1}\n\xff\xfe{"bad"\n{"users":[{"email":1}]}\n'
    resp = _ndjson_post(body)
    assert resp.status_code == 200
    rows = [json.loads(line) for line in resp.text.splitlines()]
    assert rows[0] == {"line": 1, "redacted": {"ok": 1}, "audit": []}
    # A UTF-8 error takes precedence over the JSON error on the same line.
    assert rows[1] == {"line": 2, "error": "invalid_utf8"}
    assert rows[2]["line"] == 3


def test_ndjson_line_too_long_reports_once():
    _create_policy()
    body = (
        b'"x":'  # will be inside an overlong line
        + b"a" * (DEFAULT_MAX_LINE_BYTES + 10)
        + b"\n"
        + b'{"users":[]}\n'
        + b"b" * (DEFAULT_MAX_LINE_BYTES + 1)  # unterminated final line
    )
    resp = _ndjson_post(body)
    assert resp.status_code == 200
    rows = [json.loads(line) for line in resp.text.splitlines()]
    assert rows[0] == {"line": 1, "error": "line_too_long"}
    assert rows[1] == {"line": 2, "redacted": {"users": []}, "audit": []}
    assert rows[2] == {"line": 3, "error": "line_too_long"}


def test_ndjson_empty_and_blank_only_bodies():
    _create_policy()
    assert _ndjson_post(b"").status_code == 200
    assert _ndjson_post(b"").text == ""
    resp = _ndjson_post(b"\n\r\n\n")
    assert resp.status_code == 200
    assert resp.text == ""
    # Headers still describe the pinned policy even when nothing is emitted.
    assert resp.headers["x-policy-version"] == "1"


def test_ndjson_whitespace_only_line_is_invalid_json():
    # A whitespace-only line is non-blank; JSON parsing fails as a scalar.
    _create_policy()
    resp = _ndjson_post(b"   \n")
    rows = [json.loads(line) for line in resp.text.splitlines()]
    assert rows == [{"line": 1, "error": "invalid_json"}]


def test_ndjson_uses_configured_salt(monkeypatch):
    _create_policy(
        name="salted",
        rules=[{"pointer": "/k", "action": "sha256"}],
    )
    monkeypatch.setattr(config, "get_salt", lambda: "pepper")
    resp = _ndjson_post(b'{"k":"v"}', name="salted")
    row = json.loads(resp.text)
    import hashlib

    expected = hashlib.sha256(b"pepper" + b'"v"').hexdigest()
    assert row["redacted"]["k"] == expected


def test_ndjson_version_fixed_before_body_is_consumed():
    # The policy is resolved once up front; even a large multi-MB stream all
    # sees the same version (v1), and the header reports it.
    created = _create_policy()
    etag = created.headers["ETag"]
    _create_policy(
        rules=[{"pointer": "/users/*/email", "action": "sha256"}],
        etag=etag,
    )
    body = b'{"users":[{"email":"a@x.io"}]}\n' * 50_000
    resp = _ndjson_post(body, version=1)
    assert resp.status_code == 200
    assert resp.headers["x-policy-version"] == "1"
    rows = resp.text.splitlines()
    assert len(rows) == 50_000
    for line in rows:
        row = json.loads(line)
        assert row["redacted"]["users"][0]["email"] == "***REDACTED***"
        assert row["audit"][0]["policy"]["version"] == 1


def test_ndjson_deeply_nested_line_does_not_abort_stream():
    # A line nested past the interpreter recursion limit cannot be parsed or
    # walked safely; it must report invalid_json and leave later lines intact.
    _create_policy()
    deep = b'{"a":' * 5000 + b"1" + b"}" * 5000
    assert len(deep) < DEFAULT_MAX_LINE_BYTES
    body = deep + b"\n" + b'{"users":[]}\n'
    resp = _ndjson_post(body)
    assert resp.status_code == 200
    rows = [json.loads(line) for line in resp.text.splitlines()]
    assert rows[0] == {"line": 1, "error": "invalid_json"}
    assert rows[1]["line"] == 2


def test_ndjson_line_exactly_limit_is_processed():
    # A legal-but-large document at the exact byte ceiling still works.
    _create_policy(rules=[{"pointer": "/email", "action": "mask"}])
    prefix, suffix = b'{"email": "', b'"}'
    doc = prefix + b"a" * (DEFAULT_MAX_LINE_BYTES - len(prefix) - len(suffix)) + suffix
    assert len(doc) == DEFAULT_MAX_LINE_BYTES
    resp = _ndjson_post(doc)  # no trailing newline
    assert resp.status_code == 200
    row = json.loads(resp.text)
    assert row["line"] == 1
    assert row["redacted"]["email"] == "***REDACTED***"


def test_ndjson_in_openapi():
    paths = client.get("/openapi.json").json()["paths"]
    assert "/redact/ndjson" in paths


@pytest.mark.parametrize("chunk_size", [1, 3, 7, 64, 4096])
def test_framer_chunk_boundaries_are_insignificant(chunk_size):
    data = b'{"a":1}\r\n\n{"b":[1,2]}\nlast-no-newline'
    events = _collect(data, chunk_size=chunk_size)
    assert events == [
        LineEvent(1, "line", b'{"a":1}'),
        LineEvent(3, "line", b'{"b":[1,2]}'),
        LineEvent(4, "line", b"last-no-newline"),
    ]
