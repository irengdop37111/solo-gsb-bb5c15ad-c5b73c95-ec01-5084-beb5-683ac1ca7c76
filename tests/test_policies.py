"""Integration tests for the versioned policy library and policy redaction."""

from __future__ import annotations

import threading

from fastapi.testclient import TestClient

from app import policy_store
from app.main import app

client = TestClient(app)

RULES_V1 = [
    {"pointer": "/users/*/email", "action": "mask"},
]
RULES_V2 = [
    {"pointer": "/users/*/email", "action": "mask"},
    {"pointer": "/users/*/password", "action": "remove"},
]
DATA = {"users": [{"name": "a", "email": "a@x", "password": "p"}]}


# --------------------------------------------------------------------------- #
# PUT: create / update / ETag lifecycle
# --------------------------------------------------------------------------- #


def test_create_policy_first_put():
    resp = client.put("/policies/pii", json={"rules": RULES_V1})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["name"] == "pii"
    assert body["version"] == 1
    assert body["rules"] == RULES_V1
    etag = body["etag"]
    assert etag.startswith('"') and etag.endswith('"')
    # The ETag is also returned as a response header.
    assert resp.headers["ETag"] == etag
    assert "created_at" in body


def test_update_requires_matching_etag():
    created = client.put("/policies/pii", json={"rules": RULES_V1})
    etag = created.json()["etag"]

    # No If-Match on an existing policy -> 412.
    resp = client.put("/policies/pii", json={"rules": RULES_V2})
    assert resp.status_code == 412
    assert resp.json()["detail"]["current_etag"] == etag

    # Stale / wrong ETag -> 412.
    resp = client.put(
        "/policies/pii", json={"rules": RULES_V2}, headers={"If-Match": '"deadbeef"'}
    )
    assert resp.status_code == 412
    assert resp.json()["detail"]["error"] == "etag_mismatch"

    # Correct ETag -> new immutable version.
    resp = client.put("/policies/pii", json={"rules": RULES_V2}, headers={"If-Match": etag})
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == 2
    assert body["etag"] != etag
    assert body["rules"] == RULES_V2


def test_if_match_star_semantics():
    # '*' on a missing policy fails (precondition requires existence).
    resp = client.put("/policies/pii", json={"rules": RULES_V1}, headers={"If-Match": "*"})
    assert resp.status_code == 412

    created = client.put("/policies/pii", json={"rules": RULES_V1})
    etag = created.json()["etag"]

    # '*' on an existing policy appends a new version.
    resp = client.put("/policies/pii", json={"rules": RULES_V2}, headers={"If-Match": "*"})
    assert resp.status_code == 200
    assert resp.json()["version"] == 2

    # Old ETag is now stale.
    resp = client.put("/policies/pii", json={"rules": RULES_V1}, headers={"If-Match": etag})
    assert resp.status_code == 412


def test_version_numbers_are_immutable_and_monotonic():
    etag = client.put("/policies/pii", json={"rules": RULES_V1}).json()["etag"]
    etag = client.put(
        "/policies/pii", json={"rules": RULES_V2}, headers={"If-Match": etag}
    ).json()["etag"]
    client.put(
        "/policies/pii", json={"rules": RULES_V1}, headers={"If-Match": etag}
    )

    v1 = client.get("/policies/pii/versions/1").json()
    v2 = client.get("/policies/pii/versions/2").json()
    v3 = client.get("/policies/pii/versions/3").json()
    assert [v["version"] for v in (v1, v2, v3)] == [1, 2, 3]
    assert v1["rules"] == RULES_V1  # old snapshot untouched even though v3 == v1
    assert v2["rules"] == RULES_V2
    assert v3["rules"] == RULES_V1
    assert v1["etag"] != v3["etag"]  # ETags embed the version


def test_get_current_policy_and_missing_versions():
    client.put("/policies/pii", json={"rules": RULES_V1})

    resp = client.get("/policies/pii")
    assert resp.status_code == 200
    assert resp.json()["version"] == 1
    assert resp.headers["ETag"] == resp.json()["etag"]

    assert client.get("/policies/nope").status_code == 404
    assert client.get("/policies/nope/versions/1").status_code == 404
    assert client.get("/policies/pii/versions/2").status_code == 404


def test_policy_name_validation():
    assert client.put("/policies/bad name", json={"rules": RULES_V1}).status_code == 422
    assert client.put("/policies/-lead", json={"rules": RULES_V1}).status_code == 422
    bad = client.post(
        "/redact",
        json={"data": {}, "policy": {"name": "bad/name"}},
    )
    assert bad.status_code == 422


def test_put_validates_rules():
    resp = client.put(
        "/policies/pii", json={"rules": [{"pointer": "no-slash", "action": "mask"}]}
    )
    assert resp.status_code == 422


# --------------------------------------------------------------------------- #
# Concurrent updates: only one winner per ETag
# --------------------------------------------------------------------------- #


def test_concurrent_updates_exactly_one_wins():
    etag = client.put("/policies/pii", json={"rules": RULES_V1}).json()["etag"]

    barrier = threading.Barrier(2)
    results: list[dict] = []

    def updater(rules):
        barrier.wait()
        resp = client.put(
            "/policies/pii", json={"rules": rules}, headers={"If-Match": etag}
        )
        results.append({"status": resp.status_code, "body": resp.json()})

    t1 = threading.Thread(target=updater, args=(RULES_V2,))
    t2 = threading.Thread(
        target=updater,
        args=([{"pointer": "/x", "action": "remove"}],),
    )
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    statuses = sorted(r["status"] for r in results)
    assert statuses == [200, 412]
    winner = next(r for r in results if r["status"] == 200)["body"]
    assert winner["version"] == 2

    current = client.get("/policies/pii").json()
    assert current["version"] == 2
    assert current["rules"] == winner["rules"]
    # Exactly two version rows: v1 and the winning v2 — no gaps, no duplicates.
    assert client.get("/policies/pii/versions/3").status_code == 404


# --------------------------------------------------------------------------- #
# /redact with policies
# --------------------------------------------------------------------------- #


def _create_two_versions():
    etag = client.put("/policies/pii", json={"rules": RULES_V1}).json()["etag"]
    client.put("/policies/pii", json={"rules": RULES_V2}, headers={"If-Match": etag})


def test_redact_with_latest_policy():
    _create_two_versions()
    resp = client.post("/redact", json={"data": DATA, "policy": {"name": "pii"}})
    assert resp.status_code == 200, resp.text
    body = resp.json()

    # Latest (v2): password removed, email masked.
    user = body["redacted"]["users"][0]
    assert user == {"name": "a", "email": "***REDACTED***"}

    # Response and audit name the *concrete* policy/version actually applied.
    assert body["policy"] == {"name": "pii", "version": 2}
    assert body["audit"], "expected audit entries"
    for entry in body["audit"]:
        assert entry["policy"] == {"name": "pii", "version": 2}


def test_redact_with_pinned_historical_version_is_reproducible():
    _create_two_versions()
    payload = {"data": DATA, "policy": {"name": "pii", "version": 1}}
    first = client.post("/redact", json=payload).json()
    second = client.post("/redact", json=payload).json()

    # v1 only masks email; password survives.
    assert first["redacted"] == second["redacted"]
    assert first["redacted"]["users"][0]["password"] == "p"
    assert first["policy"] == {"name": "pii", "version": 1}
    assert all(e["policy"]["version"] == 1 for e in first["audit"])


def test_latest_resolves_atomically_after_update():
    _create_two_versions()
    before = client.post(
        "/redact", json={"data": DATA, "policy": {"name": "pii"}}
    ).json()
    assert before["policy"]["version"] == 2

    # Roll a v3 that removes nothing extra but pins name only -> still resolves.
    etag = client.get("/policies/pii").json()["etag"]
    client.put(
        "/policies/pii",
        json={"rules": [{"pointer": "/users/*/name", "action": "mask"}]},
        headers={"If-Match": etag},
    )
    after = client.post(
        "/redact", json={"data": DATA, "policy": {"name": "pii"}}
    ).json()
    assert after["policy"]["version"] == 3
    assert after["redacted"]["users"][0]["name"] == "***REDACTED***"
    # Pinned v2 is unaffected by v3 existing.
    pinned = client.post(
        "/redact", json={"data": DATA, "policy": {"name": "pii", "version": 2}}
    ).json()
    assert pinned["redacted"]["users"][0]["name"] == "a"


def test_redact_policy_not_found():
    resp = client.post("/redact", json={"data": DATA, "policy": {"name": "ghost"}})
    assert resp.status_code == 404
    assert resp.json()["detail"]["name"] == "ghost"

    client.put("/policies/pii", json={"rules": RULES_V1})
    resp = client.post(
        "/redact", json={"data": DATA, "policy": {"name": "pii", "version": 9}}
    )
    assert resp.status_code == 404
    assert resp.json()["detail"]["version"] == 9


def test_rules_and_policy_are_mutually_exclusive():
    client.put("/policies/pii", json={"rules": RULES_V1})
    resp = client.post(
        "/redact",
        json={
            "data": DATA,
            "rules": [{"pointer": "/x", "action": "mask"}],
            "policy": {"name": "pii"},
        },
    )
    assert resp.status_code == 422
    assert "mutually exclusive" in resp.text


def test_inline_rules_omit_policy_in_response():
    resp = client.post(
        "/redact",
        json={"data": DATA, "rules": [{"pointer": "/users/*/email", "action": "mask"}]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["policy"] is None
    assert all("policy" not in entry for entry in body["audit"])


def test_empty_inline_rules_still_supported():
    # Backwards compatibility: no rules and no policy -> unchanged document.
    resp = client.post("/redact", json={"data": {"a": 1}})
    assert resp.status_code == 200
    assert resp.json()["redacted"] == {"a": 1}
    assert resp.json()["audit"] == []


# --------------------------------------------------------------------------- #
# Store-level persistence
# --------------------------------------------------------------------------- #


def test_data_survives_store_reconfigure(tmp_path):
    db_path = str(tmp_path / "persist.db")
    policy_store.configure(db_path)
    snapshot, created = policy_store.put_policy("pii", RULES_V1, None)
    assert created
    etag = snapshot["etag"]

    # Simulate a process restart: drop all in-memory state, reopen the file.
    policy_store.configure(db_path)
    current = policy_store.get_current("pii")
    assert current["version"] == 1
    assert current["etag"] == etag
    assert policy_store.get_version("pii", 1)["rules"] == RULES_V1


# --------------------------------------------------------------------------- #
# Concurrency stress: read/modify/retry loops from many threads
# --------------------------------------------------------------------------- #


def test_concurrent_retry_loop_never_loses_an_update():
    import time

    n_threads = 8
    target_updates_per_thread = 3

    def worker():
        # Each thread repeatedly: read current ETag, append a version; if it
        # loses the race (412), reread and retry until its own update lands.
        applied = 0
        while applied < target_updates_per_thread:
            current = policy_store.get_current("stress")
            rules = [{"pointer": f"/t/{threading.get_ident()}/{applied}", "action": "mask"}]
            try:
                policy_store.put_policy("stress", rules, current["etag"])
                applied += 1
            except policy_store.PreconditionFailed:
                time.sleep(0.001)

    initial, _ = policy_store.put_policy("stress", RULES_V1, None)
    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final = policy_store.get_current("stress")
    # v1 + one version per successful update, no gaps or duplicate numbers.
    assert final["version"] == 1 + n_threads * target_updates_per_thread
    for version in range(1, final["version"] + 1):
        assert policy_store.get_version("stress", version)["version"] == version

