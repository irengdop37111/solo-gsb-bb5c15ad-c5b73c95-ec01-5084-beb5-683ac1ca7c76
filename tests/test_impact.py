"""Tests for the candidate-policy impact preview (diff engine + HTTP endpoint)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.impact import diff_audits, preview_impact
from app.main import app
from app.redaction import compile_rule, redact

client = TestClient(app)


def rule(index, pointer, action, name=None):
    return compile_rule(index=index, pointer=pointer, action=action, name=name)


def audits(data, current_rules, candidate_rules, salt=""):
    _, current_audit = redact(data, current_rules, salt=salt)
    _, candidate_audit = redact(data, candidate_rules, salt=salt)
    return current_audit, candidate_audit


# --------------------------------------------------------------------------- #
# Pure diff classification
# --------------------------------------------------------------------------- #


def test_diff_added_removed_changed():
    data = {"email": "a@x", "password": "p", "name": "n"}
    current = [rule(0, "/email", "mask")]
    candidate = [
        rule(0, "/email", "sha256"),  # action change
        rule(1, "/password", "remove"),  # newly covered
    ]
    cur, cand = audits(data, current, candidate)
    diff = diff_audits(cur, cand)

    assert [e["pointer"] for e in diff["added"]] == ["/password"]
    assert diff["added"][0]["action"] == "remove"
    assert [e["pointer"] for e in diff["removed"]] == []
    changed = {e["pointer"]: e for e in diff["changed"]}
    assert set(changed) == {"/email"}
    assert changed["/email"]["before"]["action"] == "mask"
    assert changed["/email"]["after"]["action"] == "sha256"
    # /name is untouched on both sides -> never appears.
    pointers = {
        e["pointer"]
        for bucket in diff.values()
        for e in bucket
    }
    assert "/name" not in pointers


def test_diff_is_symmetric_for_removed():
    data = {"password": "p"}
    cur, cand = audits(data, [rule(0, "/password", "remove")], [])
    diff = diff_audits(cur, cand)
    assert [e["pointer"] for e in diff["removed"]] == ["/password"]
    assert diff["removed"][0]["action"] == "remove"
    assert diff["added"] == [] and diff["changed"] == []


def test_identical_rule_sets_have_no_impact():
    data = {"users": [{"email": "a@x"}, {"email": "b@x"}]}
    rules = [rule(0, "/users/*/email", "mask")]
    cur, cand = audits(data, rules, [rule(0, "/users/*/email", "mask")])
    diff = diff_audits(cur, cand)
    assert diff == {"added": [], "removed": [], "changed": []}


def test_same_action_different_winning_rule_is_not_a_change():
    # Both rule sets mask the email; only the winning rule declaration differs.
    # The externally visible effect is identical, so nothing is reported.
    data = {"users": [{"email": "a@x"}]}
    cur, cand = audits(
        data,
        [rule(0, "/**/email", "mask")],
        [rule(0, "/users/*/email", "mask")],
    )
    assert diff_audits(cur, cand) == {"added": [], "removed": [], "changed": []}


def test_changed_rule_refs_identify_both_winners():
    data = {"k": "v"}
    cur, cand = audits(
        data,
        [rule(0, "/k", "mask")],
        [rule(3, "/k", "remove")],
    )
    (entry,) = diff_audits(cur, cand)["changed"]
    assert entry["before"]["rule"]["index"] == 0
    assert entry["after"]["rule"]["index"] == 3


# --------------------------------------------------------------------------- #
# Subtree short-circuit semantics
# --------------------------------------------------------------------------- #


def test_parent_short_circuit_shows_up_when_parent_action_changes():
    # Current policy masks the whole card; the candidate drops that parent
    # rule and handles the children separately.
    data = {"card": {"number": "42", "cvv": "999"}, "ok": 1}
    cur, cand = audits(
        data,
        [rule(0, "/card", "mask")],
        [
            rule(0, "/card/number", "mask"),
            rule(1, "/card/cvv", "remove"),
        ],
    )
    diff = diff_audits(cur, cand)
    assert [e["pointer"] for e in diff["removed"]] == ["/card"]
    assert sorted(e["pointer"] for e in diff["added"]) == [
        "/card/cvv",
        "/card/number",
    ]
    assert diff["changed"] == []


def test_descendant_rule_added_inside_still_masked_parent_has_no_impact():
    # The parent /card mask short-circuits the whole subtree under BOTH rule
    # sets: an extra descendant rule never becomes effective -> zero impact.
    data = {"card": {"number": "42", "cvv": "999"}}
    cur, cand = audits(
        data,
        [rule(0, "/card", "mask")],
        [
            rule(0, "/card", "mask"),
            rule(1, "/card/cvv", "remove"),
        ],
    )
    diff = diff_audits(cur, cand)
    assert diff == {"added": [], "removed": [], "changed": []}


def test_new_parent_mask_removes_descendant_actions_from_audit():
    data = {"card": {"number": "42", "cvv": "999"}}
    cur, cand = audits(
        data,
        [
            rule(0, "/card/number", "mask"),
            rule(1, "/card/cvv", "remove"),
        ],
        [rule(0, "/card", "sha256")],
    )
    diff = diff_audits(cur, cand)
    assert sorted(e["pointer"] for e in diff["removed"]) == [
        "/card/cvv",
        "/card/number",
    ]
    assert [e["pointer"] for e in diff["added"]] == ["/card"]
    assert diff["added"][0]["action"] == "sha256"


# --------------------------------------------------------------------------- #
# Array deletion stability
# --------------------------------------------------------------------------- #


def test_array_deletion_keeps_original_indexes_in_diff():
    data = {"items": [{"v": "a"}, {"v": "b"}, {"v": "c"}]}
    current = [rule(0, "/items/*/v", "mask")]
    candidate = [
        rule(0, "/items/*/v", "mask"),
        rule(1, "/items/0", "remove"),  # literal parent rule wins for item 0
    ]
    cur, cand = audits(data, current, candidate)
    diff = diff_audits(cur, cand)

    # /items/0 is newly removed and its child audit disappears (short-circuit).
    assert [e["pointer"] for e in diff["added"]] == ["/items/0"]
    assert [e["pointer"] for e in diff["removed"]] == ["/items/0/v"]
    # Surviving elements keep their ORIGINAL positions (1, 2) on both sides,
    # so nothing is reported for them even though the output list shifts.
    assert diff["changed"] == []
    assert {e["pointer"] for e in cur} == {"/items/0/v", "/items/1/v", "/items/2/v"}
    assert {e["pointer"] for e in cand} == {"/items/0", "/items/1/v", "/items/2/v"}


def test_preview_impact_aggregates_counts():
    samples = [{"a": 1}, {"a": 1, "b": 2}]
    report = preview_impact(
        samples,
        [rule(0, "/a", "mask")],
        [rule(0, "/a", "mask"), rule(1, "/b", "remove")],
    )
    assert report["summary"] == {
        "added": 1,
        "removed": 0,
        "changed": 0,
        "samples": 2,
    }
    assert report["samples"][0]["has_changes"] is False
    assert report["samples"][1]["has_changes"] is True
    assert report["samples"][1]["counts"]["added"] == 1


# --------------------------------------------------------------------------- #
# HTTP layer
# --------------------------------------------------------------------------- #


def _create(name="pii", rules=None):
    rules = (
        rules
        if rules is not None
        else [{"pointer": "/users/*/email", "action": "mask"}]
    )
    resp = client.put(f"/policies/{name}", json={"rules": rules})
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_impact_endpoint_reports_baseline_and_diff():
    baseline = _create()
    payload = {
        "rules": [
            {"pointer": "/users/*/email", "action": "sha256"},
            {"pointer": "/users/*/password", "action": "remove"},
        ],
        "samples": [
            {"users": [{"email": "a@x", "password": "p", "name": "a"}]},
            {"users": [{"email": "b@x", "password": "q"}]},
        ],
    }
    resp = client.post("/policies/pii/impact", json=payload)
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["baseline"] == {
        "name": "pii",
        "version": 1,
        "etag": baseline["etag"],
    }
    assert len(body["samples"]) == 2
    first = body["samples"][0]
    assert first["index"] == 0
    assert [e["pointer"] for e in first["diff"]["added"]] == [
        "/users/0/password"
    ]
    assert first["diff"]["removed"] == []
    changed = first["diff"]["changed"]
    assert len(changed) == 1 and changed[0]["pointer"] == "/users/0/email"
    assert changed[0]["before"] == {
        "action": "mask",
        "rule": {"index": 0, "pointer": "/users/*/email", "action": "mask"},
    }
    assert changed[0]["after"]["action"] == "sha256"
    assert first["counts"] == {"added": 1, "removed": 0, "changed": 1}
    assert first["has_changes"] is True

    assert body["summary"] == {
        "added": 2,
        "removed": 0,
        "changed": 2,
        "samples": 2,
    }


def test_impact_never_creates_a_new_version():
    _create()
    resp = client.post(
        "/policies/pii/impact",
        json={
            "rules": [{"pointer": "/x", "action": "remove"}],
            "samples": [{"x": 1}],
        },
    )
    assert resp.status_code == 200
    # Current version untouched; no version 2 exists.
    current = client.get("/policies/pii").json()
    assert current["version"] == 1
    assert current["rules"] == [{"pointer": "/users/*/email", "action": "mask"}]
    assert client.get("/policies/pii/versions/2").status_code == 404


def test_impact_policy_not_found_is_404():
    resp = client.post(
        "/policies/ghost/impact",
        json={"rules": [], "samples": [{"a": 1}]},
    )
    assert resp.status_code == 404
    assert resp.json()["detail"]["name"] == "ghost"


def test_impact_identical_candidate_reports_no_changes():
    _create()
    resp = client.post(
        "/policies/pii/impact",
        json={
            "rules": [{"pointer": "/users/*/email", "action": "mask"}],
            "samples": [{"users": [{"email": "a@x"}]}],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["samples"][0]["diff"] == {"added": [], "removed": [], "changed": []}
    assert body["samples"][0]["has_changes"] is False
    assert body["summary"] == {"added": 0, "removed": 0, "changed": 0, "samples": 1}


def test_impact_empty_candidate_rules_are_valid():
    # Previewing "what if the policy had no rules" is legitimate.
    _create()
    resp = client.post(
        "/policies/pii/impact",
        json={"rules": [], "samples": [{"users": [{"email": "a@x"}]}]},
    )
    assert resp.status_code == 200, resp.text
    removed = resp.json()["samples"][0]["diff"]["removed"]
    assert [e["pointer"] for e in removed] == ["/users/0/email"]


def test_impact_sample_limits():
    _create()

    too_many = {"rules": [], "samples": [{"a": i} for i in range(21)]}
    assert client.post("/policies/pii/impact", json=too_many).status_code == 422

    zero = {"rules": [], "samples": []}
    assert client.post("/policies/pii/impact", json=zero).status_code == 422

    missing = {"rules": []}
    assert client.post("/policies/pii/impact", json=missing).status_code == 422

    # Exactly at the boundary (20) is accepted.
    boundary = {"rules": [], "samples": [{"a": i} for i in range(20)]}
    assert client.post("/policies/pii/impact", json=boundary).status_code == 200


def test_impact_invalid_candidate_rules_are_422():
    _create()
    bad_pointer = {
        "rules": [{"pointer": "no-leading-slash", "action": "mask"}],
        "samples": [{"a": 1}],
    }
    resp = client.post("/policies/pii/impact", json=bad_pointer)
    assert resp.status_code == 422
    assert "pointer" in resp.text

    bad_action = {
        "rules": [{"pointer": "/a", "action": "explode"}],
        "samples": [{"a": 1}],
    }
    assert client.post("/policies/pii/impact", json=bad_action).status_code == 422

    extra_field = {
        "rules": [],
        "samples": [{}],
        "bogus": 1,
    }
    assert client.post("/policies/pii/impact", json=extra_field).status_code == 422


def test_impact_uses_current_version_after_policy_update():
    etag = _create()["etag"]
    client.put(
        "/policies/pii",
        json={"rules": [{"pointer": "/users/*/email", "action": "remove"}]},
        headers={"If-Match": etag},
    )
    # Candidate identical to the NEW current version -> no impact; baseline v2.
    resp = client.post(
        "/policies/pii/impact",
        json={
            "rules": [{"pointer": "/users/*/email", "action": "remove"}],
            "samples": [{"users": [{"email": "a@x"}]}],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["baseline"]["version"] == 2
    assert body["samples"][0]["has_changes"] is False


def test_impact_openapi_documented():
    paths = client.get("/openapi.json").json()["paths"]
    assert "/policies/{name}/impact" in paths
