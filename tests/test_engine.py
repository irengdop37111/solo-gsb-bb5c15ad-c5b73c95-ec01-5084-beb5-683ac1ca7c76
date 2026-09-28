"""Unit tests for the pure redaction engine (no web layer)."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from app.redaction import (
    MASK_VALUE,
    InvalidPointer,
    compile_rule,
    parse_pointer,
    redact,
    to_pointer,
)


def rule(index, pointer, action, name=None):
    return compile_rule(index=index, pointer=pointer, action=action, name=name)


# --------------------------------------------------------------------------- #
# JSON Pointer parsing / rendering
# --------------------------------------------------------------------------- #


def test_parse_empty_pointer_is_root():
    assert parse_pointer("") == []


def test_parse_pointer_unescaping():
    assert parse_pointer("/a/b") == ["a", "b"]
    assert parse_pointer("/a~1b/c~0d") == ["a/b", "c~d"]
    assert parse_pointer("/a//b") == ["a", "", "b"]
    assert parse_pointer("/0") == ["0"]


def test_parse_pointer_rejects_non_pointer():
    with pytest.raises(InvalidPointer):
        parse_pointer("no-leading-slash")


@pytest.mark.parametrize(
    "pointer",
    ["", "/users/0/email", "/a~1b/c~0d", "/a//b"],
)
def test_pointer_roundtrip(pointer):
    assert to_pointer(tuple(parse_pointer(pointer))) == pointer


# --------------------------------------------------------------------------- #
# Basic actions
# --------------------------------------------------------------------------- #


def test_mask_replaces_value():
    data = {"name": "alice", "age": 30}
    out, audit = redact(data, [rule(0, "/name", "mask")])
    assert out == {"name": MASK_VALUE, "age": 30}
    assert audit == [
        {"pointer": "/name", "action": "mask", "rule": {"index": 0, "pointer": "/name", "action": "mask"}}
    ]
    # Original untouched
    assert data == {"name": "alice", "age": 30}


def test_remove_deletes_key():
    data = {"a": 1, "b": 2}
    out, audit = redact(data, [rule(0, "/a", "remove")])
    assert out == {"b": 2}
    assert audit[0]["pointer"] == "/a"
    assert audit[0]["rule"]["index"] == 0


def test_sha256_is_salted_and_canonical():
    salt = "pepper"
    data = {"secret": "t0psecret", "other": {"z": 1, "a": 2}}
    out, audit = redact(data, [rule(0, "/secret", "sha256")], salt=salt)

    payload = json.dumps("t0psecret", sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    expected = hashlib.sha256((salt + payload).encode()).hexdigest()
    assert out["secret"] == expected
    assert len(out["secret"]) == 64
    assert audit[0]["action"] == "sha256"

    # Same input + salt -> same digest; different salt -> different digest.
    out2, _ = redact(data, [rule(0, "/secret", "sha256")], salt=salt)
    assert out2["secret"] == out["secret"]
    out3, _ = redact(data, [rule(0, "/secret", "sha256")], salt="other")
    assert out3["secret"] != out["secret"]

    # Hashing an object uses canonical (sorted-key) JSON, so key order is irrelevant.
    r1, _ = redact({"x": {"z": 1, "a": 2}}, [rule(0, "/x", "sha256")], salt=salt)
    r2, _ = redact({"x": {"a": 2, "z": 1}}, [rule(0, "/x", "sha256")], salt=salt)
    assert r1["x"] == r2["x"]


def test_empty_rules_return_deep_copy():
    data = {"a": [1, 2]}
    out, audit = redact(data, [])
    assert out == data
    assert out is not data
    assert audit == []


# --------------------------------------------------------------------------- #
# Glob semantics
# --------------------------------------------------------------------------- #


def test_single_star_matches_exactly_one_level():
    data = {"users": {"alice": {"email": "a@x"}, "bob": {"email": "b@x"}}}
    out, audit = redact(data, [rule(0, "/users/*/email", "mask")])
    assert out["users"]["alice"]["email"] == MASK_VALUE
    assert out["users"]["bob"]["email"] == MASK_VALUE
    assert {e["pointer"] for e in audit} == {"/users/alice/email", "/users/bob/email"}


def test_single_star_does_not_cross_levels():
    data = {"email": "x@y", "users": {"alice": {"email": "z"}}}
    out, _ = redact(data, [rule(0, "/*/email", "mask")])
    assert out["email"] == "x@y"  # two levels needed, star gives exactly one
    assert out["users"]["alice"]["email"] == "z"  # too deep


def test_globstar_matches_any_depth():
    data = {"a": {"b": {"ssn": "1", "c": {"ssn": "2"}}, "ssn": "3"}}
    out, audit = redact(data, [rule(0, "/**/ssn", "remove")])
    assert out == {"a": {"b": {"c": {}}}}
    assert len(audit) == 3


def test_globstar_matches_zero_segments():
    data = {"ssn": "1", "x": {"ssn": "2"}}
    out, audit = redact(data, [rule(0, "/**/ssn", "mask")])
    assert out["ssn"] == MASK_VALUE
    assert out["x"]["ssn"] == MASK_VALUE
    assert {e["pointer"] for e in audit} == {"/ssn", "/x/ssn"}


def test_trailing_globstar_redacts_whole_subtree():
    data = {"keep": 1, "drop": {"a": {"b": 2}}}
    out, audit = redact(data, [rule(0, "/drop/**", "remove")])
    assert out == {"keep": 1}
    # Root of the subtree owns the action; descendants are not re-audited.
    assert [e["pointer"] for e in audit] == ["/drop"]


def test_star_matches_array_indices():
    data = {"items": [{"v": 1}, {"v": 2}]}
    out, _ = redact(data, [rule(0, "/items/*/v", "mask")])
    assert all(i["v"] == MASK_VALUE for i in out["items"])


# --------------------------------------------------------------------------- #
# Rule precedence
# --------------------------------------------------------------------------- #


def test_more_literal_segments_win_over_globstar():
    data = {"users": {"alice": {"email": "a"}}, "email": "b"}
    rules = [
        rule(0, "/**/email", "remove"),
        rule(1, "/users/alice/email", "mask"),
    ]
    out, audit = redact(data, rules)
    assert out["users"]["alice"]["email"] == MASK_VALUE  # literal beats **
    assert "email" not in out  # only the glob rule hits root-level email
    by_pointer = {e["pointer"]: e for e in audit}
    assert by_pointer["/users/alice/email"]["rule"]["index"] == 1
    assert by_pointer["/email"]["rule"]["index"] == 0


def test_fewer_wildcard_segments_win():
    data = {"users": {"alice": {"email": "x"}}}
    rules = [
        rule(0, "/**/*/email", "remove"),     # 2 wildcards
        rule(1, "/users/*/email", "mask"),    # 1 wildcard
    ]
    out, audit = redact(data, rules)
    assert out["users"]["alice"]["email"] == MASK_VALUE
    assert audit[0]["rule"]["index"] == 1


def test_exact_tie_later_declaration_wins():
    data = {"k": "v"}
    rules = [rule(0, "/k", "mask"), rule(1, "/k", "remove")]
    out, audit = redact(data, rules)
    assert out == {}
    assert audit[0]["rule"]["index"] == 1
    assert audit[0]["action"] == "remove"


def test_wildcard_tie_later_declaration_wins():
    data = {"users": {"alice": {"email": "x"}}}
    rules = [
        rule(0, "/users/*/email", "mask"),
        rule(1, "/users/*/email", "sha256"),
    ]
    out, audit = redact(data, rules)
    assert isinstance(out["users"]["alice"]["email"], str)
    assert len(out["users"]["alice"]["email"]) == 64
    assert audit[0]["rule"]["index"] == 1


def test_winner_for_all_nodes_precedence_order():
    # literal count beats declaration order even when the literal rule is first
    data = {"a": {"b": "x"}}
    rules = [rule(0, "/a/b", "remove"), rule(1, "/**", "mask")]
    out, audit = redact(data, rules)
    # "/**" matches the root and owns the whole document (zero-width),
    # so it applies to root before /a/b is ever reached.
    assert out == MASK_VALUE
    assert [e["pointer"] for e in audit] == [""]


# --------------------------------------------------------------------------- #
# Arrays & deletion stability
# --------------------------------------------------------------------------- #


def test_array_removal_uses_original_indices():
    data = {"items": ["a", "b", "c", "d"]}
    rules = [
        rule(0, "/items/1", "remove"),
        rule(1, "/items/2", "remove"),
    ]
    out, audit = redact(data, rules)
    assert out == {"items": ["a", "d"]}
    assert {e["pointer"] for e in audit} == {"/items/1", "/items/2"}


def test_array_rule_then_index_rule_no_misalignment():
    # Remove by original index 2 while masking every element: surviving
    # elements must correspond to original indices, never shifted ones.
    data = {"items": [0, 10, 20, 30]}
    rules = [
        rule(0, "/items/*", "mask"),
        rule(1, "/items/2", "remove"),  # literal beats * for index 2
    ]
    out, audit = redact(data, rules)
    assert out == {"items": [MASK_VALUE, MASK_VALUE, MASK_VALUE]}
    by_pointer = {e["pointer"]: e for e in audit}
    assert by_pointer["/items/2"]["action"] == "remove"
    assert by_pointer["/items/0"]["action"] == "mask"


def test_nested_array_removal_keeps_later_pointers_valid():
    data = {"rows": [{"id": 0, "secret": "s0"}, {"id": 1, "secret": "s1"},
                     {"id": 2, "secret": "s2"}]}
    rules = [
        rule(0, "/rows/0", "remove"),
        rule(1, "/rows/*/secret", "mask"),
    ]
    out, audit = redact(data, rules)
    assert [r["id"] for r in out["rows"]] == [1, 2]
    assert all(r["secret"] == MASK_VALUE for r in out["rows"])
    # Audit pointers refer to ORIGINAL positions; /rows/0 was removed but the
    # surviving rows/1 and rows/2 were resolved before any deletion happened.
    assert {e["pointer"] for e in audit} == {
        "/rows/0",
        "/rows/1/secret",
        "/rows/2/secret",
    }


def test_removing_all_array_elements_leaves_empty_list():
    data = {"xs": [1, 2]}
    out, _ = redact(data, [rule(0, "/xs/*", "remove")])
    assert out == {"xs": []}


# --------------------------------------------------------------------------- #
# Root / subtree behavior
# --------------------------------------------------------------------------- #


def test_root_mask_replaces_entire_document():
    data = {"a": [1, 2]}
    out, audit = redact(data, [rule(0, "", "mask")])
    assert out == MASK_VALUE
    assert audit[0]["pointer"] == ""


def test_root_remove_returns_none():
    data = {"a": 1}
    out, audit = redact(data, [rule(0, "", "remove")])
    assert out is None
    assert audit[0]["action"] == "remove"


def test_subtree_mask_suppresses_descendant_audits():
    data = {"card": {"number": "x", "cvv": "y"}, "ok": 1}
    rules = [
        rule(0, "/card/*", "mask"),
        rule(1, "/card", "remove"),
    ]
    out, audit = redact(data, rules)
    assert out == {"ok": 1}
    assert [e["pointer"] for e in audit] == ["/card"]


def test_rule_name_is_echoed():
    data = {"k": "v"}
    out, audit = redact(data, [rule(0, "/k", "mask", name="hide-k")])
    assert audit[0]["rule"]["name"] == "hide-k"


# --------------------------------------------------------------------------- #
# Edge cases
# --------------------------------------------------------------------------- #


def test_slashes_in_keys_use_rfc_escaping():
    data = {"a/b": {"c~d": "v"}}
    out, audit = redact(data, [rule(0, "/a~1b/c~0d", "remove")])
    assert out == {"a/b": {}}
    assert audit[0]["pointer"] == "/a~1b/c~0d"


def test_deep_globstar_performance():
    # Deeply nested chain; a naive backtracking glob could degrade here.
    leaf = "v"
    node = leaf
    for _ in range(200):
        node = {"n": node}
    data = {"top": node}
    out, audit = redact(data, [rule(0, "/top/**/n", "mask")])
    # First "n" below top gets masked, subtree collapses to the mask string.
    assert out == {"top": {"n": MASK_VALUE}}
    assert audit[0]["pointer"] == "/top/n"


def test_scalar_and_null_leaves():
    data = {"s": "hi", "n": None, "b": True, "f": 1.5}
    out, _ = redact(
        data,
        [rule(i, f"/{k}", "mask") for i, k in enumerate(("s", "n", "b", "f"))],
    )
    assert out == {"s": MASK_VALUE, "n": MASK_VALUE, "b": MASK_VALUE, "f": MASK_VALUE}
