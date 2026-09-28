"""Candidate-policy impact preview.

Runs the same sample through two rule sets (the currently committed policy
and a candidate rule list) and diffs the two **audit trails** the engine
emits. Because every audit entry is produced by the effective (short-circuit)
walk over the *original* document, comparing the two audits automatically:

* honours subtree short-circuiting -- when a parent node is mask/remove/
  sha256'ed, none of its descendants appear in the audit, so adding or
  removing a rule that only lands inside a shadowed subtree shows no impact;
* keeps array indices stable -- audit pointers always name ORIGINAL positions,
  so deleting elements in one rule set can never shift the compared paths.

An entry keyed by the same original JSON Pointer:

* present only under the candidate rules -> ``added``
* present only under the current rules   -> ``removed``
* present under both but with a different effective ``action`` -> ``changed``

The winning rule itself differing while the effective action stays the same
(e.g. two ``mask`` rules) is *not* reported: the externally visible effect on
the document is unchanged.
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence

from .redaction import CompiledRule, redact

AuditEntry = Dict[str, Any]
AuditList = List[AuditEntry]


def _rule_view(entry: AuditEntry) -> Dict[str, Any]:
    """The engine's rule ref, dropping the injected ``policy`` stamp if any."""
    rule = dict(entry["rule"])
    return rule


def diff_audits(current_audit: AuditList, candidate_audit: AuditList) -> Dict[str, AuditList]:
    """Classify effective-action differences between two audit trails.

    Each side maps one original JSON Pointer to exactly one audit entry (the
    walk visits every original node once). Order follows depth-first
    traversal of the original document -- for ``added`` that is the
    candidate's order, for ``removed``/``changed`` the current order.
    """
    current_by_pointer = {entry["pointer"]: entry for entry in current_audit}
    candidate_by_pointer = {entry["pointer"]: entry for entry in candidate_audit}

    added: AuditList = []
    removed: AuditList = []
    changed: AuditList = []

    for entry in candidate_audit:
        pointer = entry["pointer"]
        old = current_by_pointer.get(pointer)
        if old is None:
            added.append(
                {
                    "pointer": pointer,
                    "action": entry["action"],
                    "rule": _rule_view(entry),
                }
            )
        elif old["action"] != entry["action"]:
            changed.append(
                {
                    "pointer": pointer,
                    "before": {"action": old["action"], "rule": _rule_view(old)},
                    "after": {"action": entry["action"], "rule": _rule_view(entry)},
                }
            )

    for entry in current_audit:
        pointer = entry["pointer"]
        new = candidate_by_pointer.get(pointer)
        if new is None:
            removed.append(
                {
                    "pointer": pointer,
                    "action": entry["action"],
                    "rule": _rule_view(entry),
                }
            )

    return {"added": added, "removed": removed, "changed": changed}


def _counts(diff: Dict[str, AuditList]) -> Dict[str, int]:
    return {key: len(diff[key]) for key in ("added", "removed", "changed")}


def preview_sample_impact(
    sample: Any,
    current_rules: Sequence[CompiledRule],
    candidate_rules: Sequence[CompiledRule],
    salt: str = "",
) -> Dict[str, Any]:
    """Apply both rule sets to one sample and return its impact report."""
    # Two independent walks over the same, never-mutated, original sample.
    _current_result, current_audit = redact(sample, list(current_rules), salt=salt)
    _candidate_result, candidate_audit = redact(sample, list(candidate_rules), salt=salt)
    diff = diff_audits(current_audit, candidate_audit)
    counts = _counts(diff)
    return {
        "diff": diff,
        "counts": counts,
        "has_changes": any(counts.values()),
    }


def preview_impact(
    samples: Sequence[Any],
    current_rules: Sequence[CompiledRule],
    candidate_rules: Sequence[CompiledRule],
    salt: str = "",
) -> Dict[str, Any]:
    """Run :func:`preview_sample_impact` for every sample and aggregate."""
    results = [
        preview_sample_impact(sample, current_rules, candidate_rules, salt=salt)
        for sample in samples
    ]
    totals = {"added": 0, "removed": 0, "changed": 0}
    for result in results:
        for key in totals:
            totals[key] += result["counts"][key]
    totals["samples"] = len(results)
    return {"samples": results, "summary": totals}
