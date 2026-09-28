"""Core JSON redaction engine.

Rule paths follow JSON Pointer (RFC 6901) with two glob extensions:

* ``*``  -- matches exactly one segment (any key or array index).
* ``**`` -- matches zero or more segments at any depth.

All matching is performed against the original (unmodified) document.
Rules never interfere with each other's candidate sets; conflict resolution
only decides which single rule applies to a given node.

When several rules match the same node, the winner is selected by, in order:

1. more literal segments win,
2. then fewer wildcard segments (``*`` / ``**``) win,
3. then the rule declared later wins.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Tuple

MASK_VALUE = "***REDACTED***"

# Sentinel marking a subtree for removal while walking a copied document.
_REMOVE = object()

# A path is a tuple of raw object keys / array index strings.
Path = Tuple[str, ...]


class InvalidPointer(ValueError):
    """Raised when a rule path is not a syntactically valid JSON Pointer."""


# --------------------------------------------------------------------------- #
# Rule representation
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CompiledRule:
    index: int
    pointer: str
    action: str
    segments: Tuple[str, ...]
    name: str | None = None

    @property
    def literal_count(self) -> int:
        return sum(1 for seg in self.segments if seg not in ("*", "**"))

    @property
    def wildcard_count(self) -> int:
        return sum(1 for seg in self.segments if seg in ("*", "**"))


def compile_rule(index: int, pointer: str, action: str, name: str | None = None) -> CompiledRule:
    segments = parse_pointer(pointer)
    return CompiledRule(
        index=index,
        pointer=pointer,
        action=action,
        segments=tuple(segments),
        name=name,
    )


# --------------------------------------------------------------------------- #
# JSON Pointer parsing / rendering (RFC 6901)
# --------------------------------------------------------------------------- #


def parse_pointer(pointer: str) -> List[str]:
    """Parse a JSON Pointer string into its reference tokens.

    ``""`` denotes the whole document and parses to zero segments.
    ``~1`` unescapes to ``/`` and ``~0`` unescapes to ``~``.
    """
    if not isinstance(pointer, str):
        raise InvalidPointer("JSON Pointer must be a string")
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise InvalidPointer(
            f"invalid JSON Pointer {pointer!r}: non-empty pointer must start with '/'"
        )
    tokens: List[str] = []
    for raw in pointer.split("/")[1:]:
        if "~" in raw:
            decoded = raw.replace("~1", "/").replace("~0", "~")
        else:
            decoded = raw
        tokens.append(decoded)
    return tokens


def to_pointer(path: Path) -> str:
    """Render a path tuple back into an RFC 6901 JSON Pointer."""
    if not path:
        return ""
    return "".join("/" + seg.replace("~", "~0").replace("/", "~1") for seg in path)


# --------------------------------------------------------------------------- #
# Glob matching
# --------------------------------------------------------------------------- #


def matches(segments: Tuple[str, ...], path: Path) -> bool:
    """Match compiled rule segments against a concrete node path.

    ``*`` consumes exactly one segment; ``**`` consumes zero or more.
    """
    n, m = len(segments), len(path)
    # reachable[i][j]: first i pattern segments match first j path segments
    reachable = [[False] * (m + 1) for _ in range(n + 1)]
    reachable[0][0] = True
    for i in range(1, n + 1):
        token = segments[i - 1]
        for j in range(m + 1):
            if token == "**":
                # zero-width match, or consume one more path segment
                reachable[i][j] = reachable[i - 1][j] or (j > 0 and reachable[i][j - 1])
            elif j > 0 and (token == "*" or token == path[j - 1]):
                reachable[i][j] = reachable[i - 1][j - 1]
    return reachable[n][m]


# --------------------------------------------------------------------------- #
# Traversal of the ORIGINAL document
# --------------------------------------------------------------------------- #


def iter_nodes(value: Any, path: Path = ()) -> Iterator[Tuple[Path, Any]]:
    """Yield ``(path, value)`` for every node, depth-first, parent first."""
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from iter_nodes(child, path + (str(key),))
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            yield from iter_nodes(child, path + (str(idx),))


# --------------------------------------------------------------------------- #
# Rule resolution
# --------------------------------------------------------------------------- #


def _rank(rule: CompiledRule) -> Tuple[int, int, int]:
    # max() picks the winner: more literals, fewer wildcards, later declaration.
    return (rule.literal_count, -rule.wildcard_count, rule.index)


def build_hits(data: Any, rules: List[CompiledRule]) -> Dict[Path, CompiledRule]:
    """Map every original-document path to its unique winning rule."""
    hits: Dict[Path, CompiledRule] = {}
    for path, _value in iter_nodes(data):
        winner: CompiledRule | None = None
        for rule in rules:
            if matches(rule.segments, path):
                if winner is None or _rank(rule) > _rank(winner):
                    winner = rule
        if winner is not None:
            hits[path] = winner
    return hits


# --------------------------------------------------------------------------- #
# Actions
# --------------------------------------------------------------------------- #


def canonical_json(value: Any) -> str:
    """Deterministic JSON encoding used as hash input."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def sha256_value(value: Any, salt: str) -> str:
    digest = hashlib.sha256()
    digest.update(salt.encode("utf-8"))
    digest.update(canonical_json(value).encode("utf-8"))
    return digest.hexdigest()


# --------------------------------------------------------------------------- #
# Application
# --------------------------------------------------------------------------- #


def _rule_ref(rule: CompiledRule) -> Dict[str, Any]:
    return {
        "index": rule.index,
        "pointer": rule.pointer,
        "action": rule.action,
        **({"name": rule.name} if rule.name is not None else {}),
    }


def _audit_entry(path: Path, rule: CompiledRule, action: str) -> Dict[str, Any]:
    return {
        "pointer": to_pointer(path),
        "action": action,
        "rule": _rule_ref(rule),
    }


def redact(
    data: Any,
    rules: List[CompiledRule],
    salt: str = "",
) -> Tuple[Any, List[Dict[str, Any]]]:
    """Return ``(redacted_value, audit_trail)`` for the given rules.

    The input value is never mutated; a deep copy is produced implicitly by
    rebuilding every container during the walk.
    """
    hits = build_hits(data, rules)
    audit: List[Dict[str, Any]] = []
    result = _apply(data, (), hits, salt, audit)
    if result is _REMOVE:
        # Removing the document root leaves nothing to return.
        return None, audit
    return result, audit


def _apply(
    value: Any,
    path: Path,
    hits: Dict[Path, CompiledRule],
    salt: str,
    audit: List[Dict[str, Any]],
) -> Any:
    rule = hits.get(path)
    if rule is not None:
        # The nearest matched ancestor owns the whole subtree; descendants
        # that also matched are intentionally not re-processed.
        audit.append(_audit_entry(path, rule, rule.action))
        if rule.action == "remove":
            return _REMOVE
        if rule.action == "mask":
            return MASK_VALUE
        if rule.action == "sha256":
            return sha256_value(value, salt)
        raise ValueError(f"unknown action: {rule.action!r}")

    if isinstance(value, dict):
        return {
            key: applied
            for key, child in value.items()
            if (
                (
                    applied := _apply(
                        child, path + (str(key),), hits, salt, audit
                    )
                )
                is not _REMOVE
            )
        }

    if isinstance(value, list):
        # Rebuild the list by walking every ORIGINAL index. Filtering out
        # elements afterwards means deletions can never shift later
        # pointers -- all matching happened up front on the original list.
        out: List[Any] = []
        for idx, child in enumerate(value):
            applied = _apply(child, path + (str(idx),), hits, salt, audit)
            if applied is not _REMOVE:
                out.append(applied)
        return out

    return value
