"""Persistent, versioned policy library backed by SQLite.

A *policy* is a named, ordered list of redaction rules. Every successful
``PUT /policies/{name}`` appends an **immutable** row to ``policy_versions``
with a monotonically increasing, gap-free per-policy version number; old
versions are never modified or deleted, so any redaction pinned to
``(name, version)`` is reproducible forever.

Concurrency model
-----------------
Updates use optimistic concurrency control via ETags:

* The first PUT for a name must carry **no** ``If-Match`` header and creates
  version 1.
* Every later PUT must carry ``If-Match`` matching the current version's
  ETag. The current version is re-read *inside* the write transaction, so two
  concurrent updaters presenting the same ETag cannot both win: exactly one
  commits a new version, the other gets :class:`PreconditionFailed`.

SQLite is opened in WAL mode with a busy timeout; readers (including the
"read latest" lookup in :func:`get_current`) never block writers.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS policies (
    name           TEXT PRIMARY KEY,
    current_version INTEGER NOT NULL,
    etag           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_versions (
    name        TEXT NOT NULL,
    version     INTEGER NOT NULL,
    rules       TEXT NOT NULL,
    etag        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (name, version),
    FOREIGN KEY (name) REFERENCES policies(name)
);
"""

# Busy retry for SQLITE_BUSY while another writer holds the lock.
_BUSY_RETRIES = 20
_BUSY_WAIT_SECONDS = 0.05

# Sentinel meaning "If-Match: *" -- succeeds iff the policy exists.
ANY = object()


class PolicyNotFound(LookupError):
    """The named policy (or version) does not exist."""


class PreconditionFailed(Exception):
    """The supplied If-Match ETag does not match the current version."""


class ConflictInProgress(Exception):
    """The SQLite database lock could not be acquired."""


# --------------------------------------------------------------------------- #
# Connection management (thread-local, shared across requests)
# --------------------------------------------------------------------------- #

_local = threading.local()
_conns_lock = threading.Lock()
_all_conns: "List[sqlite3.Connection]" = []
_db_path: Optional[str] = None
_epoch = 0


def _connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=5.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Readers never block on a writer; writers still serialise.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _get_conn() -> sqlite3.Connection:
    global _db_path
    if _db_path is None:
        # Lazy default for ad-hoc imports / scripts that skip startup config.
        configure()
    conn = getattr(_local, "conn", None)
    epoch = getattr(_local, "epoch", -1)
    if conn is None or epoch != _epoch:
        conn = _connect(_db_path)
        _local.conn = conn
        _local.epoch = _epoch
        with _conns_lock:
            _all_conns.append(conn)
    return conn


def init_db() -> None:
    """Create the schema if necessary. Safe to call repeatedly."""
    conn = _get_conn()
    conn.executescript(SCHEMA)
    conn.commit()


def configure(path: Optional[str] = None) -> None:
    """(Re)point the store at a specific database file.

    Closes every cached connection (across threads) and bumps an epoch so
    threads lazily reconnect against the new path. Used by tests and startup.
    """
    global _db_path, _epoch
    with _conns_lock:
        for conn in _all_conns:
            conn.close()
        _all_conns.clear()
    _local.conn = None
    _db_path = path or config.get_policy_db_path()
    _epoch += 1
    init_db()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_rules(rules: List[Dict[str, Any]]) -> bytes:
    """Deterministic encoding of a rule list used for ETag derivation."""
    return json.dumps(rules, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )


def compute_etag(name: str, version: int, rules: List[Dict[str, Any]]) -> str:
    """Derive the immutable ETag for one versioned snapshot.

    Includes name and version in the digest so distinct versions always have
    distinct ETags even if their rule bodies are byte-identical.
    """
    digest = hashlib.sha256()
    digest.update(name.encode("utf-8"))
    digest.update(b"\0")
    digest.update(str(version).encode("ascii"))
    digest.update(b"\0")
    digest.update(_canonical_rules(rules))
    # 32 hex chars, quoted per RFC 9110's entity-tag grammar.
    return '"' + digest.hexdigest()[:32] + '"'


def _hydrate(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "name": row["name"],
        "version": row["version"],
        "rules": json.loads(row["rules"]),
        "etag": row["etag"],
        "created_at": row["created_at"],
    }


def _retry_on_busy(fn):
    """Run ``fn`` (one transactional unit), retrying only on SQLITE_BUSY."""
    last_error: Optional[sqlite3.OperationalError] = None
    for attempt in range(_BUSY_RETRIES):
        try:
            return fn()
        except sqlite3.OperationalError as exc:  # pragma: no cover - timing dependent
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                last_error = exc
                time.sleep(_BUSY_WAIT_SECONDS * (attempt + 1))
                continue
            raise
    raise ConflictInProgress(str(last_error))


# --------------------------------------------------------------------------- #
# Public operations
# --------------------------------------------------------------------------- #


def put_policy(
    name: str, rules: List[Dict[str, Any]], if_match: Optional[object]
) -> Tuple[Dict[str, Any], bool]:
    """Create or update a policy under optimistic concurrency control.

    ``if_match`` is ``None`` (create-only), :data:`ANY` (``If-Match: *``),
    or the exact ETag string expected for the current version.

    Returns ``(snapshot, created)``. Raises :class:`PreconditionFailed` when
    the precondition does not hold; the new version is then *not* written.
    """

    def unit() -> Tuple[Dict[str, Any], bool]:
        conn = _get_conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT current_version, etag FROM policies WHERE name = ?",
                (name,),
            ).fetchone()

            if row is None:
                if if_match is not None:
                    # Cannot compare against a version that does not exist.
                    raise PreconditionFailed(f"policy {name!r} does not exist")
                created = True
                version = 1
            else:
                if if_match is None:
                    raise PreconditionFailed(
                        f"policy {name!r} already exists at version {row['current_version']}; "
                        "If-Match with the current ETag is required to update"
                    )
                if if_match is not ANY and row["etag"] not in if_match:
                    raise PreconditionFailed(
                        "If-Match ETag does not match the current version"
                    )
                created = False
                version = row["current_version"] + 1

            etag = compute_etag(name, version, rules)
            created_at = _utc_now()
            payload = json.dumps(rules, ensure_ascii=False)

            if created:
                # Parent row first: policy_versions(name) references policies.
                conn.execute(
                    "INSERT INTO policies (name, current_version, etag) VALUES (?, ?, ?)",
                    (name, version, etag),
                )
            conn.execute(
                "INSERT INTO policy_versions (name, version, rules, etag, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (name, version, payload, etag, created_at),
            )
            if not created:
                conn.execute(
                    "UPDATE policies SET current_version = ?, etag = ? WHERE name = ?",
                    (version, etag, name),
                )
            conn.commit()
        except BaseException:
            conn.rollback()
            raise

        return (
            {
                "name": name,
                "version": version,
                "rules": rules,
                "etag": etag,
                "created_at": created_at,
            },
            created,
        )

    return _retry_on_busy(unit)


def get_version(name: str, version: int) -> Dict[str, Any]:
    """Return an immutable snapshot (404 mapping is the caller's job)."""
    row = _get_conn().execute(
        "SELECT name, version, rules, etag, created_at "
        "FROM policy_versions WHERE name = ? AND version = ?",
        (name, version),
    ).fetchone()
    if row is None:
        raise PolicyNotFound(f"policy {name!r} version {version} not found")
    return _hydrate(row)


def get_current(name: str) -> Dict[str, Any]:
    """Atomically read the newest committed snapshot of a policy.

    The join resolves ``current_version`` and its body in a single statement,
    so a concurrent PUT committing between two queries can never be observed
    half-way: callers either see version N entirely or N+1 entirely.
    """
    row = _get_conn().execute(
        "SELECT v.name AS name, v.version AS version, v.rules AS rules, "
        "v.etag AS etag, v.created_at AS created_at "
        "FROM policies p JOIN policy_versions v "
        "ON v.name = p.name AND v.version = p.current_version WHERE p.name = ?",
        (name,),
    ).fetchone()
    if row is None:
        raise PolicyNotFound(f"policy {name!r} not found")
    return _hydrate(row)
