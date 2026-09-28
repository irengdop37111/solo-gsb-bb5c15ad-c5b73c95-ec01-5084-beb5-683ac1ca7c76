"""Runtime configuration, sourced from environment variables."""

from __future__ import annotations

import os

# Salt prepended to the canonical JSON of a node before SHA-256 hashing.
REDACT_SALT_ENV = "REDACT_SALT"

# SQLite database holding the versioned policy library.
POLICY_DB_ENV = "POLICY_DB"
DEFAULT_POLICY_DB = "/data/policies.db"


def get_salt() -> str:
    return os.environ.get(REDACT_SALT_ENV, "")


def get_policy_db_path() -> str:
    """Filesystem path of the SQLite policy database.

    Defaults to ``/data/policies.db`` so the path lives on the Docker volume
    mounted at ``/data``; override with ``POLICY_DB`` for local development.
    """
    return os.environ.get(POLICY_DB_ENV, DEFAULT_POLICY_DB)
