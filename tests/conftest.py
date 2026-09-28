"""Shared pytest fixtures: point the policy store at a temp SQLite file."""

from __future__ import annotations

import pytest

from app import policy_store


@pytest.fixture(autouse=True)
def isolated_policy_db(tmp_path):
    """Each test gets a fresh on-disk policy database."""
    db_path = tmp_path / "policies.db"
    policy_store.configure(str(db_path))
    yield db_path
