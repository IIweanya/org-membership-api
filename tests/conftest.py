"""Shared test fixtures.

We point the app at a TEMPORARY SQLite database (not the real app.db) and recreate
its tables before every test, so tests are isolated and never touch real data.

Important: we set DATABASE_PATH *before* importing the app, because app modules read
config at import time.
"""

import os
import tempfile

import pytest

# Use a dedicated temp DB file for the whole test session.
_TMP_DB = os.path.join(tempfile.gettempdir(), "org_membership_test.db")
os.environ["DATABASE_PATH"] = _TMP_DB

from fastapi.testclient import TestClient  # noqa: E402  (after env var is set)

from app import db  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture
def client():
    db.reset_db()  # clean schema before each test
    with TestClient(app) as c:
        yield c
