"""Shared test fixtures.

`client` gives each test a fresh FastAPI TestClient AND wipes the in-memory store
first, so tests never leak data into each other.
"""

import pytest
from fastapi.testclient import TestClient

from app import store
from app.main import app


@pytest.fixture
def client():
    store.reset()  # clean slate before every test
    with TestClient(app) as c:
        yield c
