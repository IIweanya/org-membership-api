"""SQLite database connection + schema.

This is the persistence foundation that makes "your info is still there next time
you log in" possible: SQLite writes everything to a single file on disk, so data
survives server restarts. SQLite ships with Python — there is nothing to install.

We expose a single `get_connection()` helper that every other module uses, plus
`init_db()` to create the tables and `reset_db()` for tests.
"""

import sqlite3

from . import config

# The SQL that defines our tables. Run once at startup; "IF NOT EXISTS" makes it safe
# to run every time.
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt          TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS orgs (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

-- A membership links one user to one org with a role. A user can have many
-- memberships (many orgs); this is the heart of multi-org support.
CREATE TABLE IF NOT EXISTS memberships (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    org_id     TEXT NOT NULL,
    role       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (user_id, org_id)
);

-- A pending/accepted/rejected request from a user to join an org.
CREATE TABLE IF NOT EXISTS join_requests (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    org_id     TEXT NOT NULL,
    status     TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- An invite token the admin issued when accepting a join request. Single-use:
-- once accepted=1 it cannot be redeemed again.
CREATE TABLE IF NOT EXISTS invites (
    jti             TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    org_id          TEXT NOT NULL,
    role            TEXT NOT NULL,
    accepted        INTEGER NOT NULL DEFAULT 0,
    join_request_id TEXT,
    created_at      TEXT NOT NULL
);

-- A password-reset token's id. Single-use: once used=1 it can't reset again.
CREATE TABLE IF NOT EXISTS password_resets (
    jti        TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
"""


def get_connection() -> sqlite3.Connection:
    """Open a connection to the configured database.

    `row_factory = sqlite3.Row` lets us read columns by name (row["email"]) and
    convert rows to plain dicts easily.
    """
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    # Enforce foreign-key-style integrity and sane defaults.
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    """Create tables if they do not already exist."""
    with get_connection() as conn:
        conn.executescript(SCHEMA)


def reset_db() -> None:
    """Drop and recreate every table. Used by tests for a clean slate."""
    with get_connection() as conn:
        for table in (
            "password_resets", "invites", "join_requests", "memberships", "orgs", "users"
        ):
            conn.execute(f"DROP TABLE IF EXISTS {table}")
        conn.executescript(SCHEMA)
