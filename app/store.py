"""Data-access layer — every read/write of persistent data goes through here.

This is the ONLY module that talks to the database (see db.py). Routes call these
functions and receive plain dicts, so the rest of the app never deals with SQL. If
you later switch to Postgres, this is the only file that changes.
"""

import datetime
import sqlite3
import uuid

from .db import get_connection


def _new_id(prefix: str) -> str:
    """Generate a short unique id like 'org_a1b2c3d4'."""
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def _now() -> str:
    """Current UTC time as an ISO-8601 string (SQLite stores text)."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _row_to_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None


# ---- users ---------------------------------------------------------------

def create_user(name: str, email: str, password_hash: str, salt: str) -> dict:
    user = {
        "id": _new_id("user"),
        "name": name,
        "email": email,
        "password_hash": password_hash,
        "salt": salt,
        "created_at": _now(),
    }
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO users (id, name, email, password_hash, salt, created_at) "
            "VALUES (:id, :name, :email, :password_hash, :salt, :created_at)",
            user,
        )
    return user


def get_user(user_id: str) -> dict | None:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return _row_to_dict(row)


def get_user_by_email(email: str) -> dict | None:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    return _row_to_dict(row)


def update_user_password(user_id: str, password_hash: str, salt: str) -> None:
    """Overwrite a user's stored password hash + salt (used by password reset)."""
    with get_connection() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
            (password_hash, salt, user_id),
        )


# ---- orgs ----------------------------------------------------------------

def create_org(name: str, description: str, created_by: str) -> dict:
    org = {
        "id": _new_id("org"),
        "name": name,
        "description": description,
        "created_by": created_by,
        "created_at": _now(),
    }
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO orgs (id, name, description, created_by, created_at) "
            "VALUES (:id, :name, :description, :created_by, :created_at)",
            org,
        )
    return org


def get_org(org_id: str) -> dict | None:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM orgs WHERE id = ?", (org_id,)).fetchone()
    return _row_to_dict(row)


def list_orgs(search: str | None = None) -> list[dict]:
    """All orgs, optionally filtered by a case-insensitive name substring.

    This powers the public "browse / search companies" feature.
    """
    with get_connection() as conn:
        if search:
            rows = conn.execute(
                "SELECT * FROM orgs WHERE name LIKE ? ORDER BY name",
                (f"%{search}%",),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM orgs ORDER BY name").fetchall()
    return [dict(r) for r in rows]


# ---- memberships ---------------------------------------------------------

def create_membership(user_id: str, org_id: str, role: str) -> dict:
    membership = {
        "id": _new_id("mem"),
        "user_id": user_id,
        "org_id": org_id,
        "role": role,
        "created_at": _now(),
    }
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO memberships (id, user_id, org_id, role, created_at) "
            "VALUES (:id, :user_id, :org_id, :role, :created_at)",
            membership,
        )
    return membership


def get_membership(user_id: str, org_id: str) -> dict | None:
    """The one membership linking a user to an org, or None. This is how we answer
    'is this person a member?' and 'what is their role here?' — the basis of role
    constraints and tenant isolation."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM memberships WHERE user_id = ? AND org_id = ?",
            (user_id, org_id),
        ).fetchone()
    return _row_to_dict(row)


def list_memberships_for_user(user_id: str) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM memberships WHERE user_id = ?", (user_id,)
        ).fetchall()
    return [dict(r) for r in rows]


def list_members(org_id: str) -> list[dict]:
    """All members of an org, joined with their user details. Tenant isolation:
    callers only ever pass their OWN org_id (enforced by the route dependency)."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT u.id AS id, u.name AS name, u.email AS email, m.role AS role "
            "FROM memberships m JOIN users u ON u.id = m.user_id "
            "WHERE m.org_id = ? ORDER BY u.name",
            (org_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def list_admin_emails(org_id: str) -> list[str]:
    """Email addresses of every admin of an org — used to notify them of join requests."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT u.email AS email FROM memberships m "
            "JOIN users u ON u.id = m.user_id "
            "WHERE m.org_id = ? AND m.role = 'admin'",
            (org_id,),
        ).fetchall()
    return [r["email"] for r in rows]


def set_membership_role(user_id: str, org_id: str, role: str) -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE memberships SET role = ? WHERE user_id = ? AND org_id = ?",
            (role, user_id, org_id),
        )


def delete_membership(user_id: str, org_id: str) -> None:
    with get_connection() as conn:
        conn.execute(
            "DELETE FROM memberships WHERE user_id = ? AND org_id = ?",
            (user_id, org_id),
        )


def count_admins(org_id: str) -> int:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM memberships WHERE org_id = ? AND role = 'admin'",
            (org_id,),
        ).fetchone()
    return row["n"]


# ---- join requests -------------------------------------------------------

def create_join_request(user_id: str, org_id: str) -> dict:
    req = {
        "id": _new_id("jr"),
        "user_id": user_id,
        "org_id": org_id,
        "status": "pending",
        "created_at": _now(),
    }
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO join_requests (id, user_id, org_id, status, created_at) "
            "VALUES (:id, :user_id, :org_id, :status, :created_at)",
            req,
        )
    return req


def get_join_request(req_id: str) -> dict | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM join_requests WHERE id = ?", (req_id,)
        ).fetchone()
    return _row_to_dict(row)


def get_pending_join_request(user_id: str, org_id: str) -> dict | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM join_requests "
            "WHERE user_id = ? AND org_id = ? AND status = 'pending'",
            (user_id, org_id),
        ).fetchone()
    return _row_to_dict(row)


def list_join_requests(org_id: str, status: str | None = "pending") -> list[dict]:
    """Requests for an org. Default to pending — that's the admin's 'inbox'."""
    with get_connection() as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM join_requests WHERE org_id = ? AND status = ? "
                "ORDER BY created_at",
                (org_id, status),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM join_requests WHERE org_id = ? ORDER BY created_at",
                (org_id,),
            ).fetchall()
    return [dict(r) for r in rows]


def set_join_request_status(req_id: str, status: str) -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE join_requests SET status = ? WHERE id = ?", (status, req_id)
        )


# ---- invites -------------------------------------------------------------

def create_invite(
    jti: str, user_id: str, org_id: str, role: str, join_request_id: str | None
) -> dict:
    invite = {
        "jti": jti,
        "user_id": user_id,
        "org_id": org_id,
        "role": role,
        "accepted": 0,
        "join_request_id": join_request_id,
        "created_at": _now(),
    }
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO invites "
            "(jti, user_id, org_id, role, accepted, join_request_id, created_at) "
            "VALUES (:jti, :user_id, :org_id, :role, :accepted, :join_request_id, "
            ":created_at)",
            invite,
        )
    return invite


def get_invite(jti: str) -> dict | None:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM invites WHERE jti = ?", (jti,)).fetchone()
    return _row_to_dict(row)


def mark_invite_accepted(jti: str) -> None:
    with get_connection() as conn:
        conn.execute("UPDATE invites SET accepted = 1 WHERE jti = ?", (jti,))


# ---- password resets -----------------------------------------------------

def create_password_reset(jti: str, user_id: str) -> dict:
    reset = {"jti": jti, "user_id": user_id, "used": 0, "created_at": _now()}
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO password_resets (jti, user_id, used, created_at) "
            "VALUES (:jti, :user_id, :used, :created_at)",
            reset,
        )
    return reset


def get_password_reset(jti: str) -> dict | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM password_resets WHERE jti = ?", (jti,)
        ).fetchone()
    return _row_to_dict(row)


def mark_password_reset_used(jti: str) -> None:
    with get_connection() as conn:
        conn.execute("UPDATE password_resets SET used = 1 WHERE jti = ?", (jti,))
