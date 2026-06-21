"""A tiny in-memory data store.

This stands in for a database. Everything lives in plain Python dicts, so data
resets every time the process restarts. That is exactly what we want for an
assignment and for tests (each test starts from a clean slate).

The store is deliberately the ONLY module that knows how data is persisted. If you
later swap in a real database (SQLite, Postgres), you would only rewrite this file
and the route code would not have to change.
"""

import uuid

# Each dict maps an id -> a record (also a dict).
orgs: dict[str, dict] = {}
users: dict[str, dict] = {}
invites: dict[str, dict] = {}


def _new_id(prefix: str) -> str:
    """Generate a short unique id like 'org_a1b2c3d4'."""
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def reset() -> None:
    """Wipe all data. Used by tests between runs."""
    orgs.clear()
    users.clear()
    invites.clear()


def create_org(name: str) -> dict:
    org = {"id": _new_id("org"), "name": name}
    orgs[org["id"]] = org
    return org


def create_user(email: str, org_id: str, role: str) -> dict:
    user = {
        "id": _new_id("user"),
        "email": email,
        "org_id": org_id,
        "role": role,
    }
    users[user["id"]] = user
    return user


def get_user(user_id: str) -> dict | None:
    return users.get(user_id)


def find_user_by_email_in_org(email: str, org_id: str) -> dict | None:
    """Used to stop the same email being added to one org twice."""
    for user in users.values():
        if user["email"] == email and user["org_id"] == org_id:
            return user
    return None


def list_members(org_id: str) -> list[dict]:
    """All users belonging to a single org. This is where tenant isolation lives:
    we only ever return users whose org_id matches."""
    return [u for u in users.values() if u["org_id"] == org_id]


def create_invite(jti: str, email: str, org_id: str, role: str) -> dict:
    """Record an invite so we can mark it 'accepted' later and prevent reuse.

    `jti` is the invite token's unique id (a claim inside the JWT). We key invites
    by it so accepting an invite is a single lookup.
    """
    invite = {
        "jti": jti,
        "email": email,
        "org_id": org_id,
        "role": role,
        "accepted": False,
    }
    invites[jti] = invite
    return invite


def get_invite(jti: str) -> dict | None:
    return invites.get(jti)
