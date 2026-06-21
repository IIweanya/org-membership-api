"""Integration tests for the organization membership API.

These drive the real app through HTTP (via TestClient) exactly as a client would.
The headline test, `test_full_invite_lifecycle`, walks the entire flow:

    create org  ->  invite  ->  accept  ->  list members

The remaining tests prove the three required rules:
    * token validity   (bad/missing tokens are rejected)
    * role constraints  (members cannot invite)
    * tenant isolation  (one org never sees another's data)
plus single-use invites.
"""

import datetime

import jwt

from app import config


# ---- small helpers -------------------------------------------------------

def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def create_org(client, org_name="Acme", admin_email="admin@acme.com"):
    """Create an org and return its JSON body (includes admin access_token)."""
    resp = client.post(
        "/orgs", json={"org_name": org_name, "admin_email": admin_email}
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---- the headline lifecycle test ----------------------------------------

def test_full_invite_lifecycle(client):
    # 1. Create an org -> we get back an admin auth token.
    org = create_org(client)
    admin_token = org["access_token"]

    # 2. Admin invites a new person -> we get an invite token.
    invite_resp = client.post(
        "/invites",
        json={"email": "bob@acme.com", "role": "member"},
        headers=auth_header(admin_token),
    )
    assert invite_resp.status_code == 201, invite_resp.text
    invite_token = invite_resp.json()["invite_token"]

    # 3. The invitee accepts -> becomes a member, gets their own auth token.
    accept_resp = client.post(
        "/invites/accept", json={"invite_token": invite_token}
    )
    assert accept_resp.status_code == 201, accept_resp.text
    member_token = accept_resp.json()["access_token"]
    assert accept_resp.json()["org_id"] == org["org_id"]  # same tenant

    # 4. The new member lists members and sees BOTH people.
    members_resp = client.get("/members", headers=auth_header(member_token))
    assert members_resp.status_code == 200, members_resp.text
    emails = {m["email"] for m in members_resp.json()["members"]}
    assert emails == {"admin@acme.com", "bob@acme.com"}


# ---- token validity ------------------------------------------------------

def test_members_requires_token(client):
    resp = client.get("/members")  # no Authorization header
    assert resp.status_code == 401


def test_members_rejects_garbage_token(client):
    resp = client.get("/members", headers=auth_header("not-a-real-token"))
    assert resp.status_code == 401


def test_members_rejects_expired_token(client):
    org = create_org(client)
    # Forge a token that is correctly signed but already expired.
    expired = jwt.encode(
        {
            "type": "auth",
            "user_id": org["user_id"],
            "org_id": org["org_id"],
            "role": "admin",
            "exp": datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(minutes=5),
        },
        config.SECRET_KEY,
        algorithm=config.ALGORITHM,
    )
    resp = client.get("/members", headers=auth_header(expired))
    assert resp.status_code == 401


def test_invite_token_cannot_be_used_as_login(client):
    org = create_org(client)
    invite_token = client.post(
        "/invites",
        json={"email": "bob@acme.com", "role": "member"},
        headers=auth_header(org["access_token"]),
    ).json()["invite_token"]

    # An invite token is the wrong type for /members -> 401.
    resp = client.get("/members", headers=auth_header(invite_token))
    assert resp.status_code == 401


# ---- role constraints ----------------------------------------------------

def test_member_cannot_create_invite(client):
    org = create_org(client)
    # Add a plain member via the invite flow.
    invite_token = client.post(
        "/invites",
        json={"email": "bob@acme.com", "role": "member"},
        headers=auth_header(org["access_token"]),
    ).json()["invite_token"]
    member_token = client.post(
        "/invites/accept", json={"invite_token": invite_token}
    ).json()["access_token"]

    # That member tries to invite someone -> forbidden.
    resp = client.post(
        "/invites",
        json={"email": "carol@acme.com", "role": "member"},
        headers=auth_header(member_token),
    )
    assert resp.status_code == 403


# ---- tenant isolation ----------------------------------------------------

def test_orgs_are_isolated(client):
    org_a = create_org(client, org_name="Org A", admin_email="a@a.com")
    org_b = create_org(client, org_name="Org B", admin_email="b@b.com")

    # Org A's admin lists members -> sees only Org A.
    resp = client.get("/members", headers=auth_header(org_a["access_token"]))
    emails = {m["email"] for m in resp.json()["members"]}
    assert emails == {"a@a.com"}
    assert "b@b.com" not in emails

    # And the org_id returned matches the caller's org, not B's.
    assert resp.json()["org_id"] == org_a["org_id"]
    assert resp.json()["org_id"] != org_b["org_id"]


# ---- single-use invites --------------------------------------------------

def test_invite_cannot_be_accepted_twice(client):
    org = create_org(client)
    invite_token = client.post(
        "/invites",
        json={"email": "bob@acme.com", "role": "member"},
        headers=auth_header(org["access_token"]),
    ).json()["invite_token"]

    first = client.post("/invites/accept", json={"invite_token": invite_token})
    assert first.status_code == 201

    second = client.post("/invites/accept", json={"invite_token": invite_token})
    assert second.status_code == 400  # already used
