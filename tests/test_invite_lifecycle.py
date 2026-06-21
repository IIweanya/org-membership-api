"""Integration tests for the v2 organization membership API.

These drive the real app over HTTP (via TestClient) against a temporary SQLite DB.

`test_full_lifecycle` walks the entire realistic flow:

    register -> login -> create org -> (other user) search -> request to join
    -> admin notified -> admin accepts -> invite token -> accept invite
    -> list members -> promote -> leave

The remaining tests prove the required rules: token validity, role constraints,
tenant isolation, the reject path, single-use invites, and persistence.
"""

import datetime

import jwt

from app import config, db, email, security, store


# ---- helpers -------------------------------------------------------------

def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def register(client, name, email, password="secret123"):
    resp = client.post(
        "/auth/register",
        json={"name": name, "email": email, "password": password},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["access_token"]


def create_org(client, token, name="Acme", description="We make things"):
    resp = client.post(
        "/orgs",
        json={"name": name, "description": description},
        headers=auth_header(token),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def make_member(client, admin_token, org_id, name, email):
    """Helper that runs request -> accept -> accept-invite and returns the new
    member's auth token."""
    joiner_token = register(client, name, email)
    req = client.post(f"/orgs/{org_id}/join-requests", headers=auth_header(joiner_token))
    assert req.status_code == 201, req.text
    req_id = req.json()["id"]
    accept = client.post(
        f"/join-requests/{req_id}/accept", headers=auth_header(admin_token)
    )
    assert accept.status_code == 200, accept.text
    invite_token = accept.json()["invite_token"]
    done = client.post(
        "/invites/accept",
        json={"invite_token": invite_token},
        headers=auth_header(joiner_token),
    )
    assert done.status_code == 201, done.text
    return joiner_token


# ---- the headline lifecycle test ----------------------------------------

def test_full_lifecycle(client):
    # 1. Admin registers and creates an org.
    admin_token = register(client, "Alice Admin", "alice@acme.com")
    org_id = create_org(client, admin_token, name="Acme")

    # 2. A second user registers and finds the org by searching.
    joiner_token = register(client, "Bob Joiner", "bob@example.com")
    search = client.get("/orgs", params={"search": "Acm"})
    assert search.status_code == 200
    assert any(o["id"] == org_id for o in search.json())

    # 3. The user requests to join.
    req = client.post(f"/orgs/{org_id}/join-requests", headers=auth_header(joiner_token))
    assert req.status_code == 201
    req_id = req.json()["id"]

    # 4. The admin is notified (sees the pending request with who is asking).
    inbox = client.get(f"/orgs/{org_id}/join-requests", headers=auth_header(admin_token))
    assert inbox.status_code == 200
    assert [r["user_email"] for r in inbox.json()] == ["bob@example.com"]

    # 5. The admin accepts -> gets an invite token to give to the user.
    accept = client.post(f"/join-requests/{req_id}/accept", headers=auth_header(admin_token))
    assert accept.status_code == 200
    invite_token = accept.json()["invite_token"]

    # 6. The user accepts the invite -> becomes a member.
    done = client.post(
        "/invites/accept",
        json={"invite_token": invite_token},
        headers=auth_header(joiner_token),
    )
    assert done.status_code == 201

    # 7. Members list shows both people.
    members = client.get(f"/orgs/{org_id}/members", headers=auth_header(admin_token))
    assert members.status_code == 200
    emails = {m["email"] for m in members.json()["members"]}
    assert emails == {"alice@acme.com", "bob@example.com"}

    # 8. Admin promotes the new member; the member can now see the admin inbox.
    promote = client.post(
        f"/orgs/{org_id}/members/{done_user_id(client, joiner_token)}/promote",
        headers=auth_header(admin_token),
    )
    assert promote.status_code == 200
    inbox2 = client.get(f"/orgs/{org_id}/join-requests", headers=auth_header(joiner_token))
    assert inbox2.status_code == 200  # promotion took effect on the very next request

    # 9. The member leaves -> no longer listed.
    leave = client.post(f"/orgs/{org_id}/leave", headers=auth_header(joiner_token))
    assert leave.status_code == 200
    members2 = client.get(f"/orgs/{org_id}/members", headers=auth_header(admin_token))
    assert {m["email"] for m in members2.json()["members"]} == {"alice@acme.com"}


def done_user_id(client, token):
    """Look up a user's own id via /auth/me."""
    return client.get("/auth/me", headers=auth_header(token)).json()["id"]


# ---- token validity ------------------------------------------------------

def test_protected_route_requires_token(client):
    admin_token = register(client, "Alice", "alice@acme.com")
    org_id = create_org(client, admin_token)
    resp = client.get(f"/orgs/{org_id}/members")  # no token
    assert resp.status_code == 401


def test_garbage_token_rejected(client):
    admin_token = register(client, "Alice", "alice@acme.com")
    org_id = create_org(client, admin_token)
    resp = client.get(
        f"/orgs/{org_id}/members", headers=auth_header("not-a-real-token")
    )
    assert resp.status_code == 401


def test_expired_token_rejected(client):
    admin_token = register(client, "Alice", "alice@acme.com")
    org_id = create_org(client, admin_token)
    me = client.get("/auth/me", headers=auth_header(admin_token)).json()
    expired = jwt.encode(
        {
            "type": "auth",
            "user_id": me["id"],
            "exp": datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(minutes=5),
        },
        config.SECRET_KEY,
        algorithm=config.ALGORITHM,
    )
    resp = client.get(f"/orgs/{org_id}/members", headers=auth_header(expired))
    assert resp.status_code == 401


def test_login_wrong_password_rejected(client):
    register(client, "Alice", "alice@acme.com", password="correct-horse")
    resp = client.post(
        "/auth/login", json={"email": "alice@acme.com", "password": "wrong"}
    )
    assert resp.status_code == 401


def test_login_returns_working_token(client):
    register(client, "Alice", "alice@acme.com", password="correct-horse")
    login = client.post(
        "/auth/login", json={"email": "alice@acme.com", "password": "correct-horse"}
    )
    assert login.status_code == 200
    token = login.json()["access_token"]
    assert client.get("/auth/me", headers=auth_header(token)).status_code == 200


# ---- password reset ------------------------------------------------------

def _reset_token_from_email(client, user_email):
    """Trigger forgot-password and pull the reset token out of the sent email."""
    email.clear_outbox()
    resp = client.post("/auth/forgot-password", json={"email": user_email})
    assert resp.status_code == 200
    assert len(email.outbox) == 1
    # The token is the last whitespace-separated chunk of the email body.
    return email.outbox[0].body.split()[-1]


def test_full_password_reset_flow(client):
    register(client, "Alice", "alice@acme.com", password="old-password")
    token = _reset_token_from_email(client, "alice@acme.com")

    # Reset to a new password.
    reset = client.post(
        "/auth/reset-password",
        json={"reset_token": token, "new_password": "brand-new-pw"},
    )
    assert reset.status_code == 200

    # Old password no longer works; new password does.
    assert client.post(
        "/auth/login", json={"email": "alice@acme.com", "password": "old-password"}
    ).status_code == 401
    assert client.post(
        "/auth/login", json={"email": "alice@acme.com", "password": "brand-new-pw"}
    ).status_code == 200


def test_forgot_password_unknown_email_sends_nothing_but_same_reply(client):
    email.clear_outbox()
    resp = client.post("/auth/forgot-password", json={"email": "nobody@nowhere.com"})
    # Same generic reply, but no email is actually sent (no account to reveal).
    assert resp.status_code == 200
    assert len(email.outbox) == 0


def test_reset_token_is_single_use(client):
    register(client, "Alice", "alice@acme.com", password="old-password")
    token = _reset_token_from_email(client, "alice@acme.com")

    first = client.post(
        "/auth/reset-password", json={"reset_token": token, "new_password": "first-pw1"}
    )
    assert first.status_code == 200
    second = client.post(
        "/auth/reset-password", json={"reset_token": token, "new_password": "second-pw2"}
    )
    assert second.status_code == 400  # already used


def test_reset_with_garbage_token_rejected(client):
    resp = client.post(
        "/auth/reset-password",
        json={"reset_token": "not-a-token", "new_password": "whatever1"},
    )
    assert resp.status_code == 400


# ---- role constraints ----------------------------------------------------

def test_member_cannot_accept_join_request(client):
    admin_token = register(client, "Alice", "alice@acme.com")
    org_id = create_org(client, admin_token)
    member_token = make_member(client, admin_token, org_id, "Bob", "bob@example.com")

    # A third user requests to join.
    carol_token = register(client, "Carol", "carol@example.com")
    req_id = client.post(
        f"/orgs/{org_id}/join-requests", headers=auth_header(carol_token)
    ).json()["id"]

    # The plain member tries to accept it -> forbidden.
    resp = client.post(f"/join-requests/{req_id}/accept", headers=auth_header(member_token))
    assert resp.status_code == 403


def test_member_cannot_promote(client):
    admin_token = register(client, "Alice", "alice@acme.com")
    org_id = create_org(client, admin_token)
    member_token = make_member(client, admin_token, org_id, "Bob", "bob@example.com")
    bob_id = done_user_id(client, member_token)

    resp = client.post(
        f"/orgs/{org_id}/members/{bob_id}/promote", headers=auth_header(member_token)
    )
    assert resp.status_code == 403


# ---- tenant isolation ----------------------------------------------------

def test_non_member_cannot_view_members(client):
    admin_token = register(client, "Alice", "alice@acme.com")
    org_id = create_org(client, admin_token)
    outsider_token = register(client, "Eve", "eve@example.com")

    resp = client.get(f"/orgs/{org_id}/members", headers=auth_header(outsider_token))
    assert resp.status_code == 403


def test_orgs_are_isolated(client):
    a_token = register(client, "Alice", "alice@a.com")
    org_a = create_org(client, a_token, name="Org A")
    b_token = register(client, "Bob", "bob@b.com")
    org_b = create_org(client, b_token, name="Org B")

    # Alice sees only Org A's members; she's not a member of Org B at all.
    a_members = client.get(f"/orgs/{org_a}/members", headers=auth_header(a_token))
    assert {m["email"] for m in a_members.json()["members"]} == {"alice@a.com"}
    assert client.get(
        f"/orgs/{org_b}/members", headers=auth_header(a_token)
    ).status_code == 403


# ---- reject flow ---------------------------------------------------------

def test_rejected_request_issues_no_invite(client):
    admin_token = register(client, "Alice", "alice@acme.com")
    org_id = create_org(client, admin_token)
    joiner_token = register(client, "Bob", "bob@example.com")
    req_id = client.post(
        f"/orgs/{org_id}/join-requests", headers=auth_header(joiner_token)
    ).json()["id"]

    reject = client.post(f"/join-requests/{req_id}/reject", headers=auth_header(admin_token))
    assert reject.status_code == 200

    # Accepting an already-rejected request fails.
    again = client.post(f"/join-requests/{req_id}/accept", headers=auth_header(admin_token))
    assert again.status_code == 400

    # Bob is still not a member.
    bob_id = done_user_id(client, joiner_token)
    assert store.get_membership(bob_id, org_id) is None


# ---- single-use invites --------------------------------------------------

def test_invite_cannot_be_used_twice(client):
    admin_token = register(client, "Alice", "alice@acme.com")
    org_id = create_org(client, admin_token)
    joiner_token = register(client, "Bob", "bob@example.com")
    req_id = client.post(
        f"/orgs/{org_id}/join-requests", headers=auth_header(joiner_token)
    ).json()["id"]
    invite_token = client.post(
        f"/join-requests/{req_id}/accept", headers=auth_header(admin_token)
    ).json()["invite_token"]

    first = client.post(
        "/invites/accept",
        json={"invite_token": invite_token},
        headers=auth_header(joiner_token),
    )
    assert first.status_code == 201
    second = client.post(
        "/invites/accept",
        json={"invite_token": invite_token},
        headers=auth_header(joiner_token),
    )
    assert second.status_code == 400


def test_invite_for_other_user_rejected(client):
    admin_token = register(client, "Alice", "alice@acme.com")
    org_id = create_org(client, admin_token)
    bob_token = register(client, "Bob", "bob@example.com")
    req_id = client.post(
        f"/orgs/{org_id}/join-requests", headers=auth_header(bob_token)
    ).json()["id"]
    invite_token = client.post(
        f"/join-requests/{req_id}/accept", headers=auth_header(admin_token)
    ).json()["invite_token"]

    # Carol tries to use Bob's invite -> forbidden.
    carol_token = register(client, "Carol", "carol@example.com")
    resp = client.post(
        "/invites/accept",
        json={"invite_token": invite_token},
        headers=auth_header(carol_token),
    )
    assert resp.status_code == 403


# ---- email notifications -------------------------------------------------

def test_join_request_notifies_admins(client):
    admin_token = register(client, "Alice", "alice@acme.com")
    org_id = create_org(client, admin_token, name="Acme")
    joiner_token = register(client, "Bob", "bob@example.com")

    email.clear_outbox()
    client.post(f"/orgs/{org_id}/join-requests", headers=auth_header(joiner_token))

    # Exactly one email, to the admin, announcing the request.
    assert len(email.outbox) == 1
    msg = email.outbox[0]
    assert msg.to == "alice@acme.com"
    assert "join" in msg.subject.lower()
    assert "bob@example.com" in msg.body


def test_accept_emails_requester_with_token(client):
    admin_token = register(client, "Alice", "alice@acme.com")
    org_id = create_org(client, admin_token, name="Acme")
    joiner_token = register(client, "Bob", "bob@example.com")
    req_id = client.post(
        f"/orgs/{org_id}/join-requests", headers=auth_header(joiner_token)
    ).json()["id"]

    email.clear_outbox()
    accept = client.post(f"/join-requests/{req_id}/accept", headers=auth_header(admin_token))
    invite_token = accept.json()["invite_token"]

    # Bob is emailed, and the email contains the very invite token he needs.
    assert len(email.outbox) == 1
    assert email.outbox[0].to == "bob@example.com"
    assert invite_token in email.outbox[0].body


def test_reject_emails_requester(client):
    admin_token = register(client, "Alice", "alice@acme.com")
    org_id = create_org(client, admin_token, name="Acme")
    joiner_token = register(client, "Bob", "bob@example.com")
    req_id = client.post(
        f"/orgs/{org_id}/join-requests", headers=auth_header(joiner_token)
    ).json()["id"]

    email.clear_outbox()
    client.post(f"/join-requests/{req_id}/reject", headers=auth_header(admin_token))

    assert len(email.outbox) == 1
    assert email.outbox[0].to == "bob@example.com"


# ---- persistence ---------------------------------------------------------

def test_data_persists_across_connections(client):
    """Writing a user then re-reading it through a fresh DB connection proves data
    is stored on disk, not just in memory (so it survives restarts)."""
    register(client, "Alice", "alice@acme.com")
    # store.get_user_by_email opens a brand-new connection to the same file.
    again = store.get_user_by_email("alice@acme.com")
    assert again is not None
    assert again["name"] == "Alice"
    # And the password is stored hashed, never in plain text.
    assert again["password_hash"] != "secret123"
    assert security.verify_password("secret123", again["password_hash"], again["salt"])
