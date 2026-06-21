# Organization Membership API (v2)

A multi-tenant API where people **register**, **log in**, **create or browse
organizations**, **request to join** them, accept invites, and manage members —
built with **Python + FastAPI** and a **SQLite** database (data persists between
restarts).

> Looking for the simpler first version? It lives on the **`version1`** branch
> (in-memory store, admin cold-invites by email). This branch (**`version2`**) is the
> full product described below.

## What's a token? (the 30-second version)

A **token** is a signed string that proves who you are on each request — like a
festival wristband: hard to forge, and it carries facts about you. We use the
standard **JWT** format. There are two kinds here:

- **Auth token** — given when you register or log in. It encodes **only your user id**
  (who you are). Send it as `Authorization: Bearer <token>` on every protected call.
- **Invite token** — issued when an admin accepts your join request; you hand it back
  to `/invites/accept` to finish joining. Single-use.

**Key idea:** your *role* and *which orgs you belong to* are **not** in the token —
they're looked up from the database on each request. That's why being promoted,
joining, or leaving takes effect immediately without logging in again.

The three rules the API enforces:

| Rule | How it works |
| --- | --- |
| **Token validity** | Every protected call checks the JWT signature + expiry. Bad/expired → `401`. |
| **Role constraints** | Only an org **admin** can accept/reject join requests or promote members → else `403`. |
| **Tenant isolation** | You can only view/manage an org you're a **member** of; your membership is checked per request → else `403`. |

## The main flow

```
register / login                      → get an auth token
POST /orgs                            → create an org (you become admin)
GET  /orgs?search=acme                → find a company to join
POST /orgs/{id}/join-requests         → ask to join  (admin gets notified)
GET  /orgs/{id}/join-requests         → admin sees pending requests
POST /join-requests/{id}/accept       → admin accepts → returns an invite token
POST /join-requests/{id}/reject       → admin rejects (no invite)
POST /invites/accept                  → invitee redeems token → becomes a member
GET  /orgs/{id}/members               → members list (members only)
POST /orgs/{id}/members/{uid}/promote → admin promotes a member to admin
POST /orgs/{id}/leave                 → leave the org
```

## Endpoints

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `POST` | `/auth/register` | — | Create an account (name, email, password). Returns a token. |
| `POST` | `/auth/login` | — | Log in with email + password. Returns a token. |
| `GET` | `/auth/me` | user | Your profile + your org memberships. |
| `POST` | `/orgs` | user | Create an org; you become its admin. |
| `GET` | `/orgs?search=` | — | Browse / search organizations. |
| `GET` | `/orgs/{id}` | — | Org details. |
| `POST` | `/orgs/{id}/join-requests` | user | Request to join an org. |
| `GET` | `/orgs/{id}/join-requests` | admin | List pending requests (notification). |
| `POST` | `/join-requests/{id}/accept` | admin | Accept → issue invite token. |
| `POST` | `/join-requests/{id}/reject` | admin | Reject the request. |
| `POST` | `/invites/accept` | user | Redeem an invite token → become a member. |
| `GET` | `/orgs/{id}/members` | member | List members of your org. |
| `POST` | `/orgs/{id}/members/{uid}/promote` | admin | Promote a member to admin. |
| `POST` | `/orgs/{id}/leave` | member | Leave the org. |
| `GET` | `/health` | — | Liveness check. |

## Setup & run

```bash
# from the project root
python -m venv .venv
source .venv/Scripts/activate      # Windows (Git Bash). macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt

uvicorn app.main:app --reload
# open http://127.0.0.1:8000/docs
# tip: register → copy the access_token → click "Authorize" in /docs → call protected routes
```

Data is stored in `app.db` (created automatically). Delete that file to start fresh.

## Run the tests

```bash
pytest -v
```

`tests/test_invite_lifecycle.py` covers the full lifecycle (register → search →
request → admin accepts → accept invite → list → promote → leave) plus token
validity, role constraints, tenant isolation, the reject path, single-use invites,
and a persistence check.

## Project layout

```
app/
  main.py            FastAPI app, routes, DB init on startup
  config.py          JWT secret, expiry, DB path
  db.py              SQLite connection + schema
  store.py           all data access (the only module that touches the DB)
  security.py        password hashing (PBKDF2) + JWT create/verify
  models.py          request/response schemas (Pydantic)
  deps.py            auth guards: get_current_user, require_membership, require_org_admin
  routers/           auth.py, orgs.py, join_requests.py, invites.py, members.py
tests/
  conftest.py            test client + temp DB reset
  test_invite_lifecycle.py
```

## Email notifications

The app sends emails at key moments:
- a user **requests to join** → all admins of the org are notified;
- an admin **accepts** → the requester is emailed their invite token;
- an admin **rejects** → the requester is notified.

Delivery currently uses a **mock/console sender** (`app/email.py`): messages are printed
to the terminal and recorded in an in-memory `outbox` (which the tests inspect). This
keeps everything testable and offline. Swapping in a real provider (SMTP/SendGrid) means
editing only `app/email.py`.

## Notes

- Passwords are hashed with **PBKDF2-HMAC-SHA256** + a per-user salt (Python stdlib;
  no extra dependency). Plain passwords are never stored or returned.
- A user can belong to **many** orgs, each with its own role.
- The org creator is the first admin; an admin can promote others. The **last admin**
  can't leave until they promote someone else (prevents an org with no admin).
- `SECRET_KEY` and `DATABASE_PATH` can be overridden via environment variables.
