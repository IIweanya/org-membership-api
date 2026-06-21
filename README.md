# Organization Membership API

A small multi-tenant API where people create organizations, invite others by email,
accept invites, and list their org's members — built with **Python + FastAPI**.

## What's a token? (the 30-second version)

A **token** is a signed string that proves who you are on each request, like a
festival wristband: hard to forge, and it carries facts about you (your org, your
role, when it expires). We use the standard **JWT** format. There are two kinds here:

- **Auth token** — given when you create an org or accept an invite. Send it as
  `Authorization: Bearer <token>` to call protected endpoints.
- **Invite token** — emailed to an invitee; they hand it back to `/invites/accept`.

The three rules the API enforces:

| Rule | How it works |
| --- | --- |
| **Token validity** | Every protected call checks the JWT signature + expiry. Bad/expired → `401`. |
| **Role constraints** | Only an `admin` may create invites. A `member` who tries → `403`. |
| **Tenant isolation** | Your token carries your `org_id`; you only ever see your own org's members. |

## Endpoints

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `POST` | `/orgs` | — | Create an org + first admin. Returns an auth token. |
| `POST` | `/invites` | admin | Invite an email with a role. Returns an invite token. |
| `POST` | `/invites/accept` | — | Redeem an invite token, become a member. Returns an auth token. |
| `GET` | `/members` | member | List members of your org. |
| `GET` | `/health` | — | Liveness check. |

## Setup & run

```bash
# from the project root
python -m venv .venv
source .venv/Scripts/activate      # Windows (Git Bash). macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt

uvicorn app.main:app --reload
# open http://127.0.0.1:8000/docs to click through the API
```

## Run the tests

```bash
pytest -v
```

The integration tests in `tests/test_invite_lifecycle.py` cover the full invite
lifecycle (create → invite → accept → list) plus token validity, role constraints,
tenant isolation, and single-use invites.

## Project layout

```
app/
  main.py        FastAPI app + routes
  config.py      JWT secret & expiry settings
  models.py      request/response schemas (Pydantic)
  store.py       in-memory data store (swap for a real DB later)
  security.py    create/verify JWT tokens
  deps.py        auth dependencies (get_current_user, require_admin)
  routers/       orgs.py, invites.py, members.py
tests/
  conftest.py            test client + store reset
  test_invite_lifecycle.py
```

> **Note:** data is stored in memory, so it resets when the server restarts. This
> keeps the project zero-setup and makes tests deterministic. The `store.py` module
> is the only place that knows how data is persisted, so swapping in SQLite/Postgres
> later means changing just that one file.
