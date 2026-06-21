"""FastAPI application entry point.

Run locally with:   uvicorn app.main:app --reload
Then open:          http://127.0.0.1:8000/docs   (interactive API explorer)

On startup we make sure the database tables exist (init_db). The data file persists
between restarts, so accounts and orgs survive a server restart.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from .db import init_db
from .routers import auth, invites, join_requests, members, orgs


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()  # create tables if they don't exist yet
    yield


app = FastAPI(
    title="Organization Membership API",
    description=(
        "Register, log in, create or browse organizations, request to join, accept "
        "invites, and manage members — with token validity, role constraints, and "
        "tenant isolation."
    ),
    version="2.0.0",
    lifespan=lifespan,
)

app.include_router(auth.router)
app.include_router(orgs.router)
app.include_router(join_requests.router)
app.include_router(invites.router)
app.include_router(members.router)


@app.get("/health", tags=["health"])
def health() -> dict:
    """A simple liveness check."""
    return {"status": "ok"}
