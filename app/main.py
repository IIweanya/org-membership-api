"""FastAPI application entry point.

Run locally with:   uvicorn app.main:app --reload
Then open:          http://127.0.0.1:8000/docs   (interactive API explorer)
"""

from fastapi import FastAPI

from .routers import invites, members, orgs

app = FastAPI(
    title="Organization Membership API",
    description="Create orgs, invite people, accept invites, and list members — "
    "with token validity, role constraints, and tenant isolation.",
    version="1.0.0",
)

app.include_router(orgs.router)
app.include_router(invites.router)
app.include_router(members.router)


@app.get("/health", tags=["health"])
def health() -> dict:
    """A simple liveness check."""
    return {"status": "ok"}
