"""Pydantic models = the shapes of our request and response bodies.

FastAPI uses these to (a) automatically validate incoming JSON and (b) document the
API. If a request is missing a field or has the wrong type, FastAPI returns a clear
422 error before our code even runs.
"""

from typing import Literal

from pydantic import BaseModel, EmailStr


# ---- Requests ----

class CreateOrgRequest(BaseModel):
    org_name: str
    admin_email: EmailStr  # EmailStr rejects values that are not valid emails


class CreateInviteRequest(BaseModel):
    email: EmailStr
    # Literal restricts role to exactly these two strings — anything else is a 422.
    role: Literal["admin", "member"] = "member"


class AcceptInviteRequest(BaseModel):
    invite_token: str


# ---- Responses ----

class CreateOrgResponse(BaseModel):
    org_id: str
    user_id: str
    access_token: str


class CreateInviteResponse(BaseModel):
    invite_token: str


class AcceptInviteResponse(BaseModel):
    org_id: str
    user_id: str
    access_token: str


class MemberOut(BaseModel):
    id: str
    email: EmailStr
    role: str


class MembersResponse(BaseModel):
    org_id: str
    members: list[MemberOut]
