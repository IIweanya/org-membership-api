"""Pydantic models = the shapes of our request and response bodies.

FastAPI uses these to validate incoming JSON and to document the API. Note that
none of the response models include password fields — secrets never leave the server.
"""

from typing import Literal

from pydantic import BaseModel, EmailStr, Field


# ---- auth ----------------------------------------------------------------

class RegisterRequest(BaseModel):
    name: str = Field(min_length=1)
    email: EmailStr
    password: str = Field(min_length=6)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    reset_token: str
    new_password: str = Field(min_length=6)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str


class MembershipOut(BaseModel):
    org_id: str
    role: str


class UserProfile(BaseModel):
    id: str
    name: str
    email: EmailStr
    memberships: list[MembershipOut]


# ---- orgs ----------------------------------------------------------------

class CreateOrgRequest(BaseModel):
    name: str = Field(min_length=1)
    description: str = ""


class OrgOut(BaseModel):
    id: str
    name: str
    description: str


# ---- join requests -------------------------------------------------------

class JoinRequestOut(BaseModel):
    id: str
    user_id: str
    org_id: str
    status: str


class JoinRequestWithUser(BaseModel):
    """A pending request as the admin sees it — includes who is asking."""
    id: str
    org_id: str
    status: str
    user_id: str
    user_name: str
    user_email: EmailStr


class AcceptJoinRequestResponse(BaseModel):
    join_request_id: str
    status: str
    invite_token: str  # the admin hands this to the user to finish joining


# ---- invites -------------------------------------------------------------

class AcceptInviteRequest(BaseModel):
    invite_token: str


class AcceptInviteResponse(BaseModel):
    org_id: str
    role: str
    message: str = "You are now a member of the organization."


# ---- members -------------------------------------------------------------

class MemberOut(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: str


class MembersResponse(BaseModel):
    org_id: str
    members: list[MemberOut]


# ---- generic -------------------------------------------------------------

class MessageResponse(BaseModel):
    message: str


# Reusable role type for request bodies.
Role = Literal["admin", "member"]
