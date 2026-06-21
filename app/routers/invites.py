"""Invite endpoints:

  POST /invites         (admin only) -> create an invite token for an email
  POST /invites/accept  (public)     -> redeem an invite token, becoming a member

The invite token itself carries which org and role the invite is for, signed so it
cannot be tampered with. We ALSO record the invite in the store so it can be used
only once.
"""

import jwt
from fastapi import APIRouter, Depends, HTTPException, status

from .. import security, store
from ..deps import require_admin
from ..models import (
    AcceptInviteRequest,
    AcceptInviteResponse,
    CreateInviteRequest,
    CreateInviteResponse,
)

router = APIRouter(tags=["invites"])


@router.post("/invites", response_model=CreateInviteResponse, status_code=status.HTTP_201_CREATED)
def create_invite(
    body: CreateInviteRequest,
    admin: dict = Depends(require_admin),  # ROLE CONSTRAINT: admins only
) -> CreateInviteResponse:
    # TENANT ISOLATION: the invite is bound to the admin's own org. An admin can
    # never invite someone into a different org.
    org_id = admin["org_id"]

    # Don't invite someone who is already a member of this org.
    if store.find_user_by_email_in_org(body.email, org_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="That email is already a member of this organization",
        )

    token, jti = security.create_invite_token(body.email, org_id, body.role)
    store.create_invite(jti=jti, email=body.email, org_id=org_id, role=body.role)
    return CreateInviteResponse(invite_token=token)


@router.post("/invites/accept", response_model=AcceptInviteResponse, status_code=status.HTTP_201_CREATED)
def accept_invite(body: AcceptInviteRequest) -> AcceptInviteResponse:
    # 1. Verify the token's signature + expiry.
    try:
        claims = security.decode_token(body.invite_token)
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired invite token",
        )

    if claims.get("type") != "invite":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Not an invite token",
        )

    # 2. Look up the stored invite to enforce single use.
    invite = store.get_invite(claims.get("jti", ""))
    if invite is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invite not found",
        )
    if invite["accepted"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invite has already been used",
        )

    # 3. Create the member (or reuse if they somehow already exist in the org).
    existing = store.find_user_by_email_in_org(invite["email"], invite["org_id"])
    user = existing or store.create_user(
        email=invite["email"],
        org_id=invite["org_id"],
        role=invite["role"],
    )

    # 4. Burn the invite so it can't be accepted again.
    invite["accepted"] = True

    token = security.create_auth_token(user)
    return AcceptInviteResponse(
        org_id=user["org_id"],
        user_id=user["id"],
        access_token=token,
    )
