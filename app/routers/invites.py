"""Invite acceptance — the final step of joining an org.

  POST /invites/accept -> the user submits the invite token they were given when an
                          admin accepted their join request. This creates their
                          membership and burns the invite so it can't be reused.

The user must be logged in AND the invite must have been issued for that same user,
so an invite token can't be redeemed by someone else.
"""

import jwt
from fastapi import APIRouter, Depends, HTTPException, status

from .. import security, store
from ..deps import get_current_user
from ..models import AcceptInviteRequest, AcceptInviteResponse

router = APIRouter(tags=["invites"])


@router.post("/invites/accept", response_model=AcceptInviteResponse, status_code=status.HTTP_201_CREATED)
def accept_invite(
    body: AcceptInviteRequest,
    current_user: dict = Depends(get_current_user),
) -> AcceptInviteResponse:
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
            status_code=status.HTTP_400_BAD_REQUEST, detail="Not an invite token"
        )

    # 2. The invite must have been issued for the logged-in user.
    if claims.get("user_id") != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This invite was issued for a different user",
        )

    # 3. Look up the stored invite to enforce single use.
    invite = store.get_invite(claims.get("jti", ""))
    if invite is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invite not found")
    if invite["accepted"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invite has already been used",
        )

    # 4. Create the membership (unless somehow already a member), then burn the invite.
    org_id = invite["org_id"]
    role = invite["role"]
    if store.get_membership(current_user["id"], org_id) is None:
        store.create_membership(user_id=current_user["id"], org_id=org_id, role=role)
    store.mark_invite_accepted(invite["jti"])

    return AcceptInviteResponse(org_id=org_id, role=role)
