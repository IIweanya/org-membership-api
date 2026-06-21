"""Join-request endpoints — the heart of the new "ask to join" flow.

  POST /orgs/{org_id}/join-requests   -> a user asks to join an org (status: pending)
  GET  /orgs/{org_id}/join-requests   -> admin sees pending requests (the notification)
  POST /join-requests/{id}/accept     -> admin accepts -> issues an invite token
  POST /join-requests/{id}/reject     -> admin rejects -> no invite

Accepting does NOT add the member directly: it produces an invite token that the user
must accept (POST /invites/accept). That keeps a clean, single-use proof that this
specific admin approved this specific user for this specific org.
"""

from fastapi import APIRouter, Depends, HTTPException, status

from .. import security, store
from ..deps import get_current_user, require_org_admin
from ..models import (
    AcceptJoinRequestResponse,
    JoinRequestOut,
    JoinRequestWithUser,
    MessageResponse,
)

router = APIRouter(tags=["join-requests"])


@router.post(
    "/orgs/{org_id}/join-requests",
    response_model=JoinRequestOut,
    status_code=status.HTTP_201_CREATED,
)
def request_to_join(
    org_id: str,
    current_user: dict = Depends(get_current_user),
) -> JoinRequestOut:
    org = store.get_org(org_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    # Already a member? Nothing to request.
    if store.get_membership(current_user["id"], org_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You are already a member of this organization",
        )

    # Don't allow stacking duplicate pending requests.
    if store.get_pending_join_request(current_user["id"], org_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You already have a pending request to join this organization",
        )

    req = store.create_join_request(user_id=current_user["id"], org_id=org_id)
    return JoinRequestOut(**req)


@router.get(
    "/orgs/{org_id}/join-requests",
    response_model=list[JoinRequestWithUser],
)
def list_pending_requests(
    org_id: str,
    _admin=Depends(require_org_admin),  # admin of THIS org only
) -> list[JoinRequestWithUser]:
    """The admin's 'someone wants to join' inbox: pending requests + who is asking."""
    result = []
    for req in store.list_join_requests(org_id, status="pending"):
        user = store.get_user(req["user_id"])
        if user is None:
            continue
        result.append(
            JoinRequestWithUser(
                id=req["id"],
                org_id=req["org_id"],
                status=req["status"],
                user_id=user["id"],
                user_name=user["name"],
                user_email=user["email"],
            )
        )
    return result


def _load_pending_request_for_admin(req_id: str, current_user: dict) -> dict:
    """Shared guard for accept/reject: the request must exist, be pending, and the
    caller must be an admin of the request's org."""
    req = store.get_join_request(req_id)
    if req is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Join request not found")

    # Authorization is based on the request's org (the path has no org_id here).
    membership = store.get_membership(current_user["id"], req["org_id"])
    if membership is None or membership["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required for this organization",
        )

    if req["status"] != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Request has already been {req['status']}",
        )
    return req


@router.post(
    "/join-requests/{req_id}/accept",
    response_model=AcceptJoinRequestResponse,
)
def accept_join_request(
    req_id: str,
    current_user: dict = Depends(get_current_user),
) -> AcceptJoinRequestResponse:
    req = _load_pending_request_for_admin(req_id, current_user)

    # Mark accepted and issue a single-use invite token bound to this user + org.
    store.set_join_request_status(req_id, "accepted")
    token, jti = security.create_invite_token(
        user_id=req["user_id"], org_id=req["org_id"], role="member"
    )
    store.create_invite(
        jti=jti,
        user_id=req["user_id"],
        org_id=req["org_id"],
        role="member",
        join_request_id=req_id,
    )
    return AcceptJoinRequestResponse(
        join_request_id=req_id, status="accepted", invite_token=token
    )


@router.post(
    "/join-requests/{req_id}/reject",
    response_model=MessageResponse,
)
def reject_join_request(
    req_id: str,
    current_user: dict = Depends(get_current_user),
) -> MessageResponse:
    _load_pending_request_for_admin(req_id, current_user)
    store.set_join_request_status(req_id, "rejected")
    return MessageResponse(message="Join request rejected.")
