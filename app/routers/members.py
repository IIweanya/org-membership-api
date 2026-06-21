"""Member endpoints — viewing members, promoting, and leaving.

  GET  /orgs/{org_id}/members                       -> members only: list this org
  POST /orgs/{org_id}/members/{user_id}/promote     -> admin only: make someone admin
  POST /orgs/{org_id}/leave                          -> leave the org (any member)

`GET /members` is the clearest example of TENANT ISOLATION: the require_membership
dependency guarantees only a member of the org can ever read its member list.
"""

from fastapi import APIRouter, Depends, HTTPException, status

from .. import store
from ..deps import get_current_user, require_membership, require_org_admin
from ..models import MemberOut, MembersResponse, MessageResponse

router = APIRouter(tags=["members"])


@router.get("/orgs/{org_id}/members", response_model=MembersResponse)
def list_members(
    org_id: str,
    _membership=Depends(require_membership),  # must be a member of this org
) -> MembersResponse:
    members = [
        MemberOut(id=m["id"], name=m["name"], email=m["email"], role=m["role"])
        for m in store.list_members(org_id)
    ]
    return MembersResponse(org_id=org_id, members=members)


@router.post(
    "/orgs/{org_id}/members/{user_id}/promote",
    response_model=MessageResponse,
)
def promote_member(
    org_id: str,
    user_id: str,
    _admin=Depends(require_org_admin),  # only an admin of this org may promote
) -> MessageResponse:
    target = store.get_membership(user_id, org_id)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="That user is not a member of this organization",
        )
    if target["role"] == "admin":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="That user is already an admin",
        )
    store.set_membership_role(user_id, org_id, "admin")
    return MessageResponse(message="Member promoted to admin.")


@router.post("/orgs/{org_id}/leave", response_model=MessageResponse)
def leave_org(
    org_id: str,
    membership=Depends(require_membership),  # you can only leave an org you're in
    current_user: dict = Depends(get_current_user),
) -> MessageResponse:
    # Guard: don't let the last admin leave and strand the org without one.
    if membership["role"] == "admin" and store.count_admins(org_id) <= 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You are the last admin; promote another member before leaving",
        )
    store.delete_membership(current_user["id"], org_id)
    return MessageResponse(message="You have left the organization.")
