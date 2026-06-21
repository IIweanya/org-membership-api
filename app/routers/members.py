"""GET /members — list everyone in the caller's organization.

This is the clearest example of TENANT ISOLATION: we read the org_id from the
authenticated user and only ever return members of THAT org.
"""

from fastapi import APIRouter, Depends

from .. import store
from ..deps import get_current_user
from ..models import MemberOut, MembersResponse

router = APIRouter(tags=["members"])


@router.get("/members", response_model=MembersResponse)
def list_members(current_user: dict = Depends(get_current_user)) -> MembersResponse:
    org_id = current_user["org_id"]
    members = [
        MemberOut(id=u["id"], email=u["email"], role=u["role"])
        for u in store.list_members(org_id)
    ]
    return MembersResponse(org_id=org_id, members=members)
