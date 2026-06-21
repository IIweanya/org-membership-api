"""POST /orgs — the entry point to the whole system.

Creating an org also creates its first user (you), who becomes the admin. We hand
back an auth token so you can immediately call the admin-only endpoints.
"""

from fastapi import APIRouter, status

from .. import security, store
from ..models import CreateOrgRequest, CreateOrgResponse

router = APIRouter(tags=["orgs"])


@router.post("/orgs", response_model=CreateOrgResponse, status_code=status.HTTP_201_CREATED)
def create_org(body: CreateOrgRequest) -> CreateOrgResponse:
    org = store.create_org(body.org_name)
    # The creator is the first user and is always an admin.
    admin = store.create_user(email=body.admin_email, org_id=org["id"], role="admin")
    token = security.create_auth_token(admin)
    return CreateOrgResponse(
        org_id=org["id"],
        user_id=admin["id"],
        access_token=token,
    )
