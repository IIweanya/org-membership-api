"""Organization endpoints:

  POST /orgs            -> any logged-in user creates an org and becomes its admin
  GET  /orgs?search=    -> browse / search all organizations (public list)
  GET  /orgs/{org_id}   -> details of one organization

Browsing is intentionally open: a user must be able to find a company before they
can request to join it.
"""

from fastapi import APIRouter, Depends, HTTPException, status

from .. import store
from ..deps import get_current_user
from ..models import CreateOrgRequest, OrgOut

router = APIRouter(tags=["orgs"])


@router.post("/orgs", response_model=OrgOut, status_code=status.HTTP_201_CREATED)
def create_org(
    body: CreateOrgRequest,
    current_user: dict = Depends(get_current_user),
) -> OrgOut:
    org = store.create_org(
        name=body.name,
        description=body.description,
        created_by=current_user["id"],
    )
    # The creator automatically becomes the first admin of their new org.
    store.create_membership(user_id=current_user["id"], org_id=org["id"], role="admin")
    return OrgOut(id=org["id"], name=org["name"], description=org["description"])


@router.get("/orgs", response_model=list[OrgOut])
def list_orgs(search: str | None = None) -> list[OrgOut]:
    """List organizations, optionally filtered by name via ?search=."""
    orgs = store.list_orgs(search=search)
    return [OrgOut(id=o["id"], name=o["name"], description=o["description"]) for o in orgs]


@router.get("/orgs/{org_id}", response_model=OrgOut)
def get_org(org_id: str) -> OrgOut:
    org = store.get_org(org_id)
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found"
        )
    return OrgOut(id=org["id"], name=org["name"], description=org["description"])
