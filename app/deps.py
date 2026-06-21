"""Reusable dependencies that enforce authentication and access rules.

The design reflects the v2 token model:
  * The TOKEN proves identity only (which user).  -> get_current_user
  * The DATABASE says which orgs you're in and your role there.
      -> require_membership(org_id)      (are you in this org at all?)
      -> require_org_admin(org_id)       (are you an admin of this org?)

Because role/membership come from the database, an admin promoting you or you
leaving an org takes effect on your very next request — no new token needed.
"""

import jwt
from fastapi import Depends, HTTPException, Path, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import security, store

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict:
    """Return the user record for a valid auth token, else raise 401."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        claims = security.decode_token(credentials.credentials)
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if claims.get("type") != "auth":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Wrong token type",
        )

    user = store.get_user(claims.get("user_id", ""))
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer exists",
        )
    return user


def require_membership(
    org_id: str = Path(...),
    current_user: dict = Depends(get_current_user),
) -> dict:
    """Ensure the caller belongs to `org_id`; return their membership record.

    This is where TENANT ISOLATION is enforced: a user who is not a member of the
    org gets a 403 and never sees its data.
    """
    membership = store.get_membership(current_user["id"], org_id)
    if membership is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not a member of this organization",
        )
    return membership


def require_org_admin(
    org_id: str = Path(...),
    current_user: dict = Depends(get_current_user),
) -> dict:
    """Like require_membership, but the caller must be an admin of `org_id`."""
    membership = store.get_membership(current_user["id"], org_id)
    if membership is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not a member of this organization",
        )
    if membership["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required",
        )
    return membership
