"""Reusable "dependencies" that enforce auth rules.

FastAPI lets you declare that a route *depends on* a function. FastAPI runs that
function first and injects its return value into the route. We use this to:

  * get_current_user  -> decode the auth token and load the user (enforces TOKEN
                         VALIDITY and, via org_id, TENANT ISOLATION)
  * require_admin     -> additionally require role == "admin" (ROLE CONSTRAINTS)

Putting this logic in one place means every protected route is guarded the same way
and we never repeat ourselves.
"""

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import security, store

# Tells FastAPI to look for an "Authorization: Bearer <token>" header.
# auto_error=False so we can return our own 401 message when it is missing.
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
        # Covers expired, tampered, or otherwise malformed tokens.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Reject invite tokens (or anything that isn't an auth token) used as a login.
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


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """Like get_current_user, but the user must be an admin."""
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required",
        )
    return current_user
