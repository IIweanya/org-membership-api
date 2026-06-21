"""Authentication endpoints: register, login, and 'who am I'.

  POST /auth/register -> create an account (name, email, password), return a token
  POST /auth/login    -> verify email + password, return a token
  GET  /auth/me       -> the logged-in user's profile + their org memberships

The token returned here is your "logged-in" proof. Send it as
`Authorization: Bearer <token>` on every other call.
"""

from fastapi import APIRouter, Depends, HTTPException, status

from .. import security, store
from ..deps import get_current_user
from ..models import (
    LoginRequest,
    MembershipOut,
    RegisterRequest,
    TokenResponse,
    UserProfile,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest) -> TokenResponse:
    # Emails are unique — one account per email.
    if store.get_user_by_email(body.email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with that email already exists",
        )

    # Hash the password before storing; the plain text is never saved.
    password_hash, salt = security.hash_password(body.password)
    user = store.create_user(
        name=body.name,
        email=body.email,
        password_hash=password_hash,
        salt=salt,
    )
    token = security.create_auth_token(user["id"])
    return TokenResponse(access_token=token, user_id=user["id"])


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest) -> TokenResponse:
    user = store.get_user_by_email(body.email)
    # Use the same error whether the email or the password is wrong, so we don't
    # reveal which emails are registered.
    if user is None or not security.verify_password(
        body.password, user["password_hash"], user["salt"]
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    token = security.create_auth_token(user["id"])
    return TokenResponse(access_token=token, user_id=user["id"])


@router.get("/me", response_model=UserProfile)
def me(current_user: dict = Depends(get_current_user)) -> UserProfile:
    memberships = [
        MembershipOut(org_id=m["org_id"], role=m["role"])
        for m in store.list_memberships_for_user(current_user["id"])
    ]
    return UserProfile(
        id=current_user["id"],
        name=current_user["name"],
        email=current_user["email"],
        memberships=memberships,
    )
