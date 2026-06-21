"""Authentication endpoints: register, login, and 'who am I'.

  POST /auth/register -> create an account (name, email, password), return a token
  POST /auth/login    -> verify email + password, return a token
  GET  /auth/me       -> the logged-in user's profile + their org memberships

The token returned here is your "logged-in" proof. Send it as
`Authorization: Bearer <token>` on every other call.
"""

from fastapi import APIRouter, Depends, HTTPException, status

import jwt

from .. import email, security, store
from ..deps import get_current_user
from ..models import (
    ForgotPasswordRequest,
    LoginRequest,
    MembershipOut,
    MessageResponse,
    RegisterRequest,
    ResetPasswordRequest,
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


# A single generic reply so we never reveal which emails are registered.
_GENERIC_RESET_REPLY = MessageResponse(
    message="If an account exists for that email, a password-reset email has been sent."
)


@router.post("/forgot-password", response_model=MessageResponse)
def forgot_password(body: ForgotPasswordRequest) -> MessageResponse:
    user = store.get_user_by_email(body.email)
    # Only actually send if the user exists — but the response is identical either way.
    if user is not None:
        token, jti = security.create_reset_token(user["id"])
        store.create_password_reset(jti=jti, user_id=user["id"])
        email.send_email(
            to=user["email"],
            subject="Reset your password",
            body=(
                f"Hi {user['name']},\n\nUse this token to reset your password "
                f"(POST /auth/reset-password). It expires soon and can be used once:"
                f"\n\n{token}"
            ),
        )
    return _GENERIC_RESET_REPLY


@router.post("/reset-password", response_model=MessageResponse)
def reset_password(body: ResetPasswordRequest) -> MessageResponse:
    # 1. Verify the token's signature + expiry.
    try:
        claims = security.decode_token(body.reset_token)
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )
    if claims.get("type") != "reset":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Not a reset token"
        )

    # 2. Enforce single use via the stored jti.
    record = store.get_password_reset(claims.get("jti", ""))
    if record is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Reset token not found")
    if record["used"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This reset token has already been used",
        )

    user = store.get_user(claims.get("user_id", ""))
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User no longer exists")

    # 3. Hash and store the new password, then burn the token.
    password_hash, salt = security.hash_password(body.new_password)
    store.update_user_password(user["id"], password_hash, salt)
    store.mark_password_reset_used(record["jti"])
    return MessageResponse(message="Your password has been reset. You can now log in.")


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
