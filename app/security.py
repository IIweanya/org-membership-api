"""Token creation and verification — the heart of authentication.

A JWT (JSON Web Token) is just a string with three parts separated by dots:

    header.payload.signature

The `payload` holds "claims" (facts like user_id, org_id, role, and an expiry).
The `signature` is computed from the header + payload + our SECRET_KEY. Because an
attacker does not know the secret, they cannot change the claims without breaking
the signature — that is what makes a token trustworthy.

We use tokens for TWO different jobs:
  * auth tokens   -> "I am logged-in user X in org Y with role Z"
  * invite tokens -> "the bearer was invited to org Y as role Z under email E"
"""

import datetime
import uuid

import jwt  # the PyJWT library

from . import config


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def create_auth_token(user: dict) -> str:
    """Build a signed login token for a user record."""
    payload = {
        "type": "auth",
        "user_id": user["id"],
        "org_id": user["org_id"],
        "role": user["role"],
        # `exp` is a standard JWT claim. PyJWT automatically rejects the token once
        # this time has passed.
        "exp": _now() + datetime.timedelta(minutes=config.AUTH_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, config.SECRET_KEY, algorithm=config.ALGORITHM)


def create_invite_token(email: str, org_id: str, role: str) -> tuple[str, str]:
    """Build a signed invite token.

    Returns (token, jti). The `jti` ("JWT ID") is a unique id for this specific
    invite; we store it so the invite can be marked used and never accepted twice.
    """
    jti = uuid.uuid4().hex
    payload = {
        "type": "invite",
        "jti": jti,
        "email": email,
        "org_id": org_id,
        "role": role,
        "exp": _now() + datetime.timedelta(minutes=config.INVITE_TOKEN_EXPIRE_MINUTES),
    }
    token = jwt.encode(payload, config.SECRET_KEY, algorithm=config.ALGORITHM)
    return token, jti


def decode_token(token: str) -> dict:
    """Verify a token's signature + expiry and return its claims.

    Raises jwt.InvalidTokenError (or a subclass like ExpiredSignatureError) if the
    token is forged, tampered with, or expired. Callers turn that into an HTTP 401.
    """
    return jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
