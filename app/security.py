"""Passwords and tokens — the two pillars of authentication.

PASSWORDS
We never store a password as plain text. Instead we store a one-way "hash". When you
log in, we hash what you typed and compare it to the stored hash. We use PBKDF2 (from
Python's standard library) with a random per-user "salt" so that two people with the
same password still get different hashes. No external crypto library required.

TOKENS (JWT)
A JWT is a signed string proving facts ("claims"). We use two kinds:
  * auth token   -> identity only: who you are (user_id) + expiry. Your roles and
                    which orgs you belong to are looked up from the database, NOT the
                    token — so promotions/joins/leaves take effect immediately.
  * invite token -> a single-use invite: user_id, org_id, role, a unique jti, expiry.
"""

import datetime
import hashlib
import hmac
import secrets
import uuid

import jwt  # the PyJWT library

from . import config

# PBKDF2 settings. More iterations = slower to brute-force.
_PBKDF2_ROUNDS = 200_000
_PBKDF2_ALGO = "sha256"


# ---- passwords -----------------------------------------------------------

def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Return (password_hash, salt). Generates a new random salt if none given."""
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        _PBKDF2_ALGO, password.encode(), salt.encode(), _PBKDF2_ROUNDS
    )
    return digest.hex(), salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    """True if `password` hashes to the stored hash. Uses a constant-time compare
    so attackers can't learn the hash by timing the response."""
    candidate, _ = hash_password(password, salt)
    return hmac.compare_digest(candidate, password_hash)


# ---- tokens --------------------------------------------------------------

def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def create_auth_token(user_id: str) -> str:
    """Build a signed login token that identifies a user. Identity only — no role."""
    payload = {
        "type": "auth",
        "user_id": user_id,
        "exp": _now() + datetime.timedelta(minutes=config.AUTH_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, config.SECRET_KEY, algorithm=config.ALGORITHM)


def create_invite_token(user_id: str, org_id: str, role: str) -> tuple[str, str]:
    """Build a single-use invite token. Returns (token, jti)."""
    jti = uuid.uuid4().hex
    payload = {
        "type": "invite",
        "jti": jti,
        "user_id": user_id,
        "org_id": org_id,
        "role": role,
        "exp": _now() + datetime.timedelta(minutes=config.INVITE_TOKEN_EXPIRE_MINUTES),
    }
    token = jwt.encode(payload, config.SECRET_KEY, algorithm=config.ALGORITHM)
    return token, jti


def create_reset_token(user_id: str) -> tuple[str, str]:
    """Build a single-use password-reset token. Returns (token, jti).

    Like an invite, the jti is stored so the token can be used only once.
    """
    jti = uuid.uuid4().hex
    payload = {
        "type": "reset",
        "jti": jti,
        "user_id": user_id,
        "exp": _now() + datetime.timedelta(minutes=config.RESET_TOKEN_EXPIRE_MINUTES),
    }
    token = jwt.encode(payload, config.SECRET_KEY, algorithm=config.ALGORITHM)
    return token, jti


def decode_token(token: str) -> dict:
    """Verify a token's signature + expiry and return its claims.

    Raises jwt.InvalidTokenError (incl. ExpiredSignatureError) on any problem.
    """
    return jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
