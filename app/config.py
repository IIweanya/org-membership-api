"""Configuration constants for the API.

In a real deployment the SECRET_KEY would come from an environment variable and
never be committed to source control. For this learning project we keep it inline
so the app runs with zero setup.
"""

import os

# The secret used to SIGN and VERIFY our JWT tokens. Anyone who knows this secret
# could forge tokens, which is why real apps load it from the environment.
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me-in-production-0123456789")

# Signing algorithm. HS256 = HMAC + SHA-256, a simple shared-secret scheme.
ALGORITHM = "HS256"

# How long an auth (login) token stays valid, in minutes.
AUTH_TOKEN_EXPIRE_MINUTES = 60

# How long an invite token stays valid, in minutes (invites expire after a while).
INVITE_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

# The roles a user can have. Kept deliberately small for clarity.
ROLES = ("admin", "member")
