"""Configuration constants for the API.

In a real deployment the SECRET_KEY would come from an environment variable and
never be committed to source control. For this learning project we keep a default
inline so the app runs with zero setup.
"""

import os
from pathlib import Path

# The secret used to SIGN and VERIFY our JWT tokens. Anyone who knows this secret
# could forge tokens, which is why real apps load it from the environment.
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me-in-production-0123456789")

# Signing algorithm. HS256 = HMAC + SHA-256, a simple shared-secret scheme.
ALGORITHM = "HS256"

# How long an auth (login) token stays valid, in minutes.
AUTH_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 day

# How long an invite token stays valid, in minutes.
INVITE_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

# How long a password-reset token stays valid, in minutes (kept short on purpose).
RESET_TOKEN_EXPIRE_MINUTES = 30

# The roles a user can have within an org. Kept deliberately small for clarity.
ROLES = ("admin", "member")

# Where the SQLite database file lives. Tests override this with a temp file.
# Default: <project root>/app.db
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_PATH = os.getenv("DATABASE_PATH", str(PROJECT_ROOT / "app.db"))
