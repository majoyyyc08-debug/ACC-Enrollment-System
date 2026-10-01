"""
config.py
---------
Central configuration for the Flask application.

Why this pattern?
- Keeps all tunable/security-sensitive values in ONE place.
- Reads secrets from environment variables (via python-dotenv) instead of
  hard-coding them in source control -> prevents leaking the SECRET_KEY,
  which is what Flask uses to cryptographically sign session cookies and
  CSRF tokens. If that key leaks, an attacker can forge sessions.
- Separate config classes per environment (Development / Production /
  Testing) so we never accidentally run production with debug=True
  (which would expose a remote code execution console).
"""

import os
from datetime import timedelta

# Load variables from a local .env file if present (never commit .env!)
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))


class BaseConfig:
    """Settings shared by every environment."""

    # SECRET_KEY signs session cookies + CSRF tokens. In production this
    # MUST come from the environment. We only fall back to a random dev
    # key so the app doesn't crash the first time someone runs it locally.
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-insecure-key-change-me")

    # SQLite database file lives inside /instance (Flask's convention for
    # files that should NOT be committed to version control).
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'enrollment.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # saves memory, avoids noisy warnings

    # ---- Session / cookie hardening ----
    SESSION_COOKIE_HTTPONLY = True     # JS (and thus XSS payloads) cannot read the cookie
    SESSION_COOKIE_SAMESITE = "Lax"    # mitigates CSRF from cross-site requests
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    # ---- CSRF (Flask-WTF) ----
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None  # tokens valid for the whole session, not just 1 hr

    # ---- Password policy ----
    MIN_PASSWORD_LENGTH = 8


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    SESSION_COOKIE_SECURE = False  # allow http://localhost during local dev


class ProductionConfig(BaseConfig):
    DEBUG = False
    SESSION_COOKIE_SECURE = True   # cookie only sent over HTTPS
    # In production, refuse to boot with the placeholder secret key.
    SECRET_KEY = os.environ.get("SECRET_KEY")
    if not SECRET_KEY:
        raise RuntimeError(
            "SECRET_KEY environment variable must be set in production!"
        )


class TestingConfig(BaseConfig):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False  # simplifies posting forms in automated tests


config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}
