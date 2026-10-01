"""
extensions.py
-------------
Instantiate Flask extensions HERE, without binding them to an app yet.

Why a separate module?
Flask extensions normally need an `app` object to configure themselves
(`db.init_app(app)`), but many other modules (models.py, routes, decorators)
need to *import* the extension instance too. If we created the extensions
inside `create_app()` and also tried to import them from `models.py`, we'd
get a circular import (app -> models -> app). Declaring bare instances in
their own module and calling `.init_app()` later (the "application factory"
pattern) breaks that cycle cleanly.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

# Rate limiter: protects login/register endpoints from brute-force and
# automated credential-stuffing attacks by capping requests per IP.
limiter = Limiter(key_func=get_remote_address)
