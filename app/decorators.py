"""
decorators.py
-------------
Route-protection decorators implementing Role-Based Access Control (RBAC).

Flask-Login's `@login_required` only proves "someone is logged in" - it
says nothing about WHICH role that someone has. `@roles_required(...)`
adds the second layer: "logged in AND their role is one of these".

Stacking order matters:
    @app.route(...)
    @login_required
    @roles_required(ROLE_ADMIN)
    def view(): ...

Both checks run on EVERY request to the view - this is what stops, e.g.,
a logged-in student from hitting an admin-only URL directly by typing it
in the browser (a very common real-world attack: "forced browsing").
"""

from functools import wraps
from flask import abort
from flask_login import current_user


def roles_required(*allowed_roles):
    """
    Restrict a view to only the given roles.
    Usage: @roles_required(ROLE_SUPER_ADMIN, ROLE_ADMIN)

    Returns HTTP 403 (Forbidden) - NOT a redirect to login - because the
    problem here isn't "you're not authenticated", it's "you ARE
    authenticated but not allowed". Conflating the two would leak
    information about which URLs exist to unauthorized users.
    """

    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)  # Unauthorized - no identity at all
            if current_user.role not in allowed_roles:
                abort(403)  # Forbidden - identity known, insufficient privilege
            return view_func(*args, **kwargs)

        return wrapped_view

    return decorator


def active_account_required(view_func):
    """
    Extra guard: even a correctly-authenticated user with the right role
    should be blocked if their account was deactivated *after* their
    session cookie was already issued (Flask-Login's is_active check
    happens at login time, not on every request, so we re-check here for
    sensitive views).
    """

    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_active:
            abort(403)
        return view_func(*args, **kwargs)

    return wrapped_view
