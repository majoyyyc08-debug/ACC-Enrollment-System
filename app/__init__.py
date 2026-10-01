"""
app/__init__.py
----------------
The Application Factory.

Why a factory function instead of a bare module-level `app = Flask(__name__)`?
- Testability: tests can call `create_app("testing")` to get a fresh app
  bound to an in-memory database, fully isolated from the dev/prod app.
- Avoids circular imports: extensions are created unbound in
  extensions.py, and only *attached* to a concrete app here, after all
  blueprints/models have been imported.
"""

import os
from flask import Flask, render_template
from config import config_by_name
from app.extensions import db, login_manager, csrf, limiter


def create_app(config_name: str | None = None) -> Flask:
    config_name = config_name or os.environ.get("FLASK_ENV", "development")

    app = Flask(__name__)
    app.config.from_object(config_by_name[config_name])

    # Make sure the /instance folder (holds the SQLite file) exists.
    os.makedirs(app.instance_path, exist_ok=True)

    # ---- bind extensions to this app instance ----
    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = "auth.login"          # where @login_required redirects
    login_manager.login_message_category = "warning"
    login_manager.session_protection = "strong"        # ties session to browser fingerprint

    from app.models import User

    @login_manager.user_loader
    def load_user(user_id):
        # Flask-Login calls this on every request to rehydrate `current_user`
        # from the id stored in the (signed) session cookie.
        return db.session.get(User, int(user_id))

    # ---- register blueprints (one per role/area = clean separation) ----
    from app.auth.routes import auth_bp
    from app.superadmin.routes import superadmin_bp
    from app.admin.routes import admin_bp
    from app.student.routes import student_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(superadmin_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(student_bp)

    # ---- security headers on every response ----
    @app.after_request
    def set_security_headers(response):
        # Defense-in-depth headers. None of these replace proper input
        # validation, but they reduce the blast radius of certain classes
        # of bugs (clickjacking, MIME sniffing, XSS).
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        return response

    # ---- friendly error pages instead of leaking stack traces ----
    @app.errorhandler(403)
    def forbidden(e):
        return render_template("errors.html", code=403, message="You don't have permission to view this page."), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors.html", code=404, message="Page not found."), 404

    @app.errorhandler(401)
    def unauthorized(e):
        return render_template("errors.html", code=401, message="Please log in to continue."), 401

    return app
