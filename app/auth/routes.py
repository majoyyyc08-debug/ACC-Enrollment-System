"""
app/auth/routes.py
-------------------
Public-facing authentication endpoints shared by ALL roles:
    /register  - public sign-up, ALWAYS creates a `student` account.
                 (Admins/super-admins are never self-registerable - see
                 the security note in register() below.)
    /login     - single login form for every role; after success we
                 redirect based on `current_user.role`.
    /logout
    /change-password
"""

from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user

from app.extensions import db, limiter
from app.models import User, ROLE_STUDENT
from app.forms import LoginForm, StudentRegistrationForm, ChangePasswordForm

auth_bp = Blueprint("auth", __name__, template_folder="../templates/auth")


def _redirect_for_role(user: User):
    """Single source of truth for 'where does each role land after login'."""
    if user.is_super_admin():
        return redirect(url_for("superadmin.dashboard"))
    if user.is_admin():
        return redirect(url_for("admin.dashboard"))
    return redirect(url_for("student.dashboard"))


@auth_bp.route("/", methods=["GET"])
def index():
    if current_user.is_authenticated:
        return _redirect_for_role(current_user)
    return redirect(url_for("auth.login"))


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour")  # slow down automated mass-account-creation bots
def register():
    """
    SECURITY NOTE - privilege escalation prevention:
    This is the ONLY public entry point for creating an account, and it
    is hard-coded to role=student. There is no form field the client can
    submit to become an admin/super_admin here - that choice is made
    server-side, not read from user input. Admin accounts can only be
    created by a super_admin via app/superadmin/routes.py, which itself
    requires an authenticated super_admin session.
    """
    if current_user.is_authenticated:
        return _redirect_for_role(current_user)

    form = StudentRegistrationForm()
    if form.validate_on_submit():
        # Uniqueness checks (also enforced at DB level as a second layer).
        if User.query.filter_by(username=form.username.data).first():
            flash("That username is already taken.", "danger")
            return render_template("auth/register.html", form=form)
        if User.query.filter_by(email=form.email.data.lower()).first():
            flash("That email is already registered.", "danger")
            return render_template("auth/register.html", form=form)

        user = User(
            full_name=form.full_name.data.strip(),
            username=form.username.data.strip(),
            email=form.email.data.lower().strip(),
            role=ROLE_STUDENT,
        )
        user.set_password(form.password.data)  # hashed, never stored raw
        db.session.add(user)
        db.session.commit()

        flash("Account created! You can now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("15 per minute")  # brute-force / credential-stuffing throttle
def login():
    if current_user.is_authenticated:
        return _redirect_for_role(current_user)

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.strip()).first()

        # IMPORTANT: we run check_password even when user is None (against
        # a dummy hash) in a real high-security system to keep timing
        # constant and avoid username enumeration via response-time
        # differences. For clarity here we keep the straightforward form,
        # but always return the SAME generic error message either way so
        # we don't reveal whether the username or the password was wrong.
        if user and user.check_password(form.password.data):
            if not user.is_active:
                flash("This account has been deactivated. Contact an administrator.", "danger")
                return render_template("auth/login.html", form=form)

            login_user(user, remember=False)  # no persistent 'remember me' cookie by default
            flash(f"Welcome back, {user.full_name}!", "success")
            return _redirect_for_role(user)

        flash("Invalid username or password.", "danger")

    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash("Current password is incorrect.", "danger")
            return render_template("auth/change_password.html", form=form)

        current_user.set_password(form.new_password.data)
        db.session.commit()
        flash("Password updated successfully.", "success")
        return _redirect_for_role(current_user)

    return render_template("auth/change_password.html", form=form)
