"""
app/superadmin/routes.py
--------------------------
Highest privilege level. A super_admin can:
  - view a system-wide overview (counts of admins/students/courses)
  - create new admin accounts
  - activate/deactivate ANY account (including admins)

Every route below is wrapped with @roles_required(ROLE_SUPER_ADMIN), so
even if an admin or student guesses the URL, the decorator returns 403
before any view logic (or database query) runs.
"""

from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user

from app.extensions import db
from app.decorators import roles_required
from app.models import User, Course, Enrollment, ROLE_SUPER_ADMIN, ROLE_ADMIN, ROLE_STUDENT
from app.forms import CreateAdminForm

superadmin_bp = Blueprint(
    "superadmin", __name__, url_prefix="/superadmin", template_folder="../templates/superadmin"
)


@superadmin_bp.route("/dashboard")
@login_required
@roles_required(ROLE_SUPER_ADMIN)
def dashboard():
    stats = {
        "admin_count": User.query.filter_by(role=ROLE_ADMIN).count(),
        "student_count": User.query.filter_by(role=ROLE_STUDENT).count(),
        "course_count": Course.query.count(),
        "pending_enrollments": Enrollment.query.filter_by(status="pending").count(),
    }
    return render_template("superadmin/dashboard.html", stats=stats)


@superadmin_bp.route("/admins")
@login_required
@roles_required(ROLE_SUPER_ADMIN)
def list_admins():
    admins = User.query.filter_by(role=ROLE_ADMIN).order_by(User.created_at.desc()).all()
    return render_template("superadmin/admins.html", admins=admins)


@superadmin_bp.route("/admins/new", methods=["GET", "POST"])
@login_required
@roles_required(ROLE_SUPER_ADMIN)
def create_admin():
    form = CreateAdminForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash("Username already exists.", "danger")
            return render_template("superadmin/create_admin.html", form=form)
        if User.query.filter_by(email=form.email.data.lower()).first():
            flash("Email already registered.", "danger")
            return render_template("superadmin/create_admin.html", form=form)

        admin = User(
            full_name=form.full_name.data.strip(),
            username=form.username.data.strip(),
            email=form.email.data.lower().strip(),
            role=ROLE_ADMIN,                 # server decides the role, not the form
            created_by_id=current_user.id,    # audit trail: who granted this privilege
        )
        admin.set_password(form.password.data)
        db.session.add(admin)
        db.session.commit()
        flash(f"Admin account '{admin.username}' created.", "success")
        return redirect(url_for("superadmin.list_admins"))

    return render_template("superadmin/create_admin.html", form=form)


@superadmin_bp.route("/users/<int:user_id>/toggle-active", methods=["POST"])
@login_required
@roles_required(ROLE_SUPER_ADMIN)
def toggle_active(user_id):
    """Activate/deactivate any account. A deactivated user can no longer log in."""
    user = User.query.get_or_404(user_id)

    # Guard rail: a super_admin cannot deactivate their own account and
    # accidentally lock themselves out of the system.
    if user.id == current_user.id:
        flash("You cannot deactivate your own account.", "warning")
        return redirect(url_for("superadmin.list_admins"))

    user.is_active_account = not user.is_active_account
    db.session.commit()
    state = "activated" if user.is_active_account else "deactivated"
    flash(f"Account '{user.username}' {state}.", "info")

    # Send back to whichever list makes sense for that user's role.
    if user.role == ROLE_ADMIN:
        return redirect(url_for("superadmin.list_admins"))
    return redirect(url_for("superadmin.dashboard"))
