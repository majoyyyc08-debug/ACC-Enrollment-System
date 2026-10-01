"""
app/admin/routes.py
---------------------
Mid-privilege role. An admin can:
  - create/edit courses and set their capacity
  - review pending enrollment requests (approve/reject)
  - view/deactivate student accounts

Admins CANNOT create other admins or super_admins - that stays exclusive
to /superadmin (enforced simply by not exposing that route here at all,
plus the roles_required decorator on every view below).
"""

from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, abort
from flask_login import login_required, current_user

from app.extensions import db
from app.decorators import roles_required
from app.models import (
    Course,
    Enrollment,
    User,
    ROLE_ADMIN,
    ROLE_STUDENT,
    STATUS_PENDING,
    STATUS_APPROVED,
)
from app.forms import CourseForm, EnrollmentReviewForm

admin_bp = Blueprint(
    "admin", __name__, url_prefix="/admin", template_folder="../templates/admin"
)


@admin_bp.route("/dashboard")
@login_required
@roles_required(ROLE_ADMIN)
def dashboard():
    stats = {
        "course_count": Course.query.count(),
        "student_count": User.query.filter_by(role=ROLE_STUDENT).count(),
        "pending_count": Enrollment.query.filter_by(status=STATUS_PENDING).count(),
    }
    recent_pending = (
        Enrollment.query.filter_by(status=STATUS_PENDING)
        .order_by(Enrollment.requested_at.desc())
        .limit(5)
        .all()
    )
    return render_template("admin/dashboard.html", stats=stats, recent_pending=recent_pending)


# ---------------------------------------------------------------------
# Course management
# ---------------------------------------------------------------------

@admin_bp.route("/courses")
@login_required
@roles_required(ROLE_ADMIN)
def list_courses():
    courses = Course.query.order_by(Course.created_at.desc()).all()
    return render_template("admin/courses.html", courses=courses)


@admin_bp.route("/courses/new", methods=["GET", "POST"])
@login_required
@roles_required(ROLE_ADMIN)
def create_course():
    form = CourseForm()
    if form.validate_on_submit():
        if Course.query.filter_by(code=form.code.data.upper()).first():
            flash("A course with that code already exists.", "danger")
            return render_template("admin/course_form.html", form=form, mode="Create")

        course = Course(
            code=form.code.data.upper().strip(),
            title=form.title.data.strip(),
            description=form.description.data.strip() if form.description.data else "",
            capacity=form.capacity.data,
            created_by_id=current_user.id,
        )
        db.session.add(course)
        db.session.commit()
        flash(f"Course '{course.code}' created.", "success")
        return redirect(url_for("admin.list_courses"))

    return render_template("admin/course_form.html", form=form, mode="Create")


@admin_bp.route("/courses/<int:course_id>/edit", methods=["GET", "POST"])
@login_required
@roles_required(ROLE_ADMIN)
def edit_course(course_id):
    course = Course.query.get_or_404(course_id)
    form = CourseForm(obj=course)

    if form.validate_on_submit():
        # Prevent shrinking capacity below the number of already-approved
        # students - a business rule that protects data integrity.
        if form.capacity.data < course.approved_count():
            flash(
                f"Cannot set capacity below {course.approved_count()} "
                f"(current approved students).",
                "danger",
            )
            return render_template("admin/course_form.html", form=form, mode="Edit", course=course)

        course.code = form.code.data.upper().strip()
        course.title = form.title.data.strip()
        course.description = form.description.data.strip() if form.description.data else ""
        course.capacity = form.capacity.data
        db.session.commit()
        flash("Course updated.", "success")
        return redirect(url_for("admin.list_courses"))

    return render_template("admin/course_form.html", form=form, mode="Edit", course=course)


@admin_bp.route("/courses/<int:course_id>/toggle-active", methods=["POST"])
@login_required
@roles_required(ROLE_ADMIN)
def toggle_course_active(course_id):
    course = Course.query.get_or_404(course_id)
    course.is_active = not course.is_active
    db.session.commit()
    flash(f"Course '{course.code}' is now {'active' if course.is_active else 'inactive'}.", "info")
    return redirect(url_for("admin.list_courses"))


# ---------------------------------------------------------------------
# Enrollment review
# ---------------------------------------------------------------------

@admin_bp.route("/enrollments")
@login_required
@roles_required(ROLE_ADMIN)
def list_enrollments():
    pending = (
        Enrollment.query.filter_by(status=STATUS_PENDING)
        .order_by(Enrollment.requested_at.asc())
        .all()
    )
    reviewed = (
        Enrollment.query.filter(Enrollment.status != STATUS_PENDING)
        .order_by(Enrollment.reviewed_at.desc())
        .limit(25)
        .all()
    )
    return render_template("admin/enrollments.html", pending=pending, reviewed=reviewed)


@admin_bp.route("/enrollments/<int:enrollment_id>/review", methods=["GET", "POST"])
@login_required
@roles_required(ROLE_ADMIN)
def review_enrollment(enrollment_id):
    enrollment = Enrollment.query.get_or_404(enrollment_id)

    if enrollment.status != STATUS_PENDING:
        flash("This request has already been reviewed.", "warning")
        return redirect(url_for("admin.list_enrollments"))

    form = EnrollmentReviewForm()
    if form.validate_on_submit():
        # Re-check capacity at the moment of approval (not just when the
        # student requested it) - protects against a race where the
        # course filled up between request and review.
        if form.decision.data == "approved" and enrollment.course.is_full():
            flash("Cannot approve: course is at full capacity.", "danger")
            return render_template(
                "admin/review_enrollment.html", form=form, enrollment=enrollment
            )

        enrollment.status = form.decision.data
        enrollment.remarks = form.remarks.data.strip() if form.remarks.data else ""
        enrollment.reviewed_by_id = current_user.id
        enrollment.reviewed_at = datetime.utcnow()
        db.session.commit()
        flash(f"Enrollment {form.decision.data}.", "success")
        return redirect(url_for("admin.list_enrollments"))

    return render_template("admin/review_enrollment.html", form=form, enrollment=enrollment)


# ---------------------------------------------------------------------
# Student account oversight
# ---------------------------------------------------------------------

@admin_bp.route("/students")
@login_required
@roles_required(ROLE_ADMIN)
def list_students():
    students = User.query.filter_by(role=ROLE_STUDENT).order_by(User.created_at.desc()).all()
    return render_template("admin/students.html", students=students)


@admin_bp.route("/students/<int:user_id>/toggle-active", methods=["POST"])
@login_required
@roles_required(ROLE_ADMIN)
def toggle_student_active(user_id):
    student = User.query.get_or_404(user_id)
    if student.role != ROLE_STUDENT:
        # An admin route must never be able to touch a non-student
        # account - stops privilege abuse via a crafted user_id.
        abort(403)

    student.is_active_account = not student.is_active_account
    db.session.commit()
    state = "activated" if student.is_active_account else "deactivated"
    flash(f"Student '{student.username}' {state}.", "info")
    return redirect(url_for("admin.list_students"))
