"""
app/student/routes.py
------------------------
Lowest-privilege role. A student can:
  - browse active courses and available seats
  - request enrollment into a course
  - view the status of their own requests, and withdraw a pending one

SECURITY NOTE - "Insecure Direct Object Reference" (IDOR) prevention:
Every query below that touches an Enrollment is filtered by
`student_id=current_user.id`. This stops Student A from viewing or
cancelling Student B's enrollment just by guessing/incrementing the
enrollment id in the URL - a classic and very common web vulnerability.
"""

from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, abort
from flask_login import login_required, current_user

from app.extensions import db
from app.decorators import roles_required
from app.models import Course, Enrollment, ROLE_STUDENT, STATUS_PENDING, STATUS_APPROVED, STATUS_WITHDRAWN

student_bp = Blueprint(
    "student", __name__, url_prefix="/student", template_folder="../templates/student"
)


@student_bp.route("/dashboard")
@login_required
@roles_required(ROLE_STUDENT)
def dashboard():
    my_enrollments = (
        Enrollment.query.filter_by(student_id=current_user.id)
        .order_by(Enrollment.requested_at.desc())
        .all()
    )
    return render_template("student/dashboard.html", enrollments=my_enrollments)


@student_bp.route("/courses")
@login_required
@roles_required(ROLE_STUDENT)
def browse_courses():
    courses = Course.query.filter_by(is_active=True).order_by(Course.title.asc()).all()

    # Pre-compute which courses this student already has an ACTIVE
    # (pending/approved) request for, so the template can disable the
    # "Enroll" button instead of letting them submit duplicates.
    active_statuses = (STATUS_PENDING, STATUS_APPROVED)
    my_active_course_ids = {
        e.course_id
        for e in Enrollment.query.filter_by(student_id=current_user.id)
        .filter(Enrollment.status.in_(active_statuses))
        .all()
    }
    return render_template(
        "student/courses.html", courses=courses, my_active_course_ids=my_active_course_ids
    )


@student_bp.route("/courses/<int:course_id>/enroll", methods=["POST"])
@login_required
@roles_required(ROLE_STUDENT)
def enroll(course_id):
    course = Course.query.get_or_404(course_id)

    if not course.is_active:
        flash("This course is not currently open for enrollment.", "danger")
        return redirect(url_for("student.browse_courses"))

    if course.is_full():
        flash("Sorry, this course is at full capacity.", "warning")
        return redirect(url_for("student.browse_courses"))

    # Business rule: no duplicate active (pending/approved) requests for
    # the same course. Checked here for a friendly message, AND enforced
    # at the DB layer via the UniqueConstraint in models.py as a backstop.
    existing = Enrollment.query.filter_by(
        student_id=current_user.id, course_id=course.id
    ).first()
    if existing and existing.status in (STATUS_PENDING, STATUS_APPROVED):
        flash("You already have an active request for this course.", "warning")
        return redirect(url_for("student.browse_courses"))

    if existing:
        # A previous request was rejected/withdrawn - allow re-requesting
        # by resetting that same row instead of creating duplicates.
        existing.status = STATUS_PENDING
        existing.requested_at = datetime.utcnow()
        existing.reviewed_at = None
        existing.reviewed_by_id = None
        existing.remarks = ""
    else:
        existing = Enrollment(student_id=current_user.id, course_id=course.id)
        db.session.add(existing)

    db.session.commit()
    flash(f"Enrollment request submitted for {course.code}.", "success")
    return redirect(url_for("student.dashboard"))


@student_bp.route("/enrollments/<int:enrollment_id>/withdraw", methods=["POST"])
@login_required
@roles_required(ROLE_STUDENT)
def withdraw(enrollment_id):
    enrollment = Enrollment.query.get_or_404(enrollment_id)

    # IDOR guard: reject outright if this enrollment doesn't belong to
    # the currently logged-in student, regardless of role.
    if enrollment.student_id != current_user.id:
        abort(403)

    if enrollment.status not in (STATUS_PENDING, STATUS_APPROVED):
        flash("This request can no longer be withdrawn.", "warning")
        return redirect(url_for("student.dashboard"))

    enrollment.status = STATUS_WITHDRAWN
    enrollment.reviewed_at = datetime.utcnow()
    db.session.commit()
    flash("Enrollment withdrawn.", "info")
    return redirect(url_for("student.dashboard"))
