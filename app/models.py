"""
models.py
---------
Database schema (SQLAlchemy ORM models) + the core business rules that
belong to the data layer (e.g. "a course can't accept more students than
its capacity").

Using an ORM instead of raw `sqlite3.execute("...")` string-built queries
is itself a major security control: SQLAlchemy always parameterizes
queries, so user input can never be concatenated into SQL and cause a
SQL-injection vulnerability.

ROLE-BASED ACCESS CONTROL (RBAC) MODEL
---------------------------------------
Three roles, most -> least privileged:
  1. super_admin - manages Admin accounts. There is exactly one "seed"
     super_admin created by seed.py; more can be created only by an
     existing super_admin.
  2. admin       - manages Courses and reviews/approves Student
     enrollments. Created only by a super_admin.
  3. student     - registers themselves (public sign-up), can browse
     courses and submit/withdraw their own enrollment requests only.

Role is stored as a plain string column constrained by a CHECK constraint
at the DB level AND validated again in the application layer (defense in
depth: never trust a single layer of validation).
"""

from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from sqlalchemy import CheckConstraint, UniqueConstraint

from app.extensions import db

# Centralized role constants so we never mistype a role string anywhere
# in the codebase (routes, decorators, templates all import these).
ROLE_SUPER_ADMIN = "super_admin"
ROLE_ADMIN = "admin"
ROLE_STUDENT = "student"
ALL_ROLES = (ROLE_SUPER_ADMIN, ROLE_ADMIN, ROLE_STUDENT)

STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
STATUS_WITHDRAWN = "withdrawn"
ALL_STATUSES = (STATUS_PENDING, STATUS_APPROVED, STATUS_REJECTED, STATUS_WITHDRAWN)


class User(UserMixin, db.Model):
    """
    A single account table for all three roles keeps auth logic (login,
    password reset, session handling) in ONE place instead of duplicating
    it per role. `UserMixin` (from Flask-Login) supplies the
    is_authenticated / is_active / get_id() interface Flask-Login needs.
    """

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(f"role IN {ALL_ROLES}", name="ck_users_role_valid"),
    )

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)

    # We NEVER store the plaintext password. `password_hash` holds a
    # salted hash produced by Werkzeug's `generate_password_hash`
    # (PBKDF2-SHA256 by default). Even if the database leaks, raw
    # passwords are not recoverable.
    password_hash = db.Column(db.String(255), nullable=False)

    role = db.Column(db.String(20), nullable=False, default=ROLE_STUDENT)
    full_name = db.Column(db.String(120), nullable=False)

    is_active_account = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Who created this account (super_admin creates admins; admin/self
    # creates students). Nullable because the very first super_admin is
    # created by the seed script with no creator.
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    # ---- relationships ----
    enrollments = db.relationship(
        "Enrollment",
        foreign_keys="Enrollment.student_id",
        back_populates="student",
        cascade="all, delete-orphan",
    )

    # ---- password helpers ----
    def set_password(self, raw_password: str) -> None:
        """Hash and store a new password. Never assign password_hash directly."""
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        """Verify a plaintext attempt against the stored hash (constant-time compare)."""
        return check_password_hash(self.password_hash, raw_password)

    # ---- Flask-Login required overrides ----
    def get_id(self):
        # Flask-Login stores this in the session cookie to identify the user.
        return str(self.id)

    @property
    def is_active(self):
        # Overrides UserMixin.is_active: a deactivated account (e.g. a
        # student suspended by an admin) can no longer log in even with
        # the correct password.
        return self.is_active_account

    # ---- role helpers used throughout routes/templates ----
    def is_super_admin(self):
        return self.role == ROLE_SUPER_ADMIN

    def is_admin(self):
        return self.role == ROLE_ADMIN

    def is_student(self):
        return self.role == ROLE_STUDENT

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


class Course(db.Model):
    """A course/program that students can request enrollment into."""

    __tablename__ = "courses"

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    capacity = db.Column(db.Integer, nullable=False, default=30)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    enrollments = db.relationship(
        "Enrollment", back_populates="course", cascade="all, delete-orphan"
    )

    def approved_count(self) -> int:
        """How many students currently occupy a seat in this course."""
        return sum(1 for e in self.enrollments if e.status == STATUS_APPROVED)

    def seats_remaining(self) -> int:
        return max(self.capacity - self.approved_count(), 0)

    def is_full(self) -> bool:
        return self.seats_remaining() <= 0

    def __repr__(self):
        return f"<Course {self.code}>"


class Enrollment(db.Model):
    """
    A student's request to join a course, and its lifecycle:
        pending -> approved   (admin approves, if a seat is free)
        pending -> rejected   (admin rejects)
        pending -> withdrawn  (student cancels their own request)
        approved -> withdrawn (student drops the course)

    A UNIQUE constraint prevents a student from submitting duplicate
    *active* requests for the same course (business rule enforced at the
    DB layer as a last line of defense, in addition to the check we do
    in the route).
    """

    __tablename__ = "enrollments"
    __table_args__ = (
        UniqueConstraint("student_id", "course_id", name="uq_student_course"),
        CheckConstraint(f"status IN {ALL_STATUSES}", name="ck_enrollment_status_valid"),
    )

    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey("courses.id"), nullable=False)
    status = db.Column(db.String(20), nullable=False, default=STATUS_PENDING)

    requested_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    reviewed_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    remarks = db.Column(db.String(255), nullable=True)

    student = db.relationship(
        "User", foreign_keys=[student_id], back_populates="enrollments"
    )
    course = db.relationship("Course", back_populates="enrollments")
    reviewer = db.relationship("User", foreign_keys=[reviewed_by_id])

    def __repr__(self):
        return f"<Enrollment student={self.student_id} course={self.course_id} {self.status}>"
