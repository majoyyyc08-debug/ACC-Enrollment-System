"""
forms.py
--------
Flask-WTF form classes.

Why WTForms instead of reading request.form directly?
1. CSRF: Flask-WTF automatically embeds and validates a per-session CSRF
   token on every FlaskForm, blocking Cross-Site Request Forgery attacks
   (a malicious site tricking a logged-in user's browser into submitting
   a request to our app).
2. Server-side validation: length limits, required fields, email format,
   and "passwords match" are all enforced here BEFORE any data reaches
   the database - never trust client-side (HTML/JS) validation alone,
   since it's trivial to bypass with curl/Postman.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, IntegerField, TextAreaField
from wtforms.validators import (
    DataRequired,
    Email,
    Length,
    EqualTo,
    NumberRange,
    Regexp,
)


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=80)])
    password = PasswordField("Password", validators=[DataRequired()])


class StudentRegistrationForm(FlaskForm):
    """Public self-registration - always creates role=student (see routes)."""

    full_name = StringField("Full Name", validators=[DataRequired(), Length(max=120)])
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=80),
            # Whitelisting allowed characters blocks attempts to smuggle
            # markup/script or path characters into the username field.
            Regexp(r"^[A-Za-z0-9_.]+$", message="Letters, numbers, dot and underscore only."),
        ],
    )
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField(
        "Password", validators=[DataRequired(), Length(min=8, message="Minimum 8 characters.")]
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )


class CreateAdminForm(FlaskForm):
    """Used by a super_admin to create a new admin account."""

    full_name = StringField("Full Name", validators=[DataRequired(), Length(max=120)])
    username = StringField(
        "Username",
        validators=[DataRequired(), Length(min=3, max=80), Regexp(r"^[A-Za-z0-9_.]+$")],
    )
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Temporary Password", validators=[DataRequired(), Length(min=8)])


class CourseForm(FlaskForm):
    """Used by an admin to create/edit a course."""

    code = StringField(
        "Course Code",
        validators=[DataRequired(), Length(max=20), Regexp(r"^[A-Za-z0-9\-]+$")],
    )
    title = StringField("Title", validators=[DataRequired(), Length(max=150)])
    description = TextAreaField("Description", validators=[Length(max=2000)])
    capacity = IntegerField(
        "Capacity", validators=[DataRequired(), NumberRange(min=1, max=1000)]
    )


class EnrollmentReviewForm(FlaskForm):
    """Used by an admin to approve/reject a pending enrollment."""

    decision = SelectField(
        "Decision", choices=[("approved", "Approve"), ("rejected", "Reject")]
    )
    remarks = StringField("Remarks", validators=[Length(max=255)])


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current Password", validators=[DataRequired()])
    new_password = PasswordField(
        "New Password", validators=[DataRequired(), Length(min=8)]
    )
    confirm_new_password = PasswordField(
        "Confirm New Password",
        validators=[DataRequired(), EqualTo("new_password")],
    )
