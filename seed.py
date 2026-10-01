"""
seed.py
-------
Database setup and initial account creation.

Creates:
1. Database tables
2. First Super Admin account
3. First Admin account

Safe to re-run:
- Existing accounts are detected by username/email.
- No duplicate accounts will be created.
"""

import getpass

from app import create_app
from app.extensions import db
from app.models import User, ROLE_SUPER_ADMIN, ROLE_ADMIN


def create_account(role, role_name, default_username, default_email):
    """
    Create an administrator account if the username and email
    are not already registered.
    """

    # Check if the username already exists
    existing_username = User.query.filter_by(
        username=default_username
    ).first()

    if existing_username:
        print(
            f"{role_name} account already exists "
            f"with username '{default_username}'."
        )
        return

    # Check if the email already exists
    existing_email = User.query.filter_by(
        email=default_email.lower()
    ).first()

    if existing_email:
        print(
            f"An account already uses the email "
            f"'{default_email}'."
        )
        return

    print(f"\n--- Create {role_name} account ---")

    full_name = input(
        f"Full name [{role_name}]: "
    ).strip() or role_name

    username = input(
        f"Username [{default_username}]: "
    ).strip() or default_username

    email = input(
        f"Email [{default_email}]: "
    ).strip() or default_email

    # Check username again in case the user entered a custom one
    if User.query.filter_by(username=username).first():
        print(
            f"Error: username '{username}' is already registered."
        )
        return

    # Check email again in case the user entered a custom one
    email = email.lower()

    if User.query.filter_by(email=email).first():
        print(
            f"Error: email '{email}' is already registered."
        )
        return

    # Securely request the password
    password = getpass.getpass(
        "Password (min 8 chars): "
    )

    while len(password) < 8:
        print(
            "Password too short. "
            "Please use at least 8 characters."
        )

        password = getpass.getpass(
            "Password (min 8 chars): "
        )

    # Create the account
    user = User(
        full_name=full_name,
        username=username,
        email=email,
        role=role,
    )

    # Hash the password before storing it
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    print(
        f"\n{role_name} '{username}' "
        f"created successfully."
    )


def main():
    """
    Create database tables and initial administrator accounts.
    """

    app = create_app()

    with app.app_context():

        # Create all database tables
        db.create_all()

        print(
            "Database tables created "
            "(or already existed)."
        )

        # ---------------------------------
        # CREATE SUPER ADMIN
        # ---------------------------------

        create_account(
            ROLE_SUPER_ADMIN,
            "Super Admin",
            "superadmin",
            "superadmin@example.com",
        )

        # ---------------------------------
        # CREATE ADMIN
        # ---------------------------------

        create_account(
            ROLE_ADMIN,
            "Admin",
            "admin",
            "admin@example.com",
        )

        print("\n===================================")
        print("Initial accounts setup completed.")
        print("===================================")
        print()
        print("Available administrator accounts:")
        print("- Super Admin: superadmin")
        print("- Admin: admin")
        print()
        print("Run the application with:")
        print("python run.py")


if __name__ == "__main__":
    main()