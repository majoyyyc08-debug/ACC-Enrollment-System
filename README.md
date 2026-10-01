# Enrollment System (Flask + SQLite + RBAC)

A scalable, role-based student enrollment system built with **Python/Flask**
(backend), **server-rendered HTML** (frontend, via Jinja2 templates), and
**SQLite** (database, via SQLAlchemy ORM).

---

## 1. Roles & Business Logic

| Role | Can do |
|---|---|
| **super_admin** | Create/deactivate **admin** accounts. View system-wide stats. (Exactly one seeded via `seed.py`; more created only by an existing super_admin.) |
| **admin** | Create/edit/enable/disable **courses**. Approve/reject **enrollment requests**. Deactivate **student** accounts. |
| **student** | Self-register. Browse active courses. Request enrollment. Withdraw their own pending/approved requests. |

**Enrollment lifecycle:**
```
pending --(admin approves, if seats available)--> approved
pending --(admin rejects)-------------------------> rejected
pending/approved --(student withdraws)------------> withdrawn
rejected/withdrawn --(student re-requests)---------> pending  (row is reused, not duplicated)
```

Key business rules enforced in code (see comments in `app/models.py`,
`app/admin/routes.py`, `app/student/routes.py`):
- A course cannot accept more **approved** students than its `capacity`.
- Capacity can't be edited below the number of currently approved students.
- A student can't submit two simultaneous *active* (pending/approved)
  requests for the same course - enforced both at the route level and by
  a DB `UNIQUE` constraint (defense in depth).
- Seat availability is re-checked at the moment of admin approval, not
  just when the student first requested it, to avoid overbooking races.

---

## 2. Architecture (why it's structured this way)

```
enrollment_system/
├── run.py                # entry point (dev server)
├── seed.py                # one-time: create tables + first super_admin
├── config.py              # environment-based configuration
├── requirements.txt
├── .env.example           # copy to .env
├── app/
│   ├── __init__.py        # APPLICATION FACTORY - create_app()
│   ├── extensions.py      # unbound extension instances (db, login, csrf, limiter)
│   ├── models.py           # SQLAlchemy models: User, Course, Enrollment
│   ├── forms.py            # WTForms - validation + CSRF
│   ├── decorators.py       # @roles_required(...) RBAC enforcement
│   ├── auth/routes.py       # /login /register /logout /change-password
│   ├── superadmin/routes.py # /superadmin/* (manage admins)
│   ├── admin/routes.py      # /admin/* (courses, enrollment review, students)
│   ├── student/routes.py    # /student/* (browse, enroll, withdraw)
│   ├── templates/           # Jinja2 HTML, split by area, extending base.html
│   └── static/css/style.css
└── instance/
    └── enrollment.db       # SQLite file (created automatically, gitignored)
```

This uses Flask's **Application Factory + Blueprints** pattern:
- `create_app()` builds and returns the app, instead of a bare
  module-level `app = Flask(__name__)`. This makes the app fully
  testable (`create_app("testing")` spins up an isolated, in-memory-DB
  copy) and avoids circular imports between extensions and models.
- Each role's routes live in their own **Blueprint** (`auth`,
  `superadmin`, `admin`, `student`) - a natural, scalable way to keep
  the codebase organized as more features are added. Need a new admin
  feature? It goes in `app/admin/`, full stop - no digging through one
  giant `routes.py`.

**Why SQLite here, and how this scales:** SQLAlchemy is used as the
data-access layer everywhere (never raw SQL strings), so if the project
outgrows SQLite, switching to Postgres/MySQL later is a **one-line
change** — just update `DATABASE_URL` in `.env`; no route or model code
changes required.

---

## 3. Security Summary

| Concern | Mitigation |
|---|---|
| Password storage | `werkzeug.security.generate_password_hash` (salted PBKDF2) - plaintext passwords are never stored or logged. |
| SQL Injection | 100% SQLAlchemy ORM - no string-concatenated queries anywhere. |
| CSRF | `Flask-WTF` CSRFProtect issues/validates a token on every form (`{{ form.hidden_tag() }}` or a manual `csrf_token()` hidden field). |
| Privilege escalation | Public `/register` is hard-coded server-side to create `role=student` only. Admin accounts can only be created by an authenticated `super_admin` route. |
| Broken access control (RBAC) | Every protected view is wrapped in `@roles_required(...)`, which checks `current_user.role` against an explicit allow-list and aborts `401`/`403` - not a redirect that could be silently bypassed. |
| IDOR (Insecure Direct Object Reference) | Student routes (`withdraw`, enrollment queries) always filter by `student_id == current_user.id`; admin routes verify the target row's role before mutating it. |
| Brute force / credential stuffing | `Flask-Limiter` rate-limits `/login` (15/min) and `/register` (10/hour) per IP. |
| Session hijacking | `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE=Lax`, `SESSION_COOKIE_SECURE` in production, and Flask-Login's `session_protection="strong"`. |
| XSS | Jinja2 auto-escapes all template output by default; no `|safe` filters used on user input anywhere. |
| Clickjacking / MIME sniffing | `X-Frame-Options: DENY` and `X-Content-Type-Options: nosniff` headers set on every response. |
| Secrets management | `SECRET_KEY` and DB URL loaded from environment variables via `.env` (gitignored); production config refuses to boot with a placeholder key. |
| Input validation | All form fields validated server-side with WTForms (`DataRequired`, `Length`, `Email`, `Regexp` whitelists) before touching the database. |
| Account lockout escape hatch | A super_admin cannot deactivate their own account (prevents accidental self-lockout). |

---

## 4. Step-by-Step: Running the Project

### Prerequisites
- Python 3.10+ installed
- (Recommended) a terminal with `pip` available

### Step 1 - Get the project files
Unzip/copy the `enrollment_system/` folder to your machine, then open a
terminal inside it.

### Step 2 - Create a virtual environment
```bash
python -m venv venv

# Activate it:
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate
```

### Step 3 - Install dependencies
```bash
pip install -r requirements.txt
```

### Step 4 - Configure environment variables
```bash
cp .env.example .env     # Windows: copy .env.example .env
```
Open `.env` and set a real `SECRET_KEY`. You can generate one with:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```
Paste the output as the value of `SECRET_KEY` in `.env`.

### Step 5 - Initialize the database + create the first Super Admin
```bash
python seed.py
```
This creates `instance/enrollment.db` and walks you through creating the
first `super_admin` account (interactive prompts for name, username,
email, password).

### Step 6 - Run the application
```bash
python run.py
```
You'll see something like:
```
 * Running on http://127.0.0.1:5000
```

### Step 7 - Use the app
1. Open **http://127.0.0.1:5000** in your browser.
2. **Log in** as the super_admin you just created.
3. Go to **Manage Admins → + New Admin** to create an admin account.
4. **Log out**, then **log in as that admin** to create courses
   (Courses → + New Course) with a code, title, and capacity.
5. **Log out**, then go to **Register** to create a student account.
6. Log in as the student → **Browse Courses** → **Enroll** in a course.
7. Log back in as the **admin** → **Enrollments** → **Review** → approve
   or reject the request.
8. Log back in as the **student** to see the updated status on
   **My Enrollments**.

### Step 8 (optional) - Run in "production mode" locally
```bash
export FLASK_ENV=production      # Windows: set FLASK_ENV=production
gunicorn -w 4 -b 0.0.0.0:8000 "run:app"
```
(Install gunicorn first: `pip install gunicorn` — Linux/macOS only; on
Windows use `waitress` instead: `pip install waitress` then
`waitress-serve --port=8000 run:app`.)

---

## 5. Extending This Project
- Add pagination to long tables (`Course.query.paginate(...)`).
- Add email notifications when an enrollment is approved/rejected.
- Add unit tests using `create_app("testing")` + pytest.
- Swap SQLite for Postgres by changing `DATABASE_URL` in `.env` only.
- Add an audit log table recording every admin/super_admin action.

## Project Status
ACC Enrollment System initial setup.
