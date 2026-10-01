"""
run.py
------
Entry point for local development.

    python run.py

For production, do NOT use Flask's built-in server (it's single-threaded
and not hardened for the open internet). Instead run via a WSGI server,
e.g.:
    gunicorn -w 4 -b 0.0.0.0:8000 "run:app"
"""

import os
from app import create_app

app = create_app(os.environ.get("FLASK_ENV", "development"))

if __name__ == "__main__":
    # debug=True enables the interactive debugger + auto-reload -
    # NEVER enable this in production (it allows arbitrary code
    # execution via the debugger console if an error page is reached).
    app.run(debug=app.config["DEBUG"], host="127.0.0.1", port=8000)
