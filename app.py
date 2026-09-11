"""
Small Flask test application for agentic QA testing.

Pages:
  GET  /                 -> redirects to /login
  GET  /register         -> registration page (with captcha)
  GET  /login            -> login page (with captcha)
  GET  /dashboard        -> protected dashboard page (requires login)
  GET  /forgot-password  -> request a password reset
  GET  /reset-password   -> set a new password using a token (?token=...)

API endpoints:
  GET  /api/captcha            -> issue a new math captcha challenge (JSON)
  POST /api/register           -> create a new user account (requires captcha)
  POST /api/login               -> authenticate and start a session (requires captcha)
  GET  /api/profile             -> return the logged-in user's profile (protected)
  POST /api/logout              -> end the session
  POST /api/forgot-password     -> request a reset token for an email
  POST /api/reset-password      -> consume a reset token and set a new password

Data is stored in a local SQLite file (app.db), created automatically on first run.
"""

import re
import secrets
import random
import time
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, session, redirect, url_for, render_template
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "app.db"

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key-change-me"  # fine for a local test app

CAPTCHA_TTL_SECONDS = 5 * 60          # captcha challenge expires after 5 minutes
RESET_TOKEN_TTL_MINUTES = 30          # password reset link expires after 30 minutes


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        """
    )
    conn.commit()
    conn.close()


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------------------------------------------------------------------------
# Captcha helpers (simple math challenge, tied to the session, single-use)
# ---------------------------------------------------------------------------
def issue_captcha():
    a, b = random.randint(1, 9), random.randint(1, 9)
    op = random.choice(["+", "-"])
    if op == "-" and b > a:
        a, b = b, a  # keep answers non-negative
    answer = a + b if op == "+" else a - b

    challenge_id = secrets.token_hex(8)
    session["captcha_id"] = challenge_id
    session["captcha_answer"] = answer
    session["captcha_expires_at"] = time.time() + CAPTCHA_TTL_SECONDS

    return {"captcha_id": challenge_id, "question": f"What is {a} {op} {b}?"}


def verify_captcha(captcha_id, answer):
    """Validates and consumes (single-use) the captcha stored in the session."""
    expected_id = session.get("captcha_id")
    expected_answer = session.get("captcha_answer")
    expires_at = session.get("captcha_expires_at")

    if not expected_id or expected_answer is None or expires_at is None:
        return False, "no active captcha challenge; request a new one"

    if time.time() > expires_at:
        _clear_captcha()
        return False, "captcha expired; request a new one"

    if captcha_id != expected_id:
        return False, "captcha_id does not match the active challenge"

    try:
        correct = int(answer) == int(expected_answer)
    except (TypeError, ValueError):
        correct = False

    # Single-use: consume the challenge regardless of outcome so it can't be replayed
    _clear_captcha()

    if not correct:
        return False, "incorrect captcha answer"

    return True, None


def _clear_captcha():
    session.pop("captcha_id", None)
    session.pop("captcha_answer", None)
    session.pop("captcha_expires_at", None)


# ---------------------------------------------------------------------------
# Page routes (HTML)
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login_page"))


@app.route("/register")
def register_page():
    return render_template("register.html")


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        return redirect(url_for("login_page"))
    return render_template("dashboard.html")


@app.route("/forgot-password")
def forgot_password_page():
    return render_template("forgot_password.html")


@app.route("/reset-password")
def reset_password_page():
    token = request.args.get("token", "")
    return render_template("reset_password.html", token=token)


# ---------------------------------------------------------------------------
# API routes (JSON)
# ---------------------------------------------------------------------------
@app.route("/api/captcha", methods=["GET"])
def api_captcha():
    return jsonify({"ok": True, **issue_captcha()}), 200


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or {}
    full_name = (data.get("full_name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    captcha_id = data.get("captcha_id") or ""
    captcha_answer = data.get("captcha_answer")

    captcha_ok, captcha_err = verify_captcha(captcha_id, captcha_answer)
    if not captcha_ok:
        return jsonify({"ok": False, "error": captcha_err}), 400

    if not full_name or not email or not password:
        return jsonify({"ok": False, "error": "full_name, email and password are required"}), 400

    if not EMAIL_RE.match(email):
        return jsonify({"ok": False, "error": "invalid email format"}), 400

    if len(password) < 6:
        return jsonify({"ok": False, "error": "password must be at least 6 characters"}), 400

    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        conn.close()
        return jsonify({"ok": False, "error": "an account with this email already exists"}), 409

    conn.execute(
        "INSERT INTO users (full_name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (full_name, email, generate_password_hash(password), datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()

    return jsonify({"ok": True, "message": "account created successfully"}), 201


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    captcha_id = data.get("captcha_id") or ""
    captcha_answer = data.get("captcha_answer")

    captcha_ok, captcha_err = verify_captcha(captcha_id, captcha_answer)
    if not captcha_ok:
        return jsonify({"ok": False, "error": captcha_err}), 400

    if not email or not password:
        return jsonify({"ok": False, "error": "email and password are required"}), 400

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()

    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"ok": False, "error": "invalid email or password"}), 401

    session["user_id"] = user["id"]
    session["full_name"] = user["full_name"]

    return jsonify({"ok": True, "message": "login successful", "redirect": "/dashboard"}), 200


@app.route("/api/profile", methods=["GET"])
def api_profile():
    if not session.get("user_id"):
        return jsonify({"ok": False, "error": "not authenticated"}), 401

    conn = get_db()
    user = conn.execute(
        "SELECT id, full_name, email, created_at FROM users WHERE id = ?",
        (session["user_id"],),
    ).fetchone()
    conn.close()

    if not user:
        session.clear()
        return jsonify({"ok": False, "error": "user not found"}), 404

    return jsonify(
        {
            "ok": True,
            "user": {
                "id": user["id"],
                "full_name": user["full_name"],
                "email": user["email"],
                "created_at": user["created_at"],
            },
        }
    ), 200


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True, "message": "logged out"}), 200


@app.route("/api/forgot-password", methods=["POST"])
def api_forgot_password():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    if not email or not EMAIL_RE.match(email):
        return jsonify({"ok": False, "error": "a valid email is required"}), 400

    conn = get_db()
    user = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()

    # Generic response either way, to avoid leaking whether an email is registered.
    generic_message = "if that email is registered, a reset link has been generated"

    if not user:
        conn.close()
        return jsonify({"ok": True, "message": generic_message}), 200

    token = secrets.token_urlsafe(32)
    created_at = datetime.utcnow()
    expires_at = created_at + timedelta(minutes=RESET_TOKEN_TTL_MINUTES)

    conn.execute(
        "INSERT INTO password_reset_tokens (user_id, token, created_at, expires_at, used) VALUES (?, ?, ?, ?, 0)",
        (user["id"], token, created_at.isoformat(), expires_at.isoformat()),
    )
    conn.commit()
    conn.close()

    # NOTE: This app has no real email server. In production the link below would be
    # emailed to the user; here it's returned directly so it can be tested end-to-end.
    reset_link = url_for("reset_password_page", token=token, _external=True)

    return jsonify(
        {
            "ok": True,
            "message": generic_message,
            "dev_note": "no email server configured; reset link is returned directly for testing",
            "reset_link": reset_link,
            "reset_token": token,
            "expires_at": expires_at.isoformat(),
        }
    ), 200


@app.route("/api/reset-password", methods=["POST"])
def api_reset_password():
    data = request.get_json(silent=True) or {}
    token = data.get("token") or ""
    new_password = data.get("new_password") or ""
    confirm_password = data.get("confirm_password") or ""

    if not token:
        return jsonify({"ok": False, "error": "reset token is required"}), 400

    if not new_password or not confirm_password:
        return jsonify({"ok": False, "error": "new_password and confirm_password are required"}), 400

    if new_password != confirm_password:
        return jsonify({"ok": False, "error": "passwords do not match"}), 400

    if len(new_password) < 6:
        return jsonify({"ok": False, "error": "password must be at least 6 characters"}), 400

    conn = get_db()
    row = conn.execute(
        "SELECT * FROM password_reset_tokens WHERE token = ?", (token,)
    ).fetchone()

    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "invalid reset token"}), 400

    if row["used"]:
        conn.close()
        return jsonify({"ok": False, "error": "this reset token has already been used"}), 400

    expires_at = datetime.fromisoformat(row["expires_at"])
    if datetime.utcnow() > expires_at:
        conn.close()
        return jsonify({"ok": False, "error": "this reset token has expired"}), 400

    conn.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_password), row["user_id"]),
    )
    conn.execute("UPDATE password_reset_tokens SET used = 1 WHERE id = ?", (row["id"],))
    conn.commit()
    conn.close()

    return jsonify({"ok": True, "message": "password has been reset successfully"}), 200


init_db()  # ensure tables exist whether run via `python app.py` or a WSGI server like gunicorn

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
