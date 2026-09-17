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
  GET  /api/captcha
  POST /api/register
  POST /api/login
  GET  /api/profile
  POST /api/logout
  POST /api/forgot-password
  POST /api/reset-password

Database:
  PostgreSQL
"""

import os
import re
import secrets
import random
import time

from dotenv import load_dotenv
load_dotenv()

from datetime import datetime, timedelta

import psycopg
from psycopg.rows import dict_row

from flask import (
    Flask,
    request,
    jsonify,
    session,
    redirect,
    url_for,
    render_template,
)

from werkzeug.security import generate_password_hash, check_password_hash


# ---------------------------------------------------------------------------
# Flask configuration
# ---------------------------------------------------------------------------

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "dev-secret-key-change-me"
)

CAPTCHA_TTL_SECONDS = 5 * 60
RESET_TOKEN_TTL_MINUTES = 30


# ---------------------------------------------------------------------------
# PostgreSQL configuration
# ---------------------------------------------------------------------------

def get_db():
    """
    Create and return a PostgreSQL database connection
    using individual DATABASE_* environment variables.
    """

    required = [
        "DATABASE_NAME",
        "DATABASE_USER",
        "DATABASE_PASSWORD",
        "DATABASE_HOST",
        "DATABASE_PORT",
    ]
    missing = [name for name in required if not os.environ.get(name)]

    if missing:
        raise RuntimeError(
            f"Missing required environment variable(s): {', '.join(missing)}"
        )

    return psycopg.connect(
        dbname=os.environ.get("DATABASE_NAME"),
        user=os.environ.get("DATABASE_USER"),
        password=os.environ.get("DATABASE_PASSWORD"),
        host=os.environ.get("DATABASE_HOST"),
        port=os.environ.get("DATABASE_PORT"),
        row_factory=dict_row,
    )


# ---------------------------------------------------------------------------
# Database initialization
# ---------------------------------------------------------------------------

def init_db():
    conn = get_db()

    try:
        with conn.cursor() as cursor:

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    full_name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    token TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    used BOOLEAN NOT NULL DEFAULT FALSE,
                    CONSTRAINT fk_reset_user
                        FOREIGN KEY (user_id)
                        REFERENCES users(id)
                        ON DELETE CASCADE
                )
                """
            )

        conn.commit()

    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------------------------------------------------------------------------
# CAPTCHA helpers
# ---------------------------------------------------------------------------

def issue_captcha():

    a = random.randint(1, 9)
    b = random.randint(1, 9)

    op = random.choice(["+", "-"])

    if op == "-" and b > a:
        a, b = b, a

    answer = a + b if op == "+" else a - b

    challenge_id = secrets.token_hex(8)

    session["captcha_id"] = challenge_id
    session["captcha_answer"] = answer
    session["captcha_expires_at"] = (
        time.time() + CAPTCHA_TTL_SECONDS
    )

    return {
        "captcha_id": challenge_id,
        "question": f"What is {a} {op} {b}?"
    }


def verify_captcha(captcha_id, answer):

    expected_id = session.get("captcha_id")
    expected_answer = session.get("captcha_answer")
    expires_at = session.get("captcha_expires_at")

    if (
        not expected_id
        or expected_answer is None
        or expires_at is None
    ):
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

    # CAPTCHA is single-use
    _clear_captcha()

    if not correct:
        return False, "incorrect captcha answer"

    return True, None


def _clear_captcha():

    session.pop("captcha_id", None)
    session.pop("captcha_answer", None)
    session.pop("captcha_expires_at", None)


# ---------------------------------------------------------------------------
# Page routes
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

    return render_template(
        "reset_password.html",
        token=token
    )


# ---------------------------------------------------------------------------
# API - CAPTCHA
# ---------------------------------------------------------------------------

@app.route("/api/captcha", methods=["GET"])
def api_captcha():

    return jsonify(
        {
            "ok": True,
            **issue_captcha()
        }
    ), 200


# ---------------------------------------------------------------------------
# API - Register
# ---------------------------------------------------------------------------

@app.route("/api/register", methods=["POST"])
def api_register():

    data = request.get_json(silent=True) or {}

    full_name = (data.get("full_name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    captcha_id = data.get("captcha_id") or ""
    captcha_answer = data.get("captcha_answer")

    # CAPTCHA
    captcha_ok, captcha_err = verify_captcha(
        captcha_id,
        captcha_answer
    )

    if not captcha_ok:
        return jsonify(
            {
                "ok": False,
                "error": captcha_err
            }
        ), 400

    # Required fields
    if not full_name or not email or not password:

        return jsonify(
            {
                "ok": False,
                "error": "full_name, email and password are required"
            }
        ), 400

    # Email validation
    if not EMAIL_RE.match(email):

        return jsonify(
            {
                "ok": False,
                "error": "invalid email format"
            }
        ), 400

    # Password validation
    if len(password) < 6:

        return jsonify(
            {
                "ok": False,
                "error": "password must be at least 6 characters"
            }
        ), 400

    conn = get_db()

    try:

        with conn.cursor() as cursor:

            cursor.execute(
                """
                SELECT id
                FROM users
                WHERE email = %s
                """,
                (email,)
            )

            existing = cursor.fetchone()

            if existing:

                return jsonify(
                    {
                        "ok": False,
                        "error": "an account with this email already exists"
                    }
                ), 409

            cursor.execute(
                """
                INSERT INTO users
                    (
                        full_name,
                        email,
                        password_hash,
                        created_at
                    )
                VALUES
                    (%s, %s, %s, %s)
                """,
                (
                    full_name,
                    email,
                    generate_password_hash(password),
                    datetime.utcnow()
                )
            )

        conn.commit()

    finally:
        conn.close()

    return jsonify(
        {
            "ok": True,
            "message": "account created successfully"
        }
    ), 201


# ---------------------------------------------------------------------------
# API - Login
# ---------------------------------------------------------------------------

@app.route("/api/login", methods=["POST"])
def api_login():

    data = request.get_json(silent=True) or {}

    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    captcha_id = data.get("captcha_id") or ""
    captcha_answer = data.get("captcha_answer")

    # CAPTCHA
    captcha_ok, captcha_err = verify_captcha(
        captcha_id,
        captcha_answer
    )

    if not captcha_ok:

        return jsonify(
            {
                "ok": False,
                "error": captcha_err
            }
        ), 400

    if not email or not password:

        return jsonify(
            {
                "ok": False,
                "error": "email and password are required"
            }
        ), 400

    conn = get_db()

    try:

        with conn.cursor() as cursor:

            cursor.execute(
                """
                SELECT *
                FROM users
                WHERE email = %s
                """,
                (email,)
            )

            user = cursor.fetchone()

    finally:
        conn.close()

    if not user:

        return jsonify(
            {
                "ok": False,
                "error": "invalid email or password"
            }
        ), 401

    if not check_password_hash(
        user["password_hash"],
        password
    ):

        return jsonify(
            {
                "ok": False,
                "error": "invalid email or password"
            }
        ), 401

    session["user_id"] = user["id"]
    session["full_name"] = user["full_name"]

    return jsonify(
        {
            "ok": True,
            "message": "login successful",
            "redirect": "/dashboard"
        }
    ), 200


# ---------------------------------------------------------------------------
# API - Profile
# ---------------------------------------------------------------------------

@app.route("/api/profile", methods=["GET"])
def api_profile():

    if not session.get("user_id"):

        return jsonify(
            {
                "ok": False,
                "error": "not authenticated"
            }
        ), 401

    conn = get_db()

    try:

        with conn.cursor() as cursor:

            cursor.execute(
                """
                SELECT
                    id,
                    full_name,
                    email,
                    created_at
                FROM users
                WHERE id = %s
                """,
                (session["user_id"],)
            )

            user = cursor.fetchone()

    finally:
        conn.close()

    if not user:

        session.clear()

        return jsonify(
            {
                "ok": False,
                "error": "user not found"
            }
        ), 404

    return jsonify(
        {
            "ok": True,
            "user": {
                "id": user["id"],
                "full_name": user["full_name"],
                "email": user["email"],
                "created_at": user["created_at"].isoformat()
                if user["created_at"]
                else None,
            }
        }
    ), 200


# ---------------------------------------------------------------------------
# API - Logout
# ---------------------------------------------------------------------------

@app.route("/api/logout", methods=["POST"])
def api_logout():

    session.clear()

    return jsonify(
        {
            "ok": True,
            "message": "logged out"
        }
    ), 200


# ---------------------------------------------------------------------------
# API - Forgot password
# ---------------------------------------------------------------------------

@app.route("/api/forgot-password", methods=["POST"])
def api_forgot_password():

    data = request.get_json(silent=True) or {}

    email = (data.get("email") or "").strip().lower()

    if not email or not EMAIL_RE.match(email):

        return jsonify(
            {
                "ok": False,
                "error": "a valid email is required"
            }
        ), 400

    conn = get_db()

    try:

        with conn.cursor() as cursor:

            cursor.execute(
                """
                SELECT id
                FROM users
                WHERE email = %s
                """,
                (email,)
            )

            user = cursor.fetchone()

            generic_message = (
                "if that email is registered, "
                "a reset link has been generated"
            )

            if not user:

                return jsonify(
                    {
                        "ok": True,
                        "message": generic_message
                    }
                ), 200

            token = secrets.token_urlsafe(32)

            created_at = datetime.utcnow()

            expires_at = (
                created_at
                + timedelta(minutes=RESET_TOKEN_TTL_MINUTES)
            )

            cursor.execute(
                """
                INSERT INTO password_reset_tokens
                    (
                        user_id,
                        token,
                        created_at,
                        expires_at,
                        used
                    )
                VALUES
                    (%s, %s, %s, %s, FALSE)
                """,
                (
                    user["id"],
                    token,
                    created_at,
                    expires_at
                )
            )

        conn.commit()

    finally:
        conn.close()

    reset_link = url_for(
        "reset_password_page",
        token=token,
        _external=True
    )

    return jsonify(
        {
            "ok": True,
            "message": generic_message,
            "dev_note": (
                "no email server configured; "
                "reset link is returned directly for testing"
            ),
            "reset_link": reset_link,
            "reset_token": token,
            "expires_at": expires_at.isoformat(),
        }
    ), 200


# ---------------------------------------------------------------------------
# API - Reset password
# ---------------------------------------------------------------------------

@app.route("/api/reset-password", methods=["POST"])
def api_reset_password():

    data = request.get_json(silent=True) or {}

    token = data.get("token") or ""

    new_password = data.get("new_password") or ""
    confirm_password = data.get("confirm_password") or ""

    if not token:

        return jsonify(
            {
                "ok": False,
                "error": "reset token is required"
            }
        ), 400

    if not new_password or not confirm_password:

        return jsonify(
            {
                "ok": False,
                "error": (
                    "new_password and "
                    "confirm_password are required"
                )
            }
        ), 400

    if new_password != confirm_password:

        return jsonify(
            {
                "ok": False,
                "error": "passwords do not match"
            }
        ), 400

    if len(new_password) < 6:

        return jsonify(
            {
                "ok": False,
                "error": "password must be at least 6 characters"
            }
        ), 400

    conn = get_db()

    try:

        with conn.cursor() as cursor:

            cursor.execute(
                """
                SELECT *
                FROM password_reset_tokens
                WHERE token = %s
                """,
                (token,)
            )

            row = cursor.fetchone()

            if not row:

                return jsonify(
                    {
                        "ok": False,
                        "error": "invalid reset token"
                    }
                ), 400

            if row["used"]:

                return jsonify(
                    {
                        "ok": False,
                        "error": (
                            "this reset token "
                            "has already been used"
                        )
                    }
                ), 400

            if datetime.utcnow() > row["expires_at"]:

                return jsonify(
                    {
                        "ok": False,
                        "error": (
                            "this reset token "
                            "has expired"
                        )
                    }
                ), 400

            cursor.execute(
                """
                UPDATE users
                SET password_hash = %s
                WHERE id = %s
                """,
                (
                    generate_password_hash(new_password),
                    row["user_id"]
                )
            )

            cursor.execute(
                """
                UPDATE password_reset_tokens
                SET used = TRUE
                WHERE id = %s
                """,
                (row["id"],)
            )

        conn.commit()

    finally:
        conn.close()

    return jsonify(
        {
            "ok": True,
            "message": "password has been reset successfully"
        }
    ), 200


# ---------------------------------------------------------------------------
# Initialize database
# ---------------------------------------------------------------------------

init_db()


# ---------------------------------------------------------------------------
# Run application
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=True
    )