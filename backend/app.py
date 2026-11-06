
"""
TRANA backend: serves HTML pages from ./static and the JSON API.

Features:
  - Signup / login with JWT
  - Forgot / reset password
  - Upload -> validate -> AES-256-GCM encrypt
  - Schedule / cancel release
  - Time-locked download
  - Delete papers

Run:
    pip install -r requirements.txt
    python app.py

Open:
    http://127.0.0.1:3000/

Production:
    gunicorn app:app
"""

import base64
import hashlib
import io
import os
import re
import secrets
import smtplib
import sqlite3
import time

from datetime import datetime, timezone
from email.message import EmailMessage
from functools import wraps
from pathlib import Path

import jwt

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from dotenv import load_dotenv

from flask import (
    Flask,
    g,
    jsonify,
    request,
    send_file,
    send_from_directory,
)

from flask_cors import CORS

from werkzeug.exceptions import HTTPException

from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)

import db


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

# Read the port before load_dotenv runs, so a stale PORT in .env
# cannot override the port a hosting platform assigns at runtime.
ENV_PORT = os.environ.get("PORT")

load_dotenv(BASE_DIR / ".env")

DATA_DIR = BASE_DIR / "instance"
DATA_DIR.mkdir(parents=True, exist_ok=True)

MAX_UPLOAD_MB = 20

TOKEN_HOURS = 8

RESET_MINUTES = 30

ADMIN_ROLE = "admin"

DEFAULT_ROLE = "paper_setter"

BASE_URL = os.environ.get(
    "TRANA_BASE_URL",
    "http://127.0.0.1:3000"
).rstrip("/")


# ============================================================
# FLASK APP
# ============================================================

app = Flask(
    __name__,
    static_folder="static",
    static_url_path=""
)

app.config["MAX_CONTENT_LENGTH"] = (
    MAX_UPLOAD_MB * 1024 * 1024
)


# ============================================================
# CORS
# ============================================================

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": os.environ.get(
                "TRANA_CORS_ORIGINS",
                "*"
            ).split(",")
        }
    }
)


# ============================================================
# ENCRYPTION KEYS
# ============================================================

def _load_key(env_name: str, filename: str) -> bytes:
    """
    Load a 32-byte key from environment variable or instance folder.
    """

    env = os.environ.get(env_name)

    if env:
        try:
            key = base64.b64decode(
                env,
                validate=True
            )
        except Exception as exc:
            raise RuntimeError(
                f"{env_name} must be valid base64."
            ) from exc

    else:
        path = DATA_DIR / filename

        if not path.exists():

            path.write_bytes(
                os.urandom(32)
            )

            try:
                path.chmod(0o600)

            except OSError:
                pass

        key = path.read_bytes()

    if len(key) != 32:
        raise RuntimeError(
            f"{env_name} must contain exactly 32 bytes."
        )

    return key


# IMPORTANT:
# Keep these keys safe.
# Losing MASTER_KEY makes encrypted papers unreadable.

MASTER_KEY = _load_key(
    "TRANA_MASTER_KEY",
    "master.key"
)

JWT_SECRET = _load_key(
    "TRANA_JWT_SECRET",
    "jwt.key"
)


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

db.init_app(app)


# ============================================================
# API ERRORS
# ============================================================

class ApiError(Exception):

    def __init__(self, message, status=400):

        super().__init__(message)

        self.message = message

        self.status = status


# ============================================================
# DATE HELPERS
# ============================================================

def parse_iso(value):
    """
    Convert ISO datetime string to UTC timestamp.
    """

    try:

        dt = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

    except (ValueError, TypeError):

        return None

    if dt.tzinfo is None:

        dt = dt.replace(
            tzinfo=timezone.utc
        )

    return dt.timestamp()


def to_iso(epoch):
    """
    Convert timestamp to ISO UTC string.
    """

    if epoch is None:
        return None

    return (
        datetime.fromtimestamp(
            epoch,
            timezone.utc
        )
        .isoformat()
        .replace("+00:00", "Z")
    )


# ============================================================
# JWT TOKEN
# ============================================================

def make_token(user):

    now = int(time.time())

    payload = {
        "sub": str(user["id"]),
        "role": user["role"],
        "iat": now,
        "exp": now + TOKEN_HOURS * 3600,
    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm="HS256"
    )


# ============================================================
# AUTHENTICATION DECORATOR
# ============================================================

def auth_required(fn):

    @wraps(fn)
    def inner(*args, **kwargs):

        header = request.headers.get(
            "Authorization",
            ""
        )

        if not header.startswith("Bearer "):

            raise ApiError(
                "Please log in to continue.",
                401
            )

        token = header[7:]

        try:

            payload = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=["HS256"]
            )

        except jwt.ExpiredSignatureError:

            raise ApiError(
                "Your session has expired.",
                401
            )

        except jwt.InvalidTokenError:

            raise ApiError(
                "Invalid login. Please log in again.",
                401
            )

        try:

            user_id = int(
                payload["sub"]
            )

        except (ValueError, TypeError, KeyError):

            raise ApiError(
                "Invalid login. Please log in again.",
                401
            )

        user = db.get().execute(
            """
            SELECT id, name, username, role
            FROM users
            WHERE id = ?
            """,
            (user_id,)
        ).fetchone()

        if not user:

            raise ApiError(
                "This account no longer exists.",
                401
            )

        g.user = user

        return fn(*args, **kwargs)

    return inner


# ============================================================
# LOGIN RATE LIMITING
# ============================================================

_attempts = {}


def too_many_attempts(
    key,
    limit=8,
    window=300
):

    now = time.time()

    recent = [
        timestamp
        for timestamp in _attempts.get(key, [])
        if now - timestamp < window
    ]

    _attempts[key] = recent

    return len(recent) >= limit


def record_attempt(key):

    _attempts.setdefault(
        key,
        []
    ).append(
        time.time()
    )


# ============================================================
# VALIDATION
# ============================================================

USERNAME_RE = re.compile(
    r"^[a-z0-9_.-]{3,30}$"
)

EMAIL_RE = re.compile(
    r"^[^\s@]+@[^\s@]+\.[^\s@]+$"
)


# ============================================================
# SIGNUP
# ============================================================

@app.post("/api/auth/signup")
def signup():

    d = request.get_json(
        silent=True
    ) or {}

    name = str(
        d.get("name", "")
    ).strip()

    username = str(
        d.get("username", "")
    ).strip().lower()

    email = str(
        d.get("email", "")
    ).strip().lower()

    password = str(
        d.get("password", "")
    )

    if not 2 <= len(name) <= 80:

        raise ApiError(
            "Enter your full name (2 to 80 characters)."
        )

    if not USERNAME_RE.match(username):

        raise ApiError(
            "Username must be 3-30 characters: letters, numbers, . _ -"
        )

    if not EMAIL_RE.match(email) or len(email) > 120:

        raise ApiError(
            "Enter a valid email address."
        )

    if not 8 <= len(password) <= 128:

        raise ApiError(
            "Password must be 8 to 128 characters."
        )

    conn = db.get()

    existing = conn.execute(
        """
        SELECT 1
        FROM users
        WHERE username = ? OR email = ?
        """,
        (username, email)
    ).fetchone()

    if existing:

        raise ApiError(
            "That username or email is already registered.",
            409
        )

    is_first = (
        conn.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0] == 0
    )

    role = (
        ADMIN_ROLE
        if is_first
        else DEFAULT_ROLE
    )

    try:

        conn.execute(
            """
            INSERT INTO users
            (
                name,
                username,
                email,
                password_hash,
                role
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                name,
                username,
                email,
                generate_password_hash(password),
                role,
            )
        )

        conn.commit()

    except sqlite3.IntegrityError:

        conn.rollback()

        raise ApiError(
            "That username or email is already registered.",
            409
        )

    return jsonify(
        message="Account created."
    ), 201


# ============================================================
# LOGIN
# ============================================================

@app.post("/api/auth/login")
def login():

    d = request.get_json(
        silent=True
    ) or {}

    username = str(
        d.get("username", "")
    ).strip().lower()

    password = str(
        d.get("password", "")
    )

    key = (
        f"{request.remote_addr}:{username}"
    )

    if too_many_attempts(key):

        raise ApiError(
            "Too many failed attempts. Try again in a few minutes.",
            429
        )

    user = db.get().execute(
        """
        SELECT *
        FROM users
        WHERE username = ?
        """,
        (username,)
    ).fetchone()

    if (
        not user
        or not check_password_hash(
            user["password_hash"],
            password
        )
    ):

        record_attempt(key)

        raise ApiError(
            "Wrong username or password.",
            401
        )

    _attempts.pop(
        key,
        None
    )

    return jsonify(
        token=make_token(user),
        name=user["name"],
        role=user["role"]
    )


# ============================================================
# PASSWORD RESET EMAIL
# ============================================================

def send_reset_email(to, link):

    host = os.environ.get(
        "TRANA_SMTP_HOST"
    )

    if not host:

        print(
            f"\n[DEV] Password reset link for {to}:\n{link}\n"
        )

        return

    msg = EmailMessage()

    msg["Subject"] = "TRANA password reset"

    msg["From"] = (
        os.environ.get("TRANA_SMTP_FROM")
        or os.environ.get("TRANA_SMTP_USER", "")
    )

    msg["To"] = to

    msg.set_content(
        f"""
Use this link to choose a new password.
The link is valid for {RESET_MINUTES} minutes.

{link}

If you did not ask for this, ignore this email.
"""
    )

    with smtplib.SMTP(
        host,
        int(
            os.environ.get(
                "TRANA_SMTP_PORT",
                "587"
            )
        ),
        timeout=15
    ) as smtp:

        smtp.starttls()

        smtp_user = os.environ.get(
            "TRANA_SMTP_USER"
        )

        if smtp_user:

            smtp.login(
                smtp_user,
                os.environ.get(
                    "TRANA_SMTP_PASSWORD",
                    ""
                )
            )

        smtp.send_message(msg)


# ============================================================
# FORGOT PASSWORD
# ============================================================

@app.post("/api/auth/forgot")
def forgot_password():

    d = request.get_json(
        silent=True
    ) or {}

    email = str(
        d.get("email", "")
    ).strip().lower()

    if not EMAIL_RE.match(email):

        raise ApiError(
            "Please enter a valid email address."
        )

    conn = db.get()

    user = conn.execute(
        """
        SELECT id, email
        FROM users
        WHERE email = ?
        """,
        (email,)
    ).fetchone()

    if user:

        token = secrets.token_urlsafe(32)

        token_hash = hashlib.sha256(
            token.encode()
        ).hexdigest()

        conn.execute(
            """
            DELETE FROM reset_tokens
            WHERE user_id = ?
            """,
            (user["id"],)
        )

        conn.execute(
            """
            INSERT INTO reset_tokens
            (
                token_hash,
                user_id,
                expires_at
            )
            VALUES (?, ?, ?)
            """,
            (
                token_hash,
                user["id"],
                time.time() + RESET_MINUTES * 60,
            )
        )

        conn.commit()

        link = (
            f"{BASE_URL}/reset-password.html"
            f"?token={token}"
        )

        try:

            send_reset_email(
                user["email"],
                link
            )

        except Exception:

            app.logger.exception(
                "Could not send reset email"
            )

    return jsonify(
        message=(
            "If an account exists for that email, "
            "a reset link has been sent."
        )
    )


# ============================================================
# RESET PASSWORD
# ============================================================

@app.post("/api/auth/reset")
def reset_password():

    d = request.get_json(
        silent=True
    ) or {}

    token = str(
        d.get("token", "")
    )

    password = str(
        d.get("password", "")
    )

    if not 8 <= len(password) <= 128:

        raise ApiError(
            "Password must be 8 to 128 characters."
        )

    token_hash = hashlib.sha256(
        token.encode()
    ).hexdigest()

    conn = db.get()

    row = conn.execute(
        """
        SELECT user_id
        FROM reset_tokens
        WHERE token_hash = ?
          AND used = 0
          AND expires_at > ?
        """,
        (
            token_hash,
            time.time()
        )
    ).fetchone()

    if not row:

        raise ApiError(
            "This reset link is invalid or has expired.",
            400
        )

    conn.execute(
        """
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
        """,
        (
            generate_password_hash(password),
            row["user_id"],
        )
    )

    conn.execute(
        """
        DELETE FROM reset_tokens
        WHERE user_id = ?
        """,
        (row["user_id"],)
    )

    conn.commit()

    return jsonify(
        message="Password updated. You can now log in."
    )


# ============================================================
# CURRENT USER
# ============================================================

@app.get("/api/me")
@auth_required
def me():

    return jsonify(
        name=g.user["name"],
        username=g.user["username"],
        role=g.user["role"]
    )


# ============================================================
# PAPER CONFIGURATION
# ============================================================

ALLOWED_TYPES = {
    "pdf",
    "doc",
    "docx"
}

MIME = {
    "pdf": "application/pdf",

    "doc": "application/msword",

    "docx": (
        "application/vnd.openxmlformats-officedocument."
        "wordprocessingml.document"
    ),
}

LIST_COLUMNS = (
    "id, name, subject, exam_at, original_name, "
    "release_at, delivered, created_by"
)


# ============================================================
# FILE SIGNATURE VALIDATION
# ============================================================

def matches_signature(ext, head):

    if ext == "pdf":

        return head.startswith(
            b"%PDF-"
        )

    if ext == "docx":

        return head.startswith(
            b"PK\x03\x04"
        )

    if ext == "doc":

        return head.startswith(
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        )

    return False


# ============================================================
# PAPER JSON
# ============================================================

def paper_json(row):

    return {
        "id": row["id"],

        "name": row["name"],

        "subject": row["subject"],

        "fileName": row["original_name"],

        "examAt": to_iso(
            row["exam_at"]
        ),

        "encrypted": True,

        "scheduled": (
            row["release_at"] is not None
        ),

        "releaseAt": to_iso(
            row["release_at"]
        ),

        "delivered": bool(
            row["delivered"]
        ),
    }


# ============================================================
# GET PAPER WITH OWNERSHIP CHECK
# ============================================================

def get_paper(
    paper_id,
    columns=LIST_COLUMNS
):

    row = db.get().execute(
        f"""
        SELECT {columns}
        FROM papers
        WHERE id = ?
        """,
        (paper_id,)
    ).fetchone()

    if (
        not row
        or (
            g.user["role"] != ADMIN_ROLE
            and row["created_by"] != g.user["id"]
        )
    ):

        raise ApiError(
            "Paper not found.",
            404
        )

    return row


# ============================================================
# LIST PAPERS
# ============================================================

@app.get("/api/papers")
@auth_required
def list_papers():

    if g.user["role"] == ADMIN_ROLE:

        rows = db.get().execute(
            f"""
            SELECT {LIST_COLUMNS}
            FROM papers
            ORDER BY id DESC
            """
        ).fetchall()

    else:

        rows = db.get().execute(
            f"""
            SELECT {LIST_COLUMNS}
            FROM papers
            WHERE created_by = ?
            ORDER BY id DESC
            """,
            (g.user["id"],)
        ).fetchall()

    return jsonify(
        [
            paper_json(row)
            for row in rows
        ]
    )


# ============================================================
# UPLOAD PAPER
# ============================================================

@app.post("/api/papers")
@auth_required
def upload_paper():

    name = (
        request.form.get("name")
        or ""
    ).strip()

    subject = (
        request.form.get("subject")
        or ""
    ).strip()

    exam_at = parse_iso(
        request.form.get("examAt")
    )

    file = request.files.get(
        "file"
    )

    if not 3 <= len(name) <= 120:

        raise ApiError(
            "Enter a paper name (3 to 120 characters)."
        )

    if not 2 <= len(subject) <= 80:

        raise ApiError(
            "Enter a subject (2 to 80 characters)."
        )

    if exam_at is None:

        raise ApiError(
            "Choose a valid examination date and time."
        )

    if exam_at <= time.time():

        raise ApiError(
            "The examination date and time must be in the future."
        )

    if not file or not file.filename:

        raise ApiError(
            "Choose the examination paper file."
        )

    original = Path(
        file.filename
    ).name[:150]

    ext = (
        original.rsplit(".", 1)[-1].lower()
        if "." in original
        else ""
    )

    data = file.read()

    if ext not in ALLOWED_TYPES:

        raise ApiError(
            "Only PDF, DOC or DOCX files are accepted."
        )

    if not data:

        raise ApiError(
            "The selected file is empty."
        )

    if not matches_signature(
        ext,
        data[:8]
    ):

        raise ApiError(
            f"This file is not a real {ext.upper()} document."
        )

    conn = db.get()

    try:

        cur = conn.execute(
            """
            INSERT INTO papers
            (
                name,
                subject,
                exam_at,
                original_name,
                mime_type,
                file_data,
                nonce,
                created_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                subject,
                exam_at,
                original,
                MIME[ext],
                b"",
                b"",
                g.user["id"],
            )
        )

        paper_id = cur.lastrowid

        nonce = os.urandom(12)

        ciphertext = AESGCM(
            MASTER_KEY
        ).encrypt(
            nonce,
            data,
            f"paper:{paper_id}".encode()
        )

        conn.execute(
            """
            UPDATE papers
            SET file_data = ?,
                nonce = ?
            WHERE id = ?
            """,
            (
                ciphertext,
                nonce,
                paper_id,
            )
        )

        conn.commit()

    except Exception:

        conn.rollback()

        raise

    return jsonify(
        id=paper_id,
        message="Paper encrypted and saved."
    ), 201


# ============================================================
# DELETE PAPER
# ============================================================

@app.delete("/api/papers/<int:paper_id>")
@auth_required
def delete_paper(paper_id):

    get_paper(
        paper_id
    )

    conn = db.get()

    conn.execute(
        """
        DELETE FROM papers
        WHERE id = ?
        """,
        (paper_id,)
    )

    conn.commit()

    return jsonify(
        ok=True
    )


# ============================================================
# SCHEDULE PAPER RELEASE
# ============================================================

@app.post("/api/papers/<int:paper_id>/schedule")
@auth_required
def schedule_paper(paper_id):

    paper = get_paper(
        paper_id
    )

    d = request.get_json(
        silent=True
    ) or {}

    release_at = parse_iso(
        d.get("releaseAt")
    )

    if release_at is None:

        raise ApiError(
            "Choose a valid release date and time."
        )

    if paper["release_at"] is not None:

        raise ApiError(
            "This paper already has a release time. Cancel it first.",
            409
        )

    if release_at <= time.time():

        raise ApiError(
            "Release time must be in the future."
        )

    if release_at >= paper["exam_at"]:

        raise ApiError(
            "Release must be before the exam starts."
        )

    conn = db.get()

    conn.execute(
        """
        UPDATE papers
        SET release_at = ?,
            delivered = 0
        WHERE id = ?
        """,
        (
            release_at,
            paper_id,
        )
    )

    conn.commit()

    return jsonify(
        ok=True,
        releaseAt=to_iso(
            release_at
        )
    )


# ============================================================
# CANCEL PAPER SCHEDULE
# ============================================================

@app.delete("/api/papers/<int:paper_id>/schedule")
@auth_required
def cancel_schedule(paper_id):

    paper = get_paper(
        paper_id
    )

    if paper["release_at"] is None:

        raise ApiError(
            "This paper is not scheduled.",
            400
        )

    if paper["release_at"] <= time.time():

        raise ApiError(
            "This paper has already been released.",
            409
        )

    conn = db.get()

    conn.execute(
        """
        UPDATE papers
        SET release_at = NULL
        WHERE id = ?
        """,
        (paper_id,)
    )

    conn.commit()

    return jsonify(
        ok=True
    )


# ============================================================
# DOWNLOAD PAPER
# ============================================================

@app.get("/api/papers/<int:paper_id>/download")
@auth_required
def download_paper(paper_id):

    paper = get_paper(
        paper_id,
        """
        id,
        original_name,
        mime_type,
        file_data,
        nonce,
        release_at,
        created_by
        """
    )

    if paper["release_at"] is None:

        raise ApiError(
            "This paper has not been scheduled for release.",
            403
        )

    if paper["release_at"] > time.time():

        raise ApiError(
            "This paper is locked until its release time.",
            403
        )

    try:

        plain = AESGCM(
            MASTER_KEY
        ).decrypt(
            paper["nonce"],
            paper["file_data"],
            f"paper:{paper_id}".encode()
        )

    except InvalidTag:

        app.logger.error(
            "Decryption failed for paper %s",
            paper_id
        )

        raise ApiError(
            "This paper could not be decrypted.",
            500
        )

    conn = db.get()

    conn.execute(
        """
        UPDATE papers
        SET delivered = 1
        WHERE id = ?
        """,
        (paper_id,)
    )

    conn.commit()

    return send_file(
        io.BytesIO(plain),
        mimetype=(
            paper["mime_type"]
            or "application/octet-stream"
        ),
        as_attachment=True,
        download_name=paper["original_name"]
    )


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(ApiError)
def api_error(err):

    return jsonify(
        error=err.message
    ), err.status


@app.errorhandler(HTTPException)
def http_error(err):

    if request.path.startswith("/api/"):

        msgs = {
            404: "That API address does not exist.",

            405: "That request method is not allowed here.",

            413: (
                f"File is too large. "
                f"The limit is {MAX_UPLOAD_MB} MB."
            ),
        }

        return jsonify(
            error=msgs.get(
                err.code,
                err.description
            )
        ), err.code

    return err


@app.errorhandler(Exception)
def server_error(err):

    app.logger.exception(
        err
    )

    return jsonify(
        error="Something went wrong on the server. Please try again."
    ), 500


# ============================================================
# SECURITY HEADERS
# ============================================================

@app.after_request
def security_headers(resp):

    resp.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    resp.headers[
        "X-Frame-Options"
    ] = "DENY"

    if request.path.startswith("/api/"):

        resp.headers[
            "Cache-Control"
        ] = "no-store"

    return resp


# ============================================================
# FRONTEND ROUTES
# ============================================================

@app.get("/", endpoint="home")
def home():

    return send_from_directory(
        app.static_folder,
        "index.html"
    )


@app.get("/<path:page>")
def serve_page(page):

    # Only allow HTML pages from this route.
    if not page.endswith(".html"):

        raise ApiError(
            "Page not found.",
            404
        )

    return send_from_directory(
        app.static_folder,
        page
    )


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":
    print("\n========== TRANA ROUTES ==========")

    for rule in app.url_map.iter_rules():
        print(rule, sorted(rule.methods))

    print("=================================\n")

    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(ENV_PORT or "3000"), debug=False)
