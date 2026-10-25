import hashlib
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
import jwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv
from flask import Flask, Response, g, jsonify, request, send_from_directory
from flask_cors import CORS
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

import db

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")
PAPER_KEY = os.getenv("PAPER_KEY", "")
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "*")
PORT = int(os.getenv("PORT", "3000"))

if not JWT_SECRET:
    raise SystemExit("Missing JWT_SECRET in .env")

try:
    KEY = bytes.fromhex(PAPER_KEY)
except ValueError:
    KEY = b""
if len(KEY) != 32:
    raise SystemExit("PAPER_KEY must be 64 hex characters (32 bytes) in .env")

cipher = AESGCM(KEY)

# Folder with the HTML/CSS/JS pages. Only this folder is served to the browser,
# so backend files such as .env and trana.db stay private.
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

ALLOWED_EXT = {".pdf", ".doc", ".docx"}
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB upload limit
CORS(app)
db.init_app(app)


# ---------- Errors ----------

class ApiError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.message = message
        self.status = status


@app.errorhandler(ApiError)
def handle_api_error(e):
    return jsonify(error=e.message), e.status


@app.errorhandler(RequestEntityTooLarge)
def handle_too_large(e):
    return jsonify(error="File is too large (max 20 MB)"), 413


@app.errorhandler(Exception)
def handle_unexpected(e):
    if isinstance(e, HTTPException):
        return e  # keep normal 404/405 responses
    app.logger.exception(e)
    return jsonify(error="Something went wrong"), 500


# ---------- Helpers ----------

def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def require_auth(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            raise ApiError("Please log in", 401)
        try:
            g.user = jwt.decode(header[7:], JWT_SECRET, algorithms=["HS256"])
        except jwt.PyJWTError:
            raise ApiError("Session expired, please log in again", 401)
        return view(*args, **kwargs)
    return wrapper


def parse_iso(value):
    """Turn an ISO 8601 string into an epoch timestamp. Naive times are treated as local time."""
    text = str(value or "").strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        raise ApiError("Invalid release time")
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt.timestamp()


def iso_out(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def find_paper(paper_id):
    row = db.get().execute("SELECT * FROM papers WHERE id = ?", (paper_id,)).fetchone()
    if row is None:
        raise ApiError("Paper not found", 404)
    return row


def format_paper(row):
    """Shape a database row for the frontend. Never includes file data."""
    return {
        "id": row["id"],
        "name": row["name"],
        "subject": row["subject"],
        "examAt": iso_out(row["exam_at"]),
        "fileName": row["original_name"],
        "encrypted": True,
        "scheduled": row["release_at"] is not None,
        "releaseAt": iso_out(row["release_at"]) if row["release_at"] is not None else None,
        "delivered": bool(row["delivered"]),
        "createdAt": row["created_at"],
    }


def json_body():
    return request.get_json(silent=True) or {}


# ---------- Frontend pages ----------

@app.get("/")
def home():
    return send_from_directory(FRONTEND_DIR, "login.html")


@app.get("/<path:filename>")
def frontend_files(filename):
    return send_from_directory(FRONTEND_DIR, filename)


# ---------- Health ----------

@app.get("/api/health")
def health():
    return jsonify(ok=True)


# ---------- Auth ----------

@app.post("/api/auth/signup")
def signup():
    data = json_body()
    name = str(data.get("name", "")).strip()
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if not name or not username:
        raise ApiError("Name and username are required")
    if not EMAIL_RE.match(email):
        raise ApiError("Enter a valid email")
    if len(password) < 8:
        raise ApiError("Password must be at least 8 characters")

    conn = db.get()
    try:
        cur = conn.execute(
            "INSERT INTO users (name, username, email, password_hash) VALUES (?, ?, ?, ?)",
            (name, username, email, generate_password_hash(password)),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise ApiError("Username or email already in use", 409)

    return jsonify(id=cur.lastrowid, username=username), 201


@app.post("/api/auth/login")
def login():
    data = json_body()
    login_value = str(data.get("username") or data.get("email") or "").strip()
    password = str(data.get("password", ""))

    user = db.get().execute(
        "SELECT * FROM users WHERE username = ? OR email = ?",
        (login_value, login_value.lower()),
    ).fetchone()

    if user is None or not check_password_hash(user["password_hash"], password):
        raise ApiError("Invalid username or password", 401)

    token = jwt.encode(
        {
            "sub": str(user["id"]),
            "name": user["name"],
            "role": user["role"],
            "exp": datetime.now(timezone.utc) + timedelta(hours=8),
        },
        JWT_SECRET,
        algorithm="HS256",
    )
    return jsonify(token=token, name=user["name"])


@app.post("/api/auth/forgot")
def forgot():
    email = str(json_body().get("email", "")).strip().lower()

    # Same response whether or not the account exists
    generic = {"message": "If an account exists for that email, a reset link has been sent."}

    if EMAIL_RE.match(email):
        conn = db.get()
        user = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if user is not None:
            token = secrets.token_urlsafe(32)
            conn.execute("DELETE FROM reset_tokens WHERE user_id = ?", (user["id"],))
            conn.execute(
                "INSERT INTO reset_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (hash_token(token), user["id"], time.time() + 30 * 60),
            )
            conn.commit()
            # No email service yet: the link is printed in the terminal.
            print(f"Reset link for {email}: http://localhost:{PORT}/reset-password.html?token={token}")

    return jsonify(generic)


@app.post("/api/auth/reset")
def reset():
    data = json_body()
    token = str(data.get("token", ""))
    password = str(data.get("password", ""))

    if len(password) < 8:
        raise ApiError("Password must be at least 8 characters")

    conn = db.get()
    row = conn.execute(
        "SELECT * FROM reset_tokens WHERE token_hash = ? AND used = 0 AND expires_at > ?",
        (hash_token(token), time.time()),
    ).fetchone()

    if row is None:
        raise ApiError("This reset link is invalid or has expired")

    conn.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(password), row["user_id"]),
    )
    conn.execute("UPDATE reset_tokens SET used = 1 WHERE token_hash = ?", (row["token_hash"],))
    conn.commit()

    return jsonify(message="Password updated. Please log in.")


# ---------- Papers ----------

@app.get("/api/papers")
@require_auth
def list_papers():
    rows = db.get().execute("SELECT * FROM papers ORDER BY id DESC").fetchall()
    return jsonify([format_paper(r) for r in rows])


@app.post("/api/papers")
@require_auth
def upload_paper():
    name = request.form.get("name", "").strip()
    subject = request.form.get("subject", "").strip()
    exam_date = request.form.get("examDate", "")
    exam_time = request.form.get("examTime", "")
    file = request.files.get("file")

    if file is None or not file.filename:
        raise ApiError("Choose a paper file")

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXT:
        raise ApiError("Only PDF, DOC or DOCX files are allowed")

    if not (name and subject and exam_date and exam_time):
        raise ApiError("Name, subject, date and time are required")

    try:
        exam_ts = datetime.fromisoformat(f"{exam_date}T{exam_time}").astimezone().timestamp()
    except ValueError:
        raise ApiError("Invalid exam date or time")

    # Encrypt the file before it is stored
    nonce = secrets.token_bytes(12)
    ciphertext = cipher.encrypt(nonce, file.read(), None)

    conn = db.get()
    cur = conn.execute(
        """INSERT INTO papers (name, subject, exam_at, original_name, mime_type, file_data, nonce)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (name, subject, exam_ts, secure_filename(file.filename), file.mimetype, ciphertext, nonce),
    )
    conn.commit()

    return jsonify(format_paper(find_paper(cur.lastrowid))), 201


@app.post("/api/papers/<int:paper_id>/schedule")
@require_auth
def schedule_paper(paper_id):
    paper = find_paper(paper_id)
    release_ts = parse_iso(json_body().get("releaseAt"))

    if release_ts <= time.time():
        raise ApiError("Release time must be in the future")
    if release_ts > paper["exam_at"]:
        raise ApiError("Release must be before the exam starts")

    conn = db.get()
    conn.execute("UPDATE papers SET release_at = ? WHERE id = ?", (release_ts, paper_id))
    conn.commit()

    return jsonify(format_paper(find_paper(paper_id)))


@app.delete("/api/papers/<int:paper_id>/schedule")
@require_auth
def cancel_schedule(paper_id):
    find_paper(paper_id)
    conn = db.get()
    conn.execute("UPDATE papers SET release_at = NULL WHERE id = ?", (paper_id,))
    conn.commit()
    return jsonify(format_paper(find_paper(paper_id)))


@app.delete("/api/papers/<int:paper_id>")
@require_auth
def delete_paper(paper_id):
    find_paper(paper_id)
    conn = db.get()
    conn.execute("DELETE FROM papers WHERE id = ?", (paper_id,))
    conn.commit()
    return jsonify(message="Paper deleted")


@app.get("/api/papers/<int:paper_id>/download")
@require_auth
def download_paper(paper_id):
    paper = find_paper(paper_id)

    # Enforced on the server: the file can't be fetched before release
    if paper["release_at"] is None:
        raise ApiError("This paper has not been scheduled for release", 403)
    if time.time() < paper["release_at"]:
        raise ApiError("This paper is not released yet", 403)

    plain = cipher.decrypt(paper["nonce"], paper["file_data"], None)

    conn = db.get()
    conn.execute("UPDATE papers SET delivered = 1 WHERE id = ?", (paper_id,))
    conn.commit()

    return Response(
        plain,
        mimetype=paper["mime_type"] or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{paper["original_name"]}"'},
    )


if __name__ == "__main__":
    print(f"TRANA running on http://localhost:{PORT}")
    print(f"Open http://localhost:{PORT}/ in your browser")
    app.run(port=PORT, debug=False)