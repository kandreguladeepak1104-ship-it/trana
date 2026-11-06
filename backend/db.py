import sqlite3
import time
from pathlib import Path

from flask import g

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "instance" / "trana.db"

USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    username      TEXT UNIQUE NOT NULL,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'paper_setter',
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

RESET_TOKENS_TABLE = """
CREATE TABLE IF NOT EXISTS reset_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at REAL NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
);
"""

PAPERS_TABLE = """
CREATE TABLE IF NOT EXISTS papers (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    subject       TEXT NOT NULL,
    exam_at       REAL NOT NULL,
    original_name TEXT NOT NULL,
    mime_type     TEXT,
    file_data     BLOB NOT NULL,      -- AES-256-GCM ciphertext (never the plain file)
    nonce         BLOB NOT NULL,
    release_at    REAL,
    delivered     INTEGER NOT NULL DEFAULT 0,
    created_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

SCHEMA = USERS_TABLE + RESET_TOKENS_TABLE + PAPERS_TABLE

PAPER_COLUMNS = (
    "id",
    "name",
    "subject",
    "exam_at",
    "original_name",
    "mime_type",
    "file_data",
    "nonce",
    "release_at",
    "delivered",
    "created_by",
    "created_at",
)


def get():
    """Return the database connection for the current request."""
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 5000")
        g.db = conn
    return g.db


def _close(_error=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


# ============================================================
# MIGRATIONS
# ============================================================

def _columns(conn, table):
    return [row[1] for row in conn.execute(f"PRAGMA table_info({table})")]


def _note(app, message):
    if app is not None:
        app.logger.warning(message)


def _migrate_users(conn, app=None):
    """
    Bring an older users table up to the current shape.

    Very old databases only had id/username/password_hash/role, so name and
    email are added here. Existing accounts keep their password hash and can
    still log in with the same username and password.
    """

    columns = _columns(conn, "users")

    if not columns:
        return

    if "name" not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN name TEXT")
        conn.execute(
            "UPDATE users SET name = username "
            "WHERE name IS NULL OR TRIM(name) = ''"
        )
        _note(app, "Migration: added users.name")

    if "email" not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
        conn.execute(
            "UPDATE users SET email = username || '@trana.local' "
            "WHERE email IS NULL OR TRIM(email) = ''"
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS users_email_key ON users(email)"
        )
        _note(app, "Migration: added users.email")

    if "created_at" not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN created_at TEXT")
        conn.execute(
            "UPDATE users SET created_at = datetime('now') "
            "WHERE created_at IS NULL"
        )
        _note(app, "Migration: added users.created_at")


def _migrate_papers(conn, app=None):
    """
    The current papers table stores the encrypted file in the row itself.

    An older layout kept the file elsewhere and used different column names,
    so those rows cannot be read by this code. They are kept for reference
    under a timestamped name and a fresh papers table is created.
    """

    columns = _columns(conn, "papers")

    if not columns:
        return

    if set(PAPER_COLUMNS).issubset(set(columns)):
        return

    archive = "papers_legacy_" + time.strftime("%Y%m%d%H%M%S")

    conn.execute(f"ALTER TABLE papers RENAME TO {archive}")
    conn.executescript(PAPERS_TABLE)

    _note(
        app,
        f"Migration: old papers table kept as '{archive}', "
        f"a fresh papers table was created",
    )


def init_app(app):
    app.teardown_appcontext(_close)

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    DB_PATH.parent.joinpath("vault").mkdir(exist_ok=True)

    conn = sqlite3.connect(DB_PATH, timeout=15)

    # WAL lets reads continue while another worker is writing.
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")

    conn.executescript(SCHEMA)

    _migrate_users(conn, app)
    _migrate_papers(conn, app)

    conn.commit()
    conn.close()
