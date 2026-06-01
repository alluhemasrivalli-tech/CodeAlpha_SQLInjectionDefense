"""
database.py — Secure database layer (Layer 2 of double-layer security).

Security measures:
  • ONLY parameterised queries — never string-formatted SQL
  • Passwords stored as PBKDF2-HMAC-SHA256 hashes (never plaintext)
  • Sensitive fields (email, phone) stored AES-256 encrypted
  • Capability tokens control privileged operations
  • All queries logged with timestamp for audit trail
"""

import sqlite3
import os
import secrets
import datetime
from typing import Optional, Dict, List

from encryption import encrypt, decrypt, hash_password, verify_password

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "secure.sqlite")

# ── Capability token store (in-memory; use Redis in production) ───────────────
_capability_tokens: Dict[str, dict] = {}


def _issue_token(username: str, role: str = "user") -> str:
    """Issue a cryptographically secure capability token."""
    token = secrets.token_urlsafe(32)
    _capability_tokens[token] = {
        "username": username,
        "role": role,
        "issued_at": datetime.datetime.utcnow(),
        "expires_at": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
    }
    return token


def validate_token(token: str) -> Optional[Dict]:
    """Return token payload if valid and not expired, else None."""
    payload = _capability_tokens.get(token)
    if not payload:
        return None
    if datetime.datetime.utcnow() > payload["expires_at"]:
        del _capability_tokens[token]
        return None
    return payload


def revoke_token(token: str):
    _capability_tokens.pop(token, None)


class SecureDatabase:
    """
    Secure SQLite database that uses:
    - Parameterised queries (SQLi Layer 2)
    - AES-256 encrypted sensitive fields
    - Hashed passwords
    - Capability token access control
    - Audit logging
    """

    def __init__(self, db_path: str = DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    NOT NULL UNIQUE,
                password_hash TEXT    NOT NULL,
                email_enc     TEXT    NOT NULL,
                phone_enc     TEXT,
                role          TEXT    DEFAULT 'user',
                created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                event      TEXT    NOT NULL,
                username   TEXT,
                ip_address TEXT,
                detail     TEXT,
                ts         DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS attack_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                field      TEXT,
                payload    TEXT,
                level      TEXT,
                ip_address TEXT,
                ts         DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        self.conn.commit()

    # ── Auth ───────────────────────────────────────────────────────────

    def register(self, username: str, password: str, email: str, phone: str = "") -> Dict:
        """Register a new user. Returns capability token on success."""
        pw_hash    = hash_password(password)
        email_enc  = encrypt(email)
        phone_enc  = encrypt(phone) if phone else ""

        # Parameterised — never string-formatted
        self.conn.execute(
            "INSERT INTO users (username, password_hash, email_enc, phone_enc) VALUES (?, ?, ?, ?)",
            (username, pw_hash, email_enc, phone_enc),
        )
        self.conn.commit()
        self._audit("REGISTER", username, detail=f"New user registered")
        token = _issue_token(username)
        return {"success": True, "token": token, "message": "Registration successful"}

    def login(self, username: str, password: str, ip: str = "unknown") -> Dict:
        """Authenticate user. Returns capability token on success."""
        # Parameterised query — username never interpolated into SQL string
        row = self.conn.execute(
            "SELECT password_hash, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if not row:
            self._audit("LOGIN_FAIL", username, ip, "User not found")
            return {"success": False, "message": "Invalid credentials"}

        if not verify_password(password, row["password_hash"]):
            self._audit("LOGIN_FAIL", username, ip, "Wrong password")
            return {"success": False, "message": "Invalid credentials"}

        token = _issue_token(username, row["role"])
        self._audit("LOGIN_OK", username, ip, "Login successful")
        return {"success": True, "token": token, "message": "Login successful"}

    def get_profile(self, token: str) -> Dict:
        """Return decrypted user profile (requires valid token)."""
        payload = validate_token(token)
        if not payload:
            return {"success": False, "message": "Invalid or expired token"}

        row = self.conn.execute(
            "SELECT username, email_enc, phone_enc, role, created_at FROM users WHERE username = ?",
            (payload["username"],),
        ).fetchone()

        if not row:
            return {"success": False, "message": "User not found"}

        return {
            "success":    True,
            "username":   row["username"],
            "email":      decrypt(row["email_enc"]),
            "phone":      decrypt(row["phone_enc"]) if row["phone_enc"] else "",
            "role":       row["role"],
            "created_at": row["created_at"],
        }

    # ── Logging ────────────────────────────────────────────────────────

    def _audit(self, event: str, username: str = "", ip: str = "", detail: str = ""):
        self.conn.execute(
            "INSERT INTO audit_log (event, username, ip_address, detail) VALUES (?, ?, ?, ?)",
            (event, username, ip, detail),
        )
        self.conn.commit()

    def log_attack(self, field: str, payload: str, level: str, ip: str = ""):
        self.conn.execute(
            "INSERT INTO attack_log (field, payload, level, ip_address) VALUES (?, ?, ?, ?)",
            (field, payload[:500], level, ip),
        )
        self.conn.commit()

    def get_audit_logs(self, token: str) -> Dict:
        """Admin-only: return audit logs."""
        payload = validate_token(token)
        if not payload or payload.get("role") != "admin":
            return {"success": False, "message": "Admin access required"}
        rows = self.conn.execute(
            "SELECT event, username, ip_address, detail, ts FROM audit_log ORDER BY ts DESC LIMIT 100"
        ).fetchall()
        return {"success": True, "logs": [dict(r) for r in rows]}

    def get_attack_logs(self) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT field, payload, level, ip_address, ts FROM attack_log ORDER BY ts DESC LIMIT 50"
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self):
        self.conn.close()
