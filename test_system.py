"""
test_system.py — Unit tests for SQL Injection Defense System.
Run:  python -m pytest tests/ -v
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from sql_defense import detect, sanitize, get_attack_level
from encryption import encrypt, decrypt, hash_password, verify_password
from database import SecureDatabase, _issue_token, validate_token, revoke_token


# ── SQLi Detection ─────────────────────────────────────────────────────────────

class TestSQLiDetection:

    def test_clean_input(self):
        is_attack, _ = detect("john_doe")
        assert not is_attack

    def test_tautology(self):
        is_attack, reason = detect("' OR '1'='1")
        assert is_attack

    def test_union_select(self):
        is_attack, _ = detect("' UNION SELECT username, password FROM users--")
        assert is_attack

    def test_drop_table(self):
        is_attack, _ = detect("'; DROP TABLE users;--")
        assert is_attack

    def test_comment_truncation(self):
        is_attack, _ = detect("admin'--")
        assert is_attack

    def test_sleep_blind(self):
        is_attack, _ = detect("' AND SLEEP(5)--")
        assert is_attack

    def test_url_encoded_attack(self):
        is_attack, _ = detect("%27%20OR%20%271%27%3D%271")
        assert is_attack

    def test_unbalanced_quote(self):
        is_attack, _ = detect("O'Brien")
        # Single unbalanced quote — detected as suspicious
        assert is_attack

    def test_normal_email(self):
        is_attack, _ = detect("user@example.com")
        assert not is_attack

    def test_normal_number(self):
        is_attack, _ = detect("9876543210")
        assert not is_attack


# ── Sanitize ────────────────────────────────────────────────────────────────────

class TestSanitize:

    def test_attack_blocked(self):
        val, is_attack, reason = sanitize("' OR 1=1--")
        assert is_attack and val == ""

    def test_clean_escaped(self):
        val, is_attack, _ = sanitize("<script>alert(1)</script>")
        assert not is_attack
        assert "<" not in val and ">" not in val

    def test_empty_input(self):
        val, is_attack, _ = sanitize("")
        assert not is_attack and val == ""


# ── Attack level classification ────────────────────────────────────────────────

class TestAttackLevel:
    def test_drop_is_critical(self):
        assert get_attack_level("DROP TABLE users") == "CRITICAL"

    def test_union_is_high(self):
        assert get_attack_level("UNION SELECT * FROM users") == "HIGH"

    def test_comment_is_medium(self):
        assert get_attack_level("admin'--") == "MEDIUM"


# ── AES-256 Encryption ─────────────────────────────────────────────────────────

class TestEncryption:

    def test_encrypt_decrypt_roundtrip(self):
        original = "test@example.com"
        assert decrypt(encrypt(original)) == original

    def test_different_ciphertexts(self):
        msg = "same message"
        assert encrypt(msg) != encrypt(msg)  # random IV each time

    def test_password_hash_verify(self):
        pw = "MySecurePassword123!"
        h  = hash_password(pw)
        assert verify_password(pw, h)
        assert not verify_password("WrongPassword", h)

    def test_long_string(self):
        long = "a" * 500
        assert decrypt(encrypt(long)) == long


# ── Capability Tokens ──────────────────────────────────────────────────────────

class TestTokens:

    def test_issue_and_validate(self):
        token = _issue_token("alice")
        payload = validate_token(token)
        assert payload and payload["username"] == "alice"

    def test_revoke(self):
        token = _issue_token("bob")
        revoke_token(token)
        assert validate_token(token) is None

    def test_invalid_token(self):
        assert validate_token("totally-fake-token") is None


# ── SecureDatabase ─────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_db(tmp_path):
    db = SecureDatabase(str(tmp_path / "test.sqlite"))
    yield db
    db.close()

class TestDatabase:

    def test_register_and_login(self, tmp_db):
        tmp_db.register("alice", "pass123", "alice@test.com")
        result = tmp_db.login("alice", "pass123")
        assert result["success"]
        assert "token" in result

    def test_wrong_password(self, tmp_db):
        tmp_db.register("bob", "pass123", "bob@test.com")
        result = tmp_db.login("bob", "wrongpass")
        assert not result["success"]

    def test_nonexistent_user(self, tmp_db):
        result = tmp_db.login("ghost", "pass")
        assert not result["success"]

    def test_profile_decryption(self, tmp_db):
        tmp_db.register("carol", "pass123", "carol@test.com", "9000000001")
        login_result = tmp_db.login("carol", "pass123")
        profile = tmp_db.get_profile(login_result["token"])
        assert profile["email"] == "carol@test.com"
        assert profile["phone"] == "9000000001"

    def test_duplicate_username(self, tmp_db):
        tmp_db.register("dave", "pass123", "dave@test.com")
        with pytest.raises(Exception):
            tmp_db.register("dave", "other", "dave2@test.com")
