"""
app.py — Flask web server for the SQL Injection Defense System.

Routes:
  GET  /              → Login / Register page
  POST /register      → Create account
  POST /login         → Authenticate + issue token
  GET  /dashboard     → User profile (token required)
  GET  /attack-demo   → Live SQL injection demo page
  POST /api/test      → API endpoint to test injection detection
  GET  /logs          → Attack log viewer
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from sql_defense import sanitize, detect, get_attack_level
from database import SecureDatabase, validate_token

app = Flask(__name__, template_folder="../templates", static_folder="../static")
app.secret_key = os.environ.get("FLASK_SECRET", "CodeAlpha_Dev_Secret_Change_In_Prod")

db = SecureDatabase()


# ── Helpers ────────────────────────────────────────────────────────────────────

def get_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")


def check_field(field_name: str, value: str):
    """Run Layer-1 detection on a single field. Log and return error if attack."""
    _, is_attack, reason = sanitize(value)
    if is_attack:
        level = get_attack_level(value)
        db.log_attack(field_name, value, level, get_ip())
        return False, f"🚨 SQL Injection detected in '{field_name}': {reason} [Level: {level}]"
    return True, ""


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["POST"])
def register():
    data     = request.get_json() or request.form
    username = data.get("username", "")
    password = data.get("password", "")
    email    = data.get("email", "")
    phone    = data.get("phone", "")

    # Layer 1: SQLi detection on every field
    for field, value in [("username", username), ("email", email), ("phone", phone)]:
        ok, err = check_field(field, value)
        if not ok:
            return jsonify({"success": False, "message": err}), 400

    if not username or not password or not email:
        return jsonify({"success": False, "message": "username, password, and email are required"}), 400

    try:
        result = db.register(username, password, email, phone)
        session["token"] = result["token"]
        return jsonify(result)
    except Exception as e:
        if "UNIQUE" in str(e):
            return jsonify({"success": False, "message": "Username already exists"}), 409
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/login", methods=["POST"])
def login():
    data     = request.get_json() or request.form
    username = data.get("username", "")
    password = data.get("password", "")

    # Layer 1: detect injection in username field (common attack vector)
    ok, err = check_field("username", username)
    if not ok:
        return jsonify({"success": False, "message": err}), 400

    result = db.login(username, password, get_ip())
    if result["success"]:
        session["token"] = result["token"]
    return jsonify(result), 200 if result["success"] else 401


@app.route("/dashboard")
def dashboard():
    token = session.get("token")
    if not token or not validate_token(token):
        return redirect(url_for("index"))
    profile = db.get_profile(token)
    return render_template("dashboard.html", profile=profile)


@app.route("/logout")
def logout():
    session.pop("token", None)
    return redirect(url_for("index"))


@app.route("/attack-demo")
def attack_demo():
    return render_template("attack_demo.html")


@app.route("/api/test", methods=["POST"])
def api_test():
    """Test any input string for SQL injection — used by the live demo page."""
    data  = request.get_json() or {}
    value = data.get("input", "")
    field = data.get("field", "input")

    is_attack, reason = detect(value)
    level = get_attack_level(value) if is_attack else "NONE"

    if is_attack:
        db.log_attack(field, value, level, get_ip())

    return jsonify({
        "input":     value,
        "is_attack": is_attack,
        "reason":    reason if is_attack else "Input is clean ✅",
        "level":     level,
    })


@app.route("/logs")
def logs():
    attack_logs = db.get_attack_logs()
    return render_template("logs.html", logs=attack_logs)


if __name__ == "__main__":
    print("=" * 55)
    print("  CodeAlpha — SQL Injection Defense System")
    print("  Running at: http://127.0.0.1:5000")
    print("=" * 55)
    app.run(debug=True, host="0.0.0.0", port=5000)
