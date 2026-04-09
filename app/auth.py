# ============================================================
# FILE: app/auth.py
# PASTE THIS AS: app/auth.py
# ============================================================

import sqlite3
import hashlib
import os
from flask import (
    Blueprint, render_template, request,
    redirect, url_for, session, flash
)

auth_bp = Blueprint("auth", __name__)

DB_PATH = os.path.join("database", "users.db")


def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_users_table():
    """Create users table if it doesn't exist."""
    os.makedirs("database", exist_ok=True)
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT NOT NULL UNIQUE,
            email      TEXT NOT NULL UNIQUE,
            password   TEXT NOT NULL,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# ── REGISTER ──────────────────────────────────────────────────────────────────

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    init_users_table()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")

        try:
            conn = _get_conn()
            import datetime
            conn.execute(
                "INSERT INTO users (username, email, password, created_at) VALUES (?, ?, ?, ?)",
                (username, email, _hash_password(password),
                 datetime.datetime.utcnow().isoformat())
            )
            conn.commit()
            conn.close()
            flash("Account created! Please log in.", "success")
            return redirect(url_for("auth.login"))
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "danger")
            return render_template("register.html")

    return render_template("register.html")


# ── LOGIN ─────────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    init_users_table()
    if request.method == "POST":
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        conn = _get_conn()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ? AND password = ?",
            (email, _hash_password(password))
        ).fetchone()
        conn.close()

        if user:
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            session["email"]    = user["email"]
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("main.dashboard"))
        else:
            flash("Invalid email or password.", "danger")

    return render_template("login.html")


# ── LOGOUT ────────────────────────────────────────────────────────────────────

@auth_bp.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))