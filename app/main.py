# ============================================================
# FILE: app/main.py
# PASTE THIS AS: app/main.py
# ============================================================

from flask import Flask
import os


def create_app():
    app = Flask(__name__, template_folder="templates")
    app.secret_key = os.environ.get("SECRET_KEY", "forensiq-secret-change-in-production")

    # ── Ensure required folders exist ──────────────────────
    for folder in [
        "data/raw",
        "data/processed",
        "data/attachments",
        "datasets/uploaded_datasets",
        "evidence/metadata",
        "evidence/ips",
        "evidence/urls",
        "evidence/hashes",
        "reports",
        "models",
        "database",
    ]:
        os.makedirs(folder, exist_ok=True)

    # ── Register Blueprints ────────────────────────────────
    from app.routes import bp as main_bp
    app.register_blueprint(main_bp)

    # ── Register Auth Blueprint ────────────────────────────
    try:
        from app.auth import auth_bp
        app.register_blueprint(auth_bp)
    except ImportError:
        pass  # auth module optional

    return app