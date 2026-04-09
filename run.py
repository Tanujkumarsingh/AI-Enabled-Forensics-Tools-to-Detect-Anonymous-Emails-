# ============================================================
# FILE: run.py   (root of your project)
# PASTE THIS AS: run.py
# ============================================================

from app.main import create_app
from src.dashboard.history_manager import init_history_table

app = create_app()

if __name__ == "__main__":
    # Create the history table in the database on first run
    init_history_table()
    app.run(debug=True, host="0.0.0.0", port=5000)