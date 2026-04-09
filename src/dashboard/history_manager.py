# ============================================================
# FILE: src/dashboard/history_manager.py
# PASTE THIS AS: src/dashboard/history_manager.py
# ============================================================

import sqlite3
import json
import datetime
import os

DB_PATH = os.path.join("database", "users.db")


def _get_conn():
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_history_table():
    """
    Creates the analysis_history table.
    Call this ONCE at app startup in run.py.
    """
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analysis_history (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER NOT NULL,
            analysis_type   TEXT NOT NULL,
            input_summary   TEXT,
            ai_or_human     TEXT,
            classification  TEXT,
            risk_score      REAL,
            sender_email    TEXT,
            ip_address      TEXT,
            result_json     TEXT,
            created_at      TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def save_history(user_id: int,
                 analysis_type: str,
                 input_summary: str,
                 ai_or_human: str,
                 classification: str,
                 risk_score: float,
                 sender_email: str,
                 ip_address: str,
                 result: dict) -> int:
    """Save one analysis record for a user. Returns the new record id."""
    try:
        conn = _get_conn()
        cur  = conn.execute("""
            INSERT INTO analysis_history
                (user_id, analysis_type, input_summary, ai_or_human,
                 classification, risk_score, sender_email, ip_address,
                 result_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            analysis_type,
            input_summary or "",
            ai_or_human   or "",
            classification or "",
            float(risk_score or 0),
            sender_email  or "",
            ip_address    or "",
            json.dumps(result, default=str),
            datetime.datetime.utcnow().isoformat(),
        ))
        conn.commit()
        record_id = cur.lastrowid
        conn.close()
        return record_id
    except Exception as e:
        print(f"[history_manager] save_history error: {e}")
        return -1


def get_user_history(user_id: int, limit: int = 100) -> list:
    """Fetch the latest records for a user. Returns list of dicts."""
    try:
        conn = _get_conn()
        rows = conn.execute("""
            SELECT id, analysis_type, input_summary, ai_or_human,
                   classification, risk_score, sender_email, ip_address, created_at
            FROM analysis_history
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT ?
        """, (user_id, limit)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"[history_manager] get_user_history error: {e}")
        return []


def get_history_detail(record_id: int, user_id: int) -> dict:
    """Fetch full result JSON for one history record (with ownership check)."""
    try:
        conn = _get_conn()
        row  = conn.execute("""
            SELECT * FROM analysis_history
            WHERE id = ? AND user_id = ?
        """, (record_id, user_id)).fetchone()
        conn.close()
        if not row:
            return {}
        data = dict(row)
        try:
            data["result"] = json.loads(data.get("result_json", "{}"))
        except Exception:
            data["result"] = {}
        return data
    except Exception as e:
        print(f"[history_manager] get_history_detail error: {e}")
        return {}


def delete_history_record(record_id: int, user_id: int) -> bool:
    """Delete one record (must belong to the user)."""
    try:
        conn = _get_conn()
        conn.execute(
            "DELETE FROM analysis_history WHERE id = ? AND user_id = ?",
            (record_id, user_id)
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[history_manager] delete error: {e}")
        return False


def clear_user_history(user_id: int) -> bool:
    """Delete all history records for a user."""
    try:
        conn = _get_conn()
        conn.execute("DELETE FROM analysis_history WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[history_manager] clear error: {e}")
        return False


def get_user_stats(user_id: int) -> dict:
    """
    Returns dashboard summary stats:
    { total, ai_count, human_count, safe_count, unsafe_count }
    """
    stats = {
        "total":        0,
        "ai_count":     0,
        "human_count":  0,
        "safe_count":   0,
        "unsafe_count": 0,
    }
    try:
        conn = _get_conn()
        rows = conn.execute("""
            SELECT ai_or_human, classification, COUNT(*) as cnt
            FROM analysis_history
            WHERE user_id = ?
            GROUP BY ai_or_human, classification
        """, (user_id,)).fetchall()
        conn.close()

        for row in rows:
            stats["total"] += row["cnt"]
            if (row["ai_or_human"] or "").upper() == "AI":
                stats["ai_count"] += row["cnt"]
            elif (row["ai_or_human"] or "").upper() == "HUMAN":
                stats["human_count"] += row["cnt"]
            if (row["classification"] or "").lower() == "safe":
                stats["safe_count"] += row["cnt"]
            elif (row["classification"] or "").lower() == "unsafe":
                stats["unsafe_count"] += row["cnt"]
    except Exception as e:
        print(f"[history_manager] get_user_stats error: {e}")

    return stats