# ============================================================
# FILE: src/ml_models/dataset_growth.py
# PASTE AS: src/ml_models/dataset_growth.py
# ============================================================
"""
Self-Improving Dataset Manager for ForensIQ.
==============================================

After EVERY email analysis, this module:
  1. Appends the processed email (subject + body + label) to a growth CSV.
  2. Checks if the growth threshold has been reached.
  3. If threshold reached AND enough time has passed → triggers background retraining.
  4. The retrained model is hot-swapped — running server picks it up automatically.

TWO separate datasets grow:
  · datasets/growth/ai_human_growth.csv   → fed into train_ai_human.py
  · datasets/growth/safe_unsafe_growth.csv → fed into train_safe_unsafe.py

CONTINUOUS LEARNING:
  · No manual intervention needed.
  · Thread-safe: file-locking prevents concurrent corruption.
  · Hot-swap: classifiers reload automatically when model files change.

Usage (called automatically from routes.py):
    from src.ml_models.dataset_growth import growth_manager

    # After AI vs Human detection:
    growth_manager.add_ai_human(subject, body, ai_label, confidence)

    # After Safe vs Unsafe classification (human emails only):
    growth_manager.add_safe_unsafe(subject, body, classification, risk_score)

    # Get growth statistics:
    stats = growth_manager.get_stats()
"""

import os
import csv
import json
import time
import logging
import threading
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional

log = logging.getLogger("forensiq.dataset_growth")

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent.parent.parent
GROWTH_DIR  = BASE_DIR / "datasets" / "growth"
MODELS_DIR  = BASE_DIR / "models"
GROWTH_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)

# Growth CSV paths
AI_HUMAN_GROWTH_CSV    = GROWTH_DIR / "ai_human_growth.csv"
SAFE_UNSAFE_GROWTH_CSV = GROWTH_DIR / "safe_unsafe_growth.csv"

# Stats / lock files
RETRAIN_LOG_FILE  = GROWTH_DIR / "retrain_log.json"
RETRAIN_LOCK_FILE = GROWTH_DIR / "retrain.lock"

# CSV columns
AI_HUMAN_COLS    = ["timestamp", "subject", "body", "label", "confidence", "source"]
SAFE_UNSAFE_COLS = ["timestamp", "subject", "body", "label", "risk_score", "source"]

# Retraining config
RETRAIN_THRESHOLD  = 100   # retrain every N new rows added
MIN_RETRAIN_HOURS  = 6     # don't retrain more often than this


# ══════════════════════════════════════════════════════════════════════════════
# DATASET GROWTH MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class DatasetGrowthManager:
    """
    Thread-safe manager that appends analyzed emails to growth CSVs
    and triggers background retraining when thresholds are met.
    """

    def __init__(self,
                 retrain_threshold: int   = RETRAIN_THRESHOLD,
                 min_retrain_hours: float = MIN_RETRAIN_HOURS):
        self.threshold         = retrain_threshold
        self.min_retrain_hours = min_retrain_hours
        self._lock             = threading.Lock()
        self._retrain_thread:  Optional[threading.Thread] = None
        self._ensure_csv_headers()

    # ── CSV initialisation ────────────────────────────────────────────────────

    def _ensure_csv_headers(self) -> None:
        """Create growth CSVs with headers if they don't exist."""
        for path, cols in [
            (AI_HUMAN_GROWTH_CSV,    AI_HUMAN_COLS),
            (SAFE_UNSAFE_GROWTH_CSV, SAFE_UNSAFE_COLS),
        ]:
            if not path.exists():
                with open(path, "w", newline="", encoding="utf-8") as f:
                    csv.DictWriter(f, fieldnames=cols).writeheader()
                log.info("Created growth CSV: %s", path)

    # ── Public API ────────────────────────────────────────────────────────────

    def add_ai_human(self,
                     subject:    str,
                     body:       str,
                     ai_label:   str,
                     confidence: float = 0.0,
                     source:     str   = "user_analysis") -> None:
        """
        Append one email result to the AI vs Human growth dataset.

        Args:
            subject:    Email subject
            body:       Email body text
            ai_label:   "AI" or "Human"
            confidence: Classifier confidence (0.0–1.0)
            source:     Where the email came from (file/manual/dataset)
        """
        label_int = 1 if ai_label == "AI" else 0
        row = {
            "timestamp":  datetime.utcnow().isoformat(),
            "subject":    _clean(subject),
            "body":       _clean(body)[:4000],   # cap to 4K chars
            "label":      label_int,
            "confidence": round(float(confidence), 4),
            "source":     source,
        }
        self._append_row(AI_HUMAN_GROWTH_CSV, AI_HUMAN_COLS, row)
        log.debug("AI/Human growth: added %s (conf=%.2f)", ai_label, confidence)
        self._maybe_trigger_retrain("ai_human")

    def add_safe_unsafe(self,
                        subject:        str,
                        body:           str,
                        classification: str,
                        risk_score:     float = 0.0,
                        source:         str   = "user_analysis") -> None:
        """
        Append one email result to the Safe vs Unsafe growth dataset.

        Args:
            subject:        Email subject
            body:           Email body text
            classification: "Safe" or "Unsafe"
            risk_score:     Risk score 0–100
            source:         Where the email came from
        """
        label_int = 1 if classification == "Unsafe" else 0
        row = {
            "timestamp":  datetime.utcnow().isoformat(),
            "subject":    _clean(subject),
            "body":       _clean(body)[:4000],
            "label":      label_int,
            "risk_score": round(float(risk_score), 2),
            "source":     source,
        }
        self._append_row(SAFE_UNSAFE_GROWTH_CSV, SAFE_UNSAFE_COLS, row)
        log.debug("Safe/Unsafe growth: added %s (risk=%.1f)", classification, risk_score)
        self._maybe_trigger_retrain("safe_unsafe")

    def get_stats(self) -> dict:
        """Return current growth dataset statistics."""
        ah_rows = _count_rows(AI_HUMAN_GROWTH_CSV)
        su_rows = _count_rows(SAFE_UNSAFE_GROWTH_CSV)
        log_data = _load_retrain_log()
        return {
            "ai_human_growth_rows":    ah_rows,
            "safe_unsafe_growth_rows": su_rows,
            "last_retrain":            log_data.get("last_retrain", "Never"),
            "total_retrains":          log_data.get("total_retrains", 0),
            "next_retrain_at":         max(0, self.threshold - (ah_rows % self.threshold)),
        }

    # ── Append row ────────────────────────────────────────────────────────────

    def _append_row(self, path: Path, cols: list, row: dict) -> None:
        """Thread-safe CSV append."""
        with self._lock:
            try:
                with open(path, "a", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=cols)
                    writer.writerow(row)
            except Exception as exc:
                log.error("Failed to append to %s: %s", path, exc)

    # ── Retraining trigger ────────────────────────────────────────────────────

    def _maybe_trigger_retrain(self, dataset_type: str) -> None:
        """
        Check if enough new rows exist to warrant retraining.
        If yes, and no retrain is already running, launch a background thread.
        """
        rows = _count_rows(
            AI_HUMAN_GROWTH_CSV if dataset_type == "ai_human" else SAFE_UNSAFE_GROWTH_CSV
        )
        if rows == 0 or rows % self.threshold != 0:
            return  # threshold not yet reached

        # Check time gate
        log_data = _load_retrain_log()
        last_ts  = log_data.get("last_retrain_ts", 0)
        hours_elapsed = (time.time() - last_ts) / 3600
        if hours_elapsed < self.min_retrain_hours:
            log.info(
                "Retrain threshold reached but time gate not cleared "
                "(%.1f / %.1f hrs). Skipping.", hours_elapsed, self.min_retrain_hours
            )
            return

        # Don't spawn duplicate threads
        if self._retrain_thread and self._retrain_thread.is_alive():
            log.info("Retrain already in progress — skipping duplicate.")
            return

        log.info("Retraining triggered for '%s' (%d new rows).", dataset_type, rows)
        self._retrain_thread = threading.Thread(
            target=self._background_retrain,
            args=(dataset_type,),
            daemon=True,
            name=f"forensiq-retrain-{dataset_type}",
        )
        self._retrain_thread.start()

    def _background_retrain(self, dataset_type: str) -> None:
        """Run the appropriate training script in a subprocess."""
        script_map = {
            "ai_human":   str(BASE_DIR / "src" / "ml_models" / "train_ai_human.py"),
            "safe_unsafe": str(BASE_DIR / "src" / "ml_models" / "train_safe_unsafe.py"),
        }
        script = script_map.get(dataset_type)
        if not script or not os.path.isfile(script):
            log.warning("Training script not found: %s", script)
            return

        try:
            result = subprocess.run(
                ["python", script, "--retrain"],
                capture_output=True,
                text=True,
                timeout=600,   # 10-minute max
            )
            if result.returncode == 0:
                log.info("Retrain completed successfully for '%s'.", dataset_type)
                _update_retrain_log(dataset_type)
            else:
                log.error("Retrain failed for '%s':\n%s", dataset_type, result.stderr[-500:])
        except subprocess.TimeoutExpired:
            log.error("Retrain timed out for '%s'.", dataset_type)
        except Exception as exc:
            log.error("Retrain subprocess error for '%s': %s", dataset_type, exc)


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _clean(text: str) -> str:
    """Strip null bytes and excessive whitespace."""
    if not text:
        return ""
    return " ".join(str(text).replace("\x00", "").split())


def _count_rows(path: Path) -> int:
    """Count data rows in a CSV (excluding header)."""
    if not path.exists():
        return 0
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return max(0, sum(1 for _ in f) - 1)   # subtract header
    except Exception:
        return 0


def _load_retrain_log() -> dict:
    if RETRAIN_LOG_FILE.exists():
        try:
            return json.loads(RETRAIN_LOG_FILE.read_text())
        except Exception:
            pass
    return {}


def _update_retrain_log(dataset_type: str) -> None:
    data = _load_retrain_log()
    data["last_retrain"]    = datetime.utcnow().isoformat()
    data["last_retrain_ts"] = time.time()
    data["total_retrains"]  = data.get("total_retrains", 0) + 1
    data[f"last_{dataset_type}_retrain"] = datetime.utcnow().isoformat()
    try:
        RETRAIN_LOG_FILE.write_text(json.dumps(data, indent=2))
    except Exception as exc:
        log.error("Could not update retrain log: %s", exc)


# ══════════════════════════════════════════════════════════════════════════════
# MODULE-LEVEL SINGLETON
# ══════════════════════════════════════════════════════════════════════════════

growth_manager = DatasetGrowthManager()