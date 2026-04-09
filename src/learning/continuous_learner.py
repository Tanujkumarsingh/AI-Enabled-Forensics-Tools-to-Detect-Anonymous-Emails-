"""
============================================================
FILE: src/learning/continuous_learner.py
PASTE AS: src/learning/continuous_learner.py

Self-improving dataset growth + periodic model retraining.

HOW IT WORKS:
─────────────────────────────────────────────────────────
After EVERY analysis (file / manual / dataset batch):

1. AI vs Human result  → appended to datasets/ai_human_training.csv
2. Safe vs Unsafe result (human emails only)
                       → appended to datasets/safe_unsafe_training.csv

Both CSVs grow automatically with every use.

PERIODIC RETRAINING:
  A background thread checks every RETRAIN_INTERVAL_HOURS.
  If enough new rows have been added since the last retrain,
  it retrains both models silently.

  Threshold: RETRAIN_THRESHOLD_NEW_ROWS = 50
  (retrain once 50 new emails have been added)

IMPORTANT:
  - Does NOT change any existing features or routes.
  - Only appends rows. Never deletes or modifies existing data.
  - Models are saved to the same paths routes.py already loads from.
  - Thread-safe: uses a file lock so concurrent requests don't corrupt CSVs.
============================================================
"""

import os
import csv
import json
import time
import logging
import hashlib
import threading
from pathlib import Path
from typing import Optional

log = logging.getLogger("forensiq.continuous_learner")

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR         = Path(__file__).resolve().parents[3]
DATASETS_DIR     = BASE_DIR / "datasets"
MODELS_DIR       = BASE_DIR / "models"
AI_HUMAN_CSV     = DATASETS_DIR / "ai_human_training.csv"
SAFE_UNSAFE_CSV  = DATASETS_DIR / "safe_unsafe_training.csv"
AI_HUMAN_MODEL   = MODELS_DIR  / "rf_ai_human_model.pkl"
SAFE_UNSAFE_MODEL= MODELS_DIR  / "rf_model.pkl"           # same path routes.py reads
RETRAIN_STATE    = DATASETS_DIR / "retrain_state.json"

DATASETS_DIR.mkdir(exist_ok=True)
MODELS_DIR.mkdir(exist_ok=True)

# ── Config ────────────────────────────────────────────────────────────────────
RETRAIN_THRESHOLD_NEW_ROWS = 50      # retrain after this many new rows added
RETRAIN_INTERVAL_HOURS     = 24      # also retrain once per day even if threshold not hit
MIN_ROWS_TO_TRAIN          = 100     # don't attempt training if dataset too small

# ── Thread lock for CSV writes ────────────────────────────────────────────────
_csv_lock = threading.Lock()


# ══════════════════════════════════════════════════════════════════════════════
# STATE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

def _load_state() -> dict:
    if RETRAIN_STATE.exists():
        try:
            return json.loads(RETRAIN_STATE.read_text())
        except Exception:
            pass
    return {
        "ah_rows_at_last_retrain":  0,
        "su_rows_at_last_retrain":  0,
        "last_retrain_ts":          0,
        "ah_total_added":           0,
        "su_total_added":           0,
        "ah_retrain_count":         0,
        "su_retrain_count":         0,
    }


def _save_state(state: dict):
    try:
        RETRAIN_STATE.write_text(json.dumps(state, indent=2))
    except Exception as e:
        log.warning("Could not save retrain state: %s", e)


def get_learning_stats() -> dict:
    """Return stats shown on the dashboard / result page."""
    state = _load_state()
    ah_rows = _count_csv_rows(AI_HUMAN_CSV)
    su_rows = _count_csv_rows(SAFE_UNSAFE_CSV)
    return {
        "ai_human_dataset_size":    ah_rows,
        "safe_unsafe_dataset_size": su_rows,
        "ai_human_retrain_count":   state.get("ah_retrain_count", 0),
        "safe_unsafe_retrain_count":state.get("su_retrain_count", 0),
        "last_retrain_ts":          state.get("last_retrain_ts", 0),
        "last_retrain_human":       _ts_to_human(state.get("last_retrain_ts", 0)),
        "new_since_retrain": {
            "ai_human":    ah_rows - state.get("ah_rows_at_last_retrain", 0),
            "safe_unsafe": su_rows - state.get("su_rows_at_last_retrain", 0),
        },
    }


def _count_csv_rows(path: Path) -> int:
    if not path.exists():
        return 0
    try:
        with path.open("r", encoding="utf-8") as f:
            return sum(1 for _ in f) - 1   # subtract header row
    except Exception:
        return 0


def _ts_to_human(ts: float) -> str:
    if not ts:
        return "Never"
    import datetime
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


# ══════════════════════════════════════════════════════════════════════════════
# APPEND NEW EMAIL TO DATASETS (called after every analysis)
# ══════════════════════════════════════════════════════════════════════════════

def _email_hash(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16]


def _csv_headers(path: Path) -> list:
    """Read header row from existing CSV. Returns [] if file doesn't exist."""
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8") as f:
            reader = csv.reader(f)
            return next(reader, [])
    except Exception:
        return []


def _append_row(path: Path, row: dict, expected_cols: list):
    """Thread-safe append of one row to a CSV file."""
    with _csv_lock:
        file_exists = path.exists()
        with path.open("a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=expected_cols)
            if not file_exists or path.stat().st_size == 0:
                writer.writeheader()
            writer.writerow(row)


AI_HUMAN_COLS    = ["subject", "body", "sender", "label",  "source", "email_hash"]
SAFE_UNSAFE_COLS = ["subject", "body", "sender", "label",  "source", "email_hash"]


def add_to_ai_human_dataset(
    subject:   str,
    body:      str,
    sender:    str,
    ai_label:  str,     # "AI" or "Human"
    source:    str = "live_analysis",
) -> bool:
    """
    Called after every AI vs Human detection.
    Appends the email with its label to the AI/Human training CSV.

    label encoding: 0 = Human, 1 = AI
    Returns True if row was written, False if skipped (duplicate or empty).
    """
    if not body or not body.strip():
        return False

    body_clean = body.strip()[:8000]
    h          = _email_hash(body_clean)

    # Skip if this exact email is already in the dataset
    if _hash_exists(AI_HUMAN_CSV, h):
        log.debug("AI/Human: duplicate email skipped (hash=%s)", h)
        return False

    label = 1 if ai_label == "AI" else 0
    row   = {
        "subject":    (subject or "")[:200],
        "body":       body_clean,
        "sender":     (sender  or "")[:200],
        "label":      label,
        "source":     source,
        "email_hash": h,
    }
    _append_row(AI_HUMAN_CSV, row, AI_HUMAN_COLS)

    # Update state counter
    state = _load_state()
    state["ah_total_added"] = state.get("ah_total_added", 0) + 1
    _save_state(state)

    log.debug("AI/Human dataset: added row (label=%d, hash=%s)", label, h)
    _maybe_trigger_retrain()
    return True


def add_to_safe_unsafe_dataset(
    subject:        str,
    body:           str,
    sender:         str,
    classification: str,    # "Safe" or "Unsafe"
    source:         str = "live_analysis",
) -> bool:
    """
    Called after every Safe/Unsafe classification (human emails only).
    Appends the email with its label to the Safe/Unsafe training CSV.

    label encoding: 0 = Safe/Legitimate, 1 = Unsafe/Phishing
    Returns True if row was written, False if skipped.
    """
    if not body or not body.strip():
        return False
    if classification not in ("Safe", "Unsafe"):
        return False

    body_clean = body.strip()[:8000]
    h          = _email_hash(body_clean)

    if _hash_exists(SAFE_UNSAFE_CSV, h):
        log.debug("Safe/Unsafe: duplicate email skipped (hash=%s)", h)
        return False

    label = 1 if classification == "Unsafe" else 0
    row   = {
        "subject":    (subject or "")[:200],
        "body":       body_clean,
        "sender":     (sender  or "")[:200],
        "label":      label,
        "source":     source,
        "email_hash": h,
    }
    _append_row(SAFE_UNSAFE_CSV, row, SAFE_UNSAFE_COLS)

    state = _load_state()
    state["su_total_added"] = state.get("su_total_added", 0) + 1
    _save_state(state)

    log.debug("Safe/Unsafe dataset: added row (label=%d, hash=%s)", label, h)
    _maybe_trigger_retrain()
    return True


def _hash_exists(path: Path, email_hash: str) -> bool:
    """Check if email_hash already exists in CSV. Reads only the hash column."""
    if not path.exists():
        return False
    try:
        with path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("email_hash") == email_hash:
                    return True
    except Exception:
        pass
    return False


# ══════════════════════════════════════════════════════════════════════════════
# RETRAINING
# ══════════════════════════════════════════════════════════════════════════════

def _maybe_trigger_retrain():
    """
    Check if retraining threshold is met.
    If yes, launch a background thread to retrain without blocking the request.
    """
    state    = _load_state()
    ah_rows  = _count_csv_rows(AI_HUMAN_CSV)
    su_rows  = _count_csv_rows(SAFE_UNSAFE_CSV)
    now      = time.time()

    ah_new   = ah_rows - state.get("ah_rows_at_last_retrain", 0)
    su_new   = su_rows - state.get("su_rows_at_last_retrain", 0)
    hrs_ago  = (now - state.get("last_retrain_ts", 0)) / 3600

    should_retrain = (
        (ah_new >= RETRAIN_THRESHOLD_NEW_ROWS) or
        (su_new >= RETRAIN_THRESHOLD_NEW_ROWS) or
        (hrs_ago >= RETRAIN_INTERVAL_HOURS and (ah_new > 0 or su_new > 0))
    )

    if should_retrain:
        log.info(
            "Retraining triggered — ah_new=%d su_new=%d hrs_since_last=%.1f",
            ah_new, su_new, hrs_ago
        )
        t = threading.Thread(
            target=_retrain_both,
            args=(state, ah_rows, su_rows, now),
            daemon=True,
            name="forensiq_retrain",
        )
        t.start()


def _retrain_both(state: dict, ah_rows: int, su_rows: int, ts: float):
    """Background retraining of both models. Does not block web requests."""
    log.info("Background retraining started ...")

    retrained_any = False

    # ── AI vs Human model ─────────────────────────────────────────────────────
    if ah_rows >= MIN_ROWS_TO_TRAIN and AI_HUMAN_CSV.exists():
        try:
            retrain_ai_human_model()
            state["ah_rows_at_last_retrain"] = ah_rows
            state["ah_retrain_count"]        = state.get("ah_retrain_count", 0) + 1
            retrained_any = True
            log.info("AI/Human model retrained on %d rows", ah_rows)
        except Exception as e:
            log.error("AI/Human retrain failed: %s", e)

    # ── Safe vs Unsafe model ──────────────────────────────────────────────────
    if su_rows >= MIN_ROWS_TO_TRAIN and SAFE_UNSAFE_CSV.exists():
        try:
            retrain_safe_unsafe_model()
            state["su_rows_at_last_retrain"] = su_rows
            state["su_retrain_count"]        = state.get("su_retrain_count", 0) + 1
            retrained_any = True
            log.info("Safe/Unsafe model retrained on %d rows", su_rows)
        except Exception as e:
            log.error("Safe/Unsafe retrain failed: %s", e)

    if retrained_any:
        state["last_retrain_ts"] = ts
        _save_state(state)
        log.info("Background retraining complete.")


def retrain_ai_human_model(
    dataset_path: Optional[str] = None,
    model_out:    Optional[str] = None,
) -> dict:
    """
    Train the AI vs Human RandomForest classifier.
    Uses datasets/ai_human_training.csv by default.
    Saves model to models/rf_ai_human_model.pkl

    Returns evaluation metrics dict.
    """
    import pandas as pd
    import joblib
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score

    csv_path   = Path(dataset_path) if dataset_path else AI_HUMAN_CSV
    model_path = Path(model_out)    if model_out    else AI_HUMAN_MODEL

    df = pd.read_csv(csv_path)
    df = df.dropna(subset=["body", "label"])
    df["text"] = (df["subject"].fillna("") + " " + df["body"].fillna("")).str.strip()
    X = df["text"].values
    y = df["label"].astype(int).values

    log.info("AI/Human training: %d rows | Human=%d AI=%d",
             len(X), (y==0).sum(), (y==1).sum())

    if len(X) < MIN_ROWS_TO_TRAIN:
        raise ValueError(f"Need at least {MIN_ROWS_TO_TRAIN} rows, got {len(X)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    vec = TfidfVectorizer(
        max_features=8000,
        ngram_range=(1, 2),
        stop_words="english",
        sublinear_tf=True,
    )
    X_tr = vec.fit_transform(X_train)
    X_te = vec.transform(X_test)

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",    # handle class imbalance
    )
    clf.fit(X_tr, y_train)
    y_pred = clf.predict(X_te)

    report = classification_report(
        y_test, y_pred,
        target_names=["Human", "AI"],
        output_dict=True,
    )
    acc = round(accuracy_score(y_test, y_pred) * 100, 2)
    log.info("AI/Human model accuracy: %.2f%%", acc)

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": clf, "vectorizer": vec}, model_path)
    log.info("AI/Human model saved to %s", model_path)

    return {
        "accuracy":          acc,
        "classification_report": report,
        "train_size":        len(X_train),
        "test_size":         len(X_test),
        "model_path":        str(model_path),
    }


def retrain_safe_unsafe_model(
    dataset_path: Optional[str] = None,
    model_out:    Optional[str] = None,
) -> dict:
    """
    Train the Safe vs Unsafe RandomForest classifier.
    Uses datasets/safe_unsafe_training.csv by default.
    Saves model to models/rf_model.pkl (same path routes.py already loads from).

    Returns evaluation metrics dict.
    """
    import pandas as pd
    import joblib
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score

    csv_path   = Path(dataset_path) if dataset_path else SAFE_UNSAFE_CSV
    model_path = Path(model_out)    if model_out    else SAFE_UNSAFE_MODEL

    df = pd.read_csv(csv_path)
    df = df.dropna(subset=["body", "label"])
    df["text"] = (
        df["subject"].fillna("") + " " +
        df["body"].fillna("") + " " +
        df["sender"].fillna("")
    ).str.strip()

    X = df["text"].values
    y = df["label"].astype(int).values

    log.info("Safe/Unsafe training: %d rows | Safe=%d Unsafe=%d",
             len(X), (y==0).sum(), (y==1).sum())

    if len(X) < MIN_ROWS_TO_TRAIN:
        raise ValueError(f"Need at least {MIN_ROWS_TO_TRAIN} rows, got {len(X)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    vec = TfidfVectorizer(
        max_features=10000,
        ngram_range=(1, 2),
        stop_words="english",
        sublinear_tf=True,
    )
    X_tr = vec.fit_transform(X_train)
    X_te = vec.transform(X_test)

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )
    clf.fit(X_tr, y_train)
    y_pred = clf.predict(X_te)

    report = classification_report(
        y_test, y_pred,
        target_names=["Safe", "Unsafe"],
        output_dict=True,
    )
    acc = round(accuracy_score(y_test, y_pred) * 100, 2)
    log.info("Safe/Unsafe model accuracy: %.2f%%", acc)

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": clf, "vectorizer": vec}, model_path)
    log.info("Safe/Unsafe model saved to %s", model_path)

    return {
        "accuracy":              acc,
        "classification_report": report,
        "train_size":            len(X_train),
        "test_size":             len(X_test),
        "model_path":            str(model_path),
    }


# ══════════════════════════════════════════════════════════════════════════════
# STARTUP — launch background periodic retraining thread
# ══════════════════════════════════════════════════════════════════════════════

def start_background_retrainer():
    """
    Call this once in app/main.py at startup.
    Runs a daemon thread that checks for retraining every hour.
    """
    def _loop():
        while True:
            try:
                _maybe_trigger_retrain()
            except Exception as e:
                log.error("Background retrainer error: %s", e)
            time.sleep(3600)     # check every hour

    t = threading.Thread(
        target=_loop,
        daemon=True,
        name="forensiq_retrain_scheduler",
    )
    t.start()
    log.info("Background retraining scheduler started (check interval: 1 hour)")