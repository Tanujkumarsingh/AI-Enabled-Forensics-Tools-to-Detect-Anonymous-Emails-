"""
============================================================
FILE: src/ml_models/train_model.py
PASTE AS: src/ml_models/train_model.py
(REPLACES the existing train_model.py — all original features kept)

Training pipeline for BOTH classifiers:
  1. AI vs Human detector   → models/rf_ai_human.pkl
  2. Safe vs Unsafe (phishing) → models/rf_model.pkl

Can be trained on:
  - The downloaded base datasets (from dataset_downloader.py)
  - OR merged with the live growth datasets automatically

Usage:
    # Train AI/Human model
    python src/ml_models/train_model.py --ai-human

    # Train phishing model
    python src/ml_models/train_model.py --phishing

    # Train both
    python src/ml_models/train_model.py --all

    # Train on specific CSV (original behaviour preserved)
    python src/ml_models/train_model.py --dataset datasets/phishing_dataset.csv

    # Merge growth data before training
    python src/ml_models/train_model.py --all --merge-growth
============================================================
"""

import os
import sys
import argparse
import logging
from pathlib import Path

log = logging.getLogger("forensiq.train_model")
logging.basicConfig(level=logging.INFO, format="[%(name)s] %(message)s")

BASE_DIR     = Path(__file__).resolve().parent.parent.parent
DATASETS_DIR = BASE_DIR / "datasets"
MODELS_DIR   = BASE_DIR / "models"
MODELS_DIR.mkdir(exist_ok=True)


# ══════════════════════════════════════════════════════════════════════════
# CORE TRAINING FUNCTION  (unchanged from original — preserves existing API)
# ══════════════════════════════════════════════════════════════════════════

def train(dataset_path: str, model_out: str = "models/rf_model.pkl",
          target_names: list = None):
    """
    Train a TF-IDF + RandomForest classifier on a labelled email CSV.
    Preserves the original function signature — no breaking changes.

    Args:
        dataset_path : path to CSV with columns: label, subject, body[, sender]
        model_out    : where to save the .pkl model
        target_names : list of class names for the classification report
    """
    if target_names is None:
        target_names = ["Legitimate", "Phishing"]

    try:
        import pandas as pd
        import joblib
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report, accuracy_score
    except ImportError as e:
        log.error("Missing dependency: %s — run: pip install scikit-learn pandas joblib", e)
        sys.exit(1)

    log.info("Loading dataset: %s", dataset_path)
    df = _load_dataset(dataset_path)

    if df is None or len(df) < 20:
        log.error("Dataset too small or failed to load: %s", dataset_path)
        sys.exit(1)

    log.info("Dataset: %d emails | class breakdown: %s",
             len(df), dict(df["label"].value_counts()))

    X = df["text"].values
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    log.info("Vectorizing with TF-IDF (max_features=10000, ngrams=(1,2))...")
    vectorizer = TfidfVectorizer(
        max_features = 10_000,
        ngram_range  = (1, 2),
        stop_words   = "english",
        sublinear_tf = True,
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec  = vectorizer.transform(X_test)

    log.info("Training RandomForest (200 trees)...")
    clf = RandomForestClassifier(
        n_estimators    = 200,
        max_depth       = None,
        min_samples_split = 2,
        random_state    = 42,
        n_jobs          = -1,
    )
    clf.fit(X_train_vec, y_train)

    y_pred = clf.predict(X_test_vec)
    acc    = accuracy_score(y_test, y_pred)
    log.info("\nEvaluation Report (accuracy=%.3f):", acc)
    print(classification_report(y_test, y_pred,
                                 target_names=target_names,
                                 zero_division=0))

    os.makedirs(os.path.dirname(model_out) or ".", exist_ok=True)

    # Atomic write
    tmp = model_out + ".tmp"
    joblib.dump({"model": clf, "vectorizer": vectorizer}, tmp)
    os.replace(tmp, model_out)
    log.info("Model saved → %s", model_out)
    return {"accuracy": acc, "n_train": len(X_train), "n_test": len(X_test)}


# ══════════════════════════════════════════════════════════════════════════
# DATASET LOADER  (handles both base and merged datasets)
# ══════════════════════════════════════════════════════════════════════════

def _load_dataset(path: str, growth_path: str = None):
    """
    Load a CSV dataset. Optionally merges with a growth CSV.
    Returns a DataFrame with columns: label, text (subject+body combined).
    """
    try:
        import pandas as pd
    except ImportError:
        log.error("pandas not installed")
        return None

    frames = []

    # Load main dataset
    try:
        df = pd.read_csv(path, on_bad_lines="skip", encoding="utf-8")
        frames.append(df)
        log.info("  Loaded base dataset: %d rows", len(df))
    except Exception as e:
        log.error("Failed to load %s: %s", path, e)
        return None

    # Optionally merge growth data
    if growth_path and Path(growth_path).exists():
        try:
            gdf = pd.read_csv(growth_path, on_bad_lines="skip", encoding="utf-8")
            frames.append(gdf)
            log.info("  Merged growth dataset: +%d rows", len(gdf))
        except Exception as e:
            log.warning("Could not merge growth data: %s", e)

    df = pd.concat(frames, ignore_index=True)

    # Detect columns
    label_col   = next((c for c in df.columns if c.lower() in
                        ("label","class","target","is_phishing","spam")), None)
    body_col    = next((c for c in df.columns if c.lower() in
                        ("body","content","text","message","email_text")), None)
    subject_col = next((c for c in df.columns if c.lower() in
                        ("subject","Subject","title")), None)

    if not label_col or not body_col:
        log.error("Dataset must have 'label' and 'body' columns. Found: %s", list(df.columns))
        return None

    # Normalise labels to int
    def normalise_label(v):
        s = str(v).strip().lower()
        if s in ("1","spam","phishing","malicious","ai","true","yes"):
            return 1
        if s in ("0","ham","legitimate","safe","human","false","no"):
            return 0
        return None

    df["label"] = df[label_col].apply(normalise_label)
    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int)

    # Build text feature
    df["text"] = ""
    if subject_col:
        df["text"] += df[subject_col].fillna("").astype(str) + " "
    df["text"] += df[body_col].fillna("").astype(str)

    df = df.dropna(subset=["text"])
    df = df[df["text"].str.len() > 20]

    return df[["label", "text"]]


# ══════════════════════════════════════════════════════════════════════════
# HIGH-LEVEL TRAINERS
# ══════════════════════════════════════════════════════════════════════════

def train_ai_human(merge_growth: bool = False):
    """Train the AI vs Human classifier."""
    base    = str(DATASETS_DIR / "ai_human_dataset.csv")
    growth  = str(DATASETS_DIR / "growth_ai_human.csv") if merge_growth else None
    out     = str(MODELS_DIR / "rf_ai_human.pkl")

    if not Path(base).exists():
        log.error("AI/Human base dataset not found: %s", base)
        log.error("Run first: python src/ml_models/dataset_downloader.py --ai-human")
        return None

    # Use merged _load_dataset via the train() function
    # We temporarily merge into a combined CSV then call train()
    try:
        import pandas as pd
        df = _load_dataset(base, growth)
        if df is None:
            return None

        # Write merged to a temp path and train from it
        tmp = str(DATASETS_DIR / "_tmp_ai_human.csv")
        df.to_csv(tmp, index=False)
        result = train(tmp, out, target_names=["Human", "AI"])
        Path(tmp).unlink(missing_ok=True)
        return result
    except Exception as e:
        log.error("AI/Human training failed: %s", e)
        return None


def train_phishing(merge_growth: bool = False):
    """Train the Safe vs Unsafe phishing classifier."""
    base   = str(DATASETS_DIR / "phishing_dataset.csv")
    growth = str(DATASETS_DIR / "growth_phishing.csv") if merge_growth else None
    out    = str(MODELS_DIR / "rf_model.pkl")

    if not Path(base).exists():
        log.error("Phishing base dataset not found: %s", base)
        log.error("Run first: python src/ml_models/dataset_downloader.py --phishing")
        return None

    try:
        import pandas as pd
        df = _load_dataset(base, growth)
        if df is None:
            return None

        tmp = str(DATASETS_DIR / "_tmp_phishing.csv")
        df.to_csv(tmp, index=False)
        result = train(tmp, out, target_names=["Legitimate", "Phishing"])
        Path(tmp).unlink(missing_ok=True)
        return result
    except Exception as e:
        log.error("Phishing training failed: %s", e)
        return None


# ══════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train ForensIQ ML models",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Download datasets first:
  python src/ml_models/dataset_downloader.py --all

  # Then train both models:
  python src/ml_models/train_model.py --all

  # Train with live growth data merged in:
  python src/ml_models/train_model.py --all --merge-growth

  # Original usage (still works):
  python src/ml_models/train_model.py --dataset datasets/phishing_dataset.csv
        """
    )
    parser.add_argument("--all",          action="store_true", help="Train both models")
    parser.add_argument("--ai-human",     action="store_true", help="Train AI vs Human model only")
    parser.add_argument("--phishing",     action="store_true", help="Train phishing model only")
    parser.add_argument("--merge-growth", action="store_true", help="Merge live growth data before training")
    # Original argument — preserved for backward compatibility
    parser.add_argument("--dataset",  help="Path to labelled CSV (original usage)")
    parser.add_argument("--output",   default="models/rf_model.pkl", help="Output model path")
    args = parser.parse_args()

    # Original single-dataset mode — unchanged behaviour
    if args.dataset:
        train(args.dataset, args.output)
        sys.exit(0)

    ran_something = False

    if args.all or args.ai_human:
        log.info("=" * 60)
        log.info("Training AI vs Human classifier")
        log.info("=" * 60)
        result = train_ai_human(merge_growth=args.merge_growth)
        if result:
            log.info("AI/Human model trained — accuracy=%.3f on %d test samples",
                     result["accuracy"], result["n_test"])
        ran_something = True

    if args.all or args.phishing:
        log.info("=" * 60)
        log.info("Training Safe vs Unsafe (phishing) classifier")
        log.info("=" * 60)
        result = train_phishing(merge_growth=args.merge_growth)
        if result:
            log.info("Phishing model trained — accuracy=%.3f on %d test samples",
                     result["accuracy"], result["n_test"])
        ran_something = True

    if not ran_something:
        parser.print_help()