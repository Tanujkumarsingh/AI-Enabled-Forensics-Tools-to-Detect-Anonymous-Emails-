"""
src/ml_models/train_safe_unsafe.py
=====================================
Trains the Safe vs Unsafe (phishing) email classifier.

Datasets used (ONLY these two — no others):
  datasets/raw/phishing/spamassasin.csv    → safe=0
  datasets/raw/phishing/phishing_email.csv → unsafe=1
  datasets/processed/safe_unsafe_training.csv (built by dataset_downloader.py)

Training modes:
  MODE A — BERT + RandomForest (if models/bert_model/ exists):
    1. Extract BERT [CLS] embeddings for each email
    2. Append rule-based score as extra feature
    3. Train RandomForest on (BERT_emb + rule_score) features
    → saves models/rf_model.pkl  (BERT-aware RF)

  MODE B — TF-IDF + RandomForest (default, no BERT needed):
    1. TF-IDF vectorize (10k features, bigrams)
    2. Train RandomForest
    → saves models/rf_model.pkl  (TF-IDF RF)

Continuous Learning:
  Merges datasets/growth/safe_unsafe_growth.csv if it exists.

Usage:
  python src/ml_models/train_safe_unsafe.py           # first time
  python src/ml_models/train_safe_unsafe.py --retrain # with growth data
  python src/ml_models/train_safe_unsafe.py --bert    # BERT+RF mode
"""

import os, sys, json, logging, argparse, re
from pathlib import Path

log = logging.getLogger("forensiq.train_safe_unsafe")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

BASE_DIR     = Path(__file__).resolve().parent.parent.parent
PROC_DIR     = BASE_DIR / "datasets" / "processed"
GROWTH_DIR   = BASE_DIR / "datasets" / "growth"
MODELS_DIR   = BASE_DIR / "models"
MODELS_DIR.mkdir(exist_ok=True)

DATASET_PATH = PROC_DIR    / "safe_unsafe_training.csv"
GROWTH_PATH  = GROWTH_DIR  / "safe_unsafe_growth.csv"
MODEL_OUT    = MODELS_DIR  / "rf_model.pkl"
METRICS_OUT  = MODELS_DIR  / "safe_unsafe_metrics.json"
BERT_DIR     = MODELS_DIR  / "bert_model"


# ── Rule-based score (must match safe_unsafe_classifier.py) ──────────────────

STRONG_KW = [
    "verify your account","confirm your identity","click here immediately",
    "suspended account","update your payment","your account will be closed",
    "unusual sign-in","login attempt detected","reset your password",
    "you have been selected","winner","claim your reward","your account has been",
]
MEDIUM_KW = [
    "dear customer","dear user","you have won","claim your prize","free gift",
    "urgent","act now","limited time","click here","lottery","congratulations",
    "bank account","credit card","social security","western union",
]

def _rule_score(text: str) -> float:
    t = text.lower()
    score = 0
    for kw in STRONG_KW:
        if kw in t: score += 15
    for kw in MEDIUM_KW:
        if kw in t: score += 8
    if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text):
        score += 20
    if re.search(r"(password|pin|otp|cvv).{0,30}(enter|provide|send|confirm)", t):
        score += 20
    return min(score / 100.0, 1.0)


# ── BERT embedding extractor ──────────────────────────────────────────────────

def _bert_embeddings(texts: list, batch_size: int = 16):
    """Extract [CLS] embeddings. Returns np.ndarray shape (N, 768+1)."""
    import torch, numpy as np
    from transformers import AutoTokenizer, AutoModelForSequenceClassification

    log.info("Loading BERT from %s ...", BERT_DIR)
    tokenizer = AutoTokenizer.from_pretrained(str(BERT_DIR))
    model     = AutoModelForSequenceClassification.from_pretrained(
        str(BERT_DIR))
    model.eval()

    all_embs = []
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i+batch_size]
        inp   = tokenizer(batch, return_tensors="pt", truncation=True,
                          max_length=512, padding=True)
        with torch.no_grad():
            out = model(**inp, output_hidden_states=True)
            cls = out.hidden_states[-1][:, 0, :].numpy()   # (batch, 768)
        all_embs.append(cls)
        if (i // batch_size) % 10 == 0:
            log.info("  BERT embeddings: %d / %d", i+len(batch), len(texts))

    embs = np.vstack(all_embs)   # (N, 768)

    # Append rule-based score as extra feature
    rule_scores = np.array([_rule_score(t) for t in texts]).reshape(-1, 1)
    return np.hstack([embs, rule_scores])   # (N, 769)


# ── Train ─────────────────────────────────────────────────────────────────────

def train(dataset_path: Path, model_out: Path, metrics_out: Path,
          include_growth: bool = True, use_bert: bool = False) -> dict:
    try:
        import pandas as pd, numpy as np, joblib
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split, cross_val_score
        from sklearn.metrics import classification_report, accuracy_score
        from sklearn.feature_extraction.text import TfidfVectorizer
    except ImportError as e:
        log.error("pip install scikit-learn pandas joblib numpy — missing: %s", e)
        sys.exit(1)

    if not dataset_path.exists():
        log.error(
            "Dataset not found: %s\n"
            "Run: python src/ml_models/dataset_downloader.py --safe-unsafe",
            dataset_path)
        sys.exit(1)

    # ── Load data ──────────────────────────────────────────────────────────────
    log.info("Loading: %s", dataset_path)
    df = pd.read_csv(dataset_path)

    if include_growth and GROWTH_PATH.exists():
        gdf = pd.read_csv(GROWTH_PATH)
        before = len(df)
        df = pd.concat([df, gdf], ignore_index=True).drop_duplicates(subset=["body"])
        log.info("Merged growth data: %d → %d rows (+%d)",
                 before, len(df), len(df)-before)

    df = df.dropna(subset=["body","label"])
    df["label"] = df["label"].astype(int)

    safe_n   = (df["label"] == 0).sum()
    unsafe_n = (df["label"] == 1).sum()
    log.info("Dataset: %d total | %d safe | %d unsafe", len(df), safe_n, unsafe_n)

    if unsafe_n == 0:
        log.error("No unsafe rows! Run dataset_downloader.py --safe-unsafe first.")
        sys.exit(1)
    if safe_n == 0:
        log.error("No safe rows! Run dataset_downloader.py --safe-unsafe first.")
        sys.exit(1)

    # ── Combine subject + body ─────────────────────────────────────────────────
    subj_col = "subject" if "subject" in df.columns else None
    df["text"] = (
        (df[subj_col].fillna("").astype(str) + " ") if subj_col else ""
    ) + df["body"].fillna("").astype(str)

    texts = df["text"].tolist()
    y     = df["label"].values

    # ── Feature extraction ─────────────────────────────────────────────────────
    if use_bert and BERT_DIR.is_dir():
        log.info("MODE A: BERT embeddings + rule score → RandomForest")
        try:
            X = _bert_embeddings(texts)
            log.info("BERT features shape: %s", X.shape)
            mode = "BERT_RandomForest"
        except Exception as e:
            log.warning("BERT extraction failed (%s) — falling back to TF-IDF", e)
            use_bert = False

    if not use_bert:
        log.info("MODE B: TF-IDF (10k features, bigrams) → RandomForest")
        vectorizer = TfidfVectorizer(
            max_features=10000, ngram_range=(1, 2),
            stop_words="english", sublinear_tf=True, min_df=2, max_df=0.95)
        X    = vectorizer.fit_transform(texts)
        mode = "RandomForest_TFIDF"

    # ── Train / eval ───────────────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    log.info("Training RandomForest (200 trees) on %d samples...",
             X_train.shape[0] if hasattr(X_train,"shape") else len(X_train))

    clf = RandomForestClassifier(
        n_estimators=200, max_depth=None, min_samples_split=2,
        class_weight="balanced", random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc    = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred,
                                   target_names=["Safe","Unsafe"], output_dict=True)
    log.info("\n%s", classification_report(y_test, y_pred, target_names=["Safe","Unsafe"]))
    log.info("Test accuracy: %.4f", acc)

    cv = cross_val_score(clf, X, y, cv=5, scoring="accuracy", n_jobs=-1)
    log.info("Cross-val accuracy: %.4f ± %.4f", cv.mean(), cv.std())

    # ── Save ───────────────────────────────────────────────────────────────────
    save_data = {"model": clf, "mode": mode}
    if not use_bert:
        save_data["vectorizer"] = vectorizer
        # Top TF-IDF features
        feat_names = vectorizer.get_feature_names_out()
        importances= clf.feature_importances_
        top_idx    = importances.argsort()[-10:][::-1]
        top_feats  = {feat_names[i]: round(float(importances[i]),5) for i in top_idx}
        log.info("Top features: %s", top_feats)
    else:
        top_feats = {}

    model_out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(save_data, model_out)
    log.info("Model saved → %s  [mode=%s]", model_out, mode)

    metrics = {
        "accuracy":      round(acc, 4),
        "cv_mean":       round(float(cv.mean()), 4),
        "cv_std":        round(float(cv.std()), 4),
        "train_samples": int(X_train.shape[0]) if hasattr(X_train,"shape") else len(X_train),
        "test_samples":  int(X_test.shape[0])  if hasattr(X_test,"shape")  else len(X_test),
        "total_dataset": int(len(y)),
        "safe_count":    int(safe_n),
        "unsafe_count":  int(unsafe_n),
        "mode":          mode,
        "top_features":  top_feats,
        "classification_report": report,
        "datasets_used": ["spamassasin.csv", "phishing_email.csv"],
    }
    with open(metrics_out, "w") as f:
        json.dump(metrics, f, indent=2)
    log.info("Metrics saved → %s", metrics_out)
    return metrics


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Train Safe vs Unsafe phishing classifier")
    p.add_argument("--dataset", default=str(DATASET_PATH))
    p.add_argument("--output",  default=str(MODEL_OUT))
    p.add_argument("--retrain", action="store_true",
                   help="Include continuous learning growth data")
    p.add_argument("--bert",    action="store_true",
                   help="Use BERT embeddings (requires models/bert_model/)")
    args = p.parse_args()

    metrics = train(
        Path(args.dataset), Path(args.output), METRICS_OUT,
        include_growth=True,
        use_bert=args.bert or BERT_DIR.is_dir()
    )
    print(f"\n✓ Training complete — accuracy: {metrics['accuracy']}")
    print(f"  Mode: {metrics['mode']}")
    print(f"  Dataset: {metrics['total_dataset']} rows "
          f"({metrics['safe_count']} safe, {metrics['unsafe_count']} unsafe)")