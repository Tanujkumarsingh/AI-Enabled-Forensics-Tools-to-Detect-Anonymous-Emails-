"""
src/ml_models/train_ai_human.py
==================================
Trains the AI vs Human email detector.

Dataset used (ONLY this one):
  datasets/raw/ai_vs_human/human-llm.zip
  → processed to: datasets/processed/ai_human_training.csv
  → human=0, AI/LLM=1

Pipeline (as specified):
  Input Email
    ↓
  Rule-based features (AI writing patterns — 10 linguistic features)
    ↓
  Classifier (RandomForest trained on human-llm dataset)
    ↓
  Output: AI / Human

Continuous Learning:
  Merges datasets/growth/ai_human_growth.csv if it exists.

Usage:
  python src/ml_models/dataset_downloader.py --ai-human   # first time
  python src/ml_models/train_ai_human.py
  python src/ml_models/train_ai_human.py --retrain        # with growth data
"""

import os, sys, json, logging, argparse, math, re
from pathlib import Path
from collections import Counter

log = logging.getLogger("forensiq.train_ai_human")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

BASE_DIR    = Path(__file__).resolve().parent.parent.parent
PROC_DIR    = BASE_DIR / "datasets" / "processed"
GROWTH_DIR  = BASE_DIR / "datasets" / "growth"
MODELS_DIR  = BASE_DIR / "models"
MODELS_DIR.mkdir(exist_ok=True)

DATASET_PATH = PROC_DIR   / "ai_human_training.csv"
GROWTH_PATH  = GROWTH_DIR / "ai_human_growth.csv"
MODEL_OUT    = MODELS_DIR / "ai_human_model.pkl"
METRICS_OUT  = MODELS_DIR / "ai_human_metrics.json"

# ── Feature names — MUST match human_vs_ai.py ML_FEATURE_ORDER ───────────────
FEATURE_NAMES = [
    "sentence_length_variance",   # 1 — humans vary more
    "vocabulary_richness",         # 2 — TTR
    "ai_phrase_score",             # 3 — AI boilerplate phrases
    "contraction_count",           # 4 — humans use contractions
    "transition_word_ratio",       # 5 — AI overuses transitions
    "informal_word_score",         # 6 — humans use informal words
    "text_entropy",                # 7 — AI = more predictable
    "typo_indicator",              # 8 — humans make small errors
    "emotional_word_count",        # 9 — humans express emotions
    "personal_pronoun_ratio",      # 10 — humans use I/me/my more
]

# ── Word lists (same as human_vs_ai.py) ──────────────────────────────────────
CONTRACTIONS = [
    "don't","can't","won't","it's","i'm","i've","i'll","i'd",
    "you're","you've","you'll","you'd","he's","she's","we're",
    "they're","that's","what's","let's","there's","couldn't",
    "wouldn't","shouldn't","didn't","doesn't","isn't","aren't",
]
AI_PHRASES = [
    "it is important to note","in conclusion","furthermore","moreover",
    "it should be noted","as mentioned above","in summary","to summarize",
    "hope this email finds you well","please do not hesitate",
    "at your earliest convenience","we look forward to","kindly note",
    "rest assured","pursuant to","herewith","going forward",
    "it is imperative","it is critical","we are pleased to inform",
    "as per our records","dear valued customer",
]
TRANSITION_WORDS = [
    "however","therefore","furthermore","consequently","additionally",
    "nevertheless","nonetheless","subsequently","accordingly",
    "alternatively","conversely","henceforth","thereby","hence","thus",
]
INFORMAL_WORDS = [
    "hey","yeah","yep","nope","gonna","wanna","gotta","kinda","sorta",
    "lol","omg","btw","fyi","tbh","imo","ugh","hmm","cool","awesome",
    "dude","okay","ok","nah","meh","totally","literally",
]
EMOTIONAL_WORDS = [
    "love","hate","angry","frustrated","excited","happy","sad","worried",
    "scared","terrified","amazing","awful","terrible","wonderful",
    "fantastic","disappointed","thrilled","devastated","nervous","anxious",
]
PERSONAL_PRONOUNS = {"i","me","my","myself","we","our","us"}


def _tokenize(t: str) -> list:
    return re.findall(r"\b[a-zA-Z']+\b", t.lower())

def _sentences(t: str) -> list:
    return [s.strip() for s in re.split(r"[.!?]+", t) if s.strip()]

def _entropy(words: list) -> float:
    if not words: return 0.0
    freq = Counter(words); total = len(words)
    return -sum((c/total)*math.log2(c/total) for c in freq.values())


def extract_features_batch(texts: list):
    """
    Extract the 10 linguistic rule-based features for a list of texts.
    Returns np.ndarray shape (N, 10).
    Feature order MUST match FEATURE_NAMES and human_vs_ai.py ML_FEATURE_ORDER.
    """
    import numpy as np
    X = []
    for text in texts:
        text  = str(text or "")
        words = _tokenize(text)
        sents = _sentences(text)
        tl    = text.lower()
        n     = max(len(words), 1)

        # 1. sentence_length_variance
        if len(sents) >= 2:
            lens = [len(s.split()) for s in sents]
            mean = sum(lens)/len(lens)
            slv  = math.sqrt(sum((l-mean)**2 for l in lens)/len(lens))
        else:
            slv = 0.0

        # 2. vocabulary_richness (TTR)
        vr = len(set(words)) / n

        # 3. ai_phrase_score
        ai_ps = min(sum(1 for p in AI_PHRASES if p in tl) / 5.0, 1.0)

        # 4. contraction_count
        cc = sum(1 for c in CONTRACTIONS if c in tl)

        # 5. transition_word_ratio
        tw = sum(1 for w in words if w in TRANSITION_WORDS) / n

        # 6. informal_word_score
        iw = sum(1 for w in words if w in INFORMAL_WORDS) / n

        # 7. text_entropy
        te = _entropy(words)

        # 8. typo_indicator (double spaces + punctuation-letter adjacency)
        ti = (len(re.findall(r"  +", text)) +
              len(re.findall(r"[,.!?][A-Za-z]", text)))

        # 9. emotional_word_count
        ew = sum(1 for w in words if w in EMOTIONAL_WORDS)

        # 10. personal_pronoun_ratio
        pp = sum(1 for w in words if w in PERSONAL_PRONOUNS) / n

        X.append([slv, vr, ai_ps, cc, tw, iw, te, ti, ew, pp])

    return np.array(X, dtype=float)


def train(dataset_path: Path, model_out: Path, metrics_out: Path,
          include_growth: bool = True) -> dict:
    try:
        import pandas as pd, numpy as np, joblib
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split, cross_val_score
        from sklearn.metrics import classification_report, accuracy_score
    except ImportError as e:
        log.error("pip install scikit-learn pandas joblib numpy — missing: %s", e)
        sys.exit(1)

    if not dataset_path.exists():
        log.error(
            "Dataset not found: %s\n"
            "Run: python src/ml_models/dataset_downloader.py --ai-human",
            dataset_path)
        sys.exit(1)

    # ── Load ───────────────────────────────────────────────────────────────────
    log.info("Loading: %s", dataset_path)
    df = pd.read_csv(dataset_path)

    if include_growth and GROWTH_PATH.exists():
        gdf    = pd.read_csv(GROWTH_PATH)
        before = len(df)
        df     = pd.concat([df, gdf], ignore_index=True).drop_duplicates(subset=["body"])
        log.info("Merged growth: %d → %d rows (+%d)", before, len(df), len(df)-before)

    df = df.dropna(subset=["body","label"])
    df["label"] = df["label"].astype(int)

    human_n = (df["label"] == 0).sum()
    ai_n    = (df["label"] == 1).sum()
    log.info("Dataset: %d total | %d human | %d AI", len(df), human_n, ai_n)

    if ai_n == 0:
        log.error(
            "No AI-labelled rows! Check human-llm.zip label column.\n"
            "Run: python src/ml_models/dataset_downloader.py --ai-human")
        sys.exit(1)
    if human_n == 0:
        log.error("No Human-labelled rows! Check human-llm.zip label column.")
        sys.exit(1)

    # ── Feature extraction (rule-based linguistic features) ────────────────────
    texts = (df["subject"].fillna("").astype(str) + " " +
             df["body"].fillna("").astype(str)).tolist()
    log.info("Extracting 10 rule-based features from %d emails...", len(texts))
    X = extract_features_batch(texts)
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    # ── Train RandomForest ─────────────────────────────────────────────────────
    log.info("Training RandomForest (200 trees) on %d samples...", len(X_train))
    clf = RandomForestClassifier(
        n_estimators=200, max_depth=None, min_samples_split=2,
        class_weight="balanced", random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    # ── Evaluate ───────────────────────────────────────────────────────────────
    y_pred = clf.predict(X_test)
    acc    = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred,
                                   target_names=["Human","AI"], output_dict=True)
    log.info("\n%s", classification_report(y_test, y_pred, target_names=["Human","AI"]))
    log.info("Test accuracy: %.4f", acc)

    cv = cross_val_score(clf, X, y, cv=5, scoring="accuracy", n_jobs=-1)
    log.info("Cross-val accuracy: %.4f ± %.4f", cv.mean(), cv.std())

    importances = dict(zip(FEATURE_NAMES, clf.feature_importances_.tolist()))
    log.info("Top features:")
    for k, v in sorted(importances.items(), key=lambda x: -x[1])[:5]:
        log.info("  %-32s %.4f", k, v)

    # ── Save ───────────────────────────────────────────────────────────────────
    model_out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "model":         clf,
        "feature_names": FEATURE_NAMES,
        "version":       "2.0",
        "trained_on":    int(len(X_train)),
        "dataset_rows":  int(len(X)),
        "dataset_file":  "human-llm.zip",
    }, model_out)
    log.info("Model saved → %s", model_out)

    metrics = {
        "accuracy":           round(acc, 4),
        "cv_mean":            round(float(cv.mean()), 4),
        "cv_std":             round(float(cv.std()), 4),
        "train_samples":      int(len(X_train)),
        "test_samples":       int(len(X_test)),
        "total_dataset":      int(len(X)),
        "human_count":        int(human_n),
        "ai_count":           int(ai_n),
        "feature_importance": {k: round(v, 4) for k, v in importances.items()},
        "classification_report": report,
        "dataset_used":       "human-llm.zip (Human + LLM Generated Emails)",
    }
    with open(metrics_out, "w") as f:
        json.dump(metrics, f, indent=2)
    log.info("Metrics saved → %s", metrics_out)
    return metrics


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Train AI vs Human email detector")
    p.add_argument("--dataset", default=str(DATASET_PATH))
    p.add_argument("--output",  default=str(MODEL_OUT))
    p.add_argument("--retrain", action="store_true",
                   help="Include continuous learning growth data")
    args = p.parse_args()
    metrics = train(Path(args.dataset), Path(args.output), METRICS_OUT,
                    include_growth=True)
    print(f"\n✓ Training complete — accuracy: {metrics['accuracy']}")
    print(f"  Dataset: {metrics['total_dataset']} rows "
          f"({metrics['human_count']} human, {metrics['ai_count']} AI)")
    print(f"  From: {metrics['dataset_used']}")