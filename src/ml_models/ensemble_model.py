# ============================================================
# FILE: src/ml_models/ensemble_model.py
# PASTE AS: src/ml_models/ensemble_model.py
# ============================================================
"""
Ensemble model that combines BERT + RandomForest + rule-based scores
into one final phishing verdict with weighted voting.
"""


def ensemble_predict(subject: str, body: str, sender: str = "") -> dict:
    """
    Run all available classifiers and combine with weighted voting.

    Weights:
      BERT classifier     → 0.50
      RandomForest        → 0.30
      Keyword/rule-based  → 0.20

    Returns { label, confidence, score, votes, method }
    """
    votes  = {}
    scores = {}

    # ── BERT ───────────────────────────────────────────────
    try:
        from src.ml_models.bert_classifier import classify_phishing
        bert_result = classify_phishing(body, subject)
        votes["bert"]  = bert_result.get("label", "Legitimate")
        scores["bert"] = bert_result.get("score", 0.0)
    except Exception:
        votes["bert"]  = "Legitimate"
        scores["bert"] = 0.0

    # ── RandomForest ────────────────────────────────────────
    try:
        from src.ml_models.phishing_classifier import classify_email
        rf_result = classify_email(subject, body, sender)
        votes["rf"]  = rf_result.get("label", "Legitimate")
        scores["rf"] = rf_result.get("probability", 0.0)
    except Exception:
        votes["rf"]  = "Legitimate"
        scores["rf"] = 0.0

    # ── Keyword/Rule ────────────────────────────────────────
    try:
        from src.features.phishing_keywords import score_keywords
        kw = score_keywords(subject + " " + body)
        kw_prob = kw.get("score", 0) / 100
        votes["kw"]  = "Phishing" if kw_prob > 0.4 else "Legitimate"
        scores["kw"] = kw_prob
    except Exception:
        votes["kw"]  = "Legitimate"
        scores["kw"] = 0.0

    # ── Weighted ensemble score ──────────────────────────────
    WEIGHTS = {"bert": 0.50, "rf": 0.30, "kw": 0.20}
    ensemble_score = sum(scores[k] * WEIGHTS[k] for k in WEIGHTS)

    label      = "Phishing" if ensemble_score > 0.45 else "Legitimate"
    confidence = round(
        ensemble_score if label == "Phishing" else (1 - ensemble_score), 3
    )

    return {
        "label":      label,
        "confidence": confidence,
        "score":      round(ensemble_score, 3),
        "votes":      votes,
        "scores":     {k: round(v, 3) for k, v in scores.items()},
        "method":     "ensemble",
    }