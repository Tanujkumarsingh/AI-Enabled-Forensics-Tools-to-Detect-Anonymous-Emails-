# ============================================================
# FILE: src/ml_models/phishing_classifier.py
# PASTE AS: src/ml_models/phishing_classifier.py
# ============================================================
"""
Traditional ML phishing classifier using scikit-learn.
Uses TF-IDF + RandomForest. Falls back to rule-based if model not found.
"""

import os
import re

MODEL_PATH = os.path.join("models", "rf_model.pkl")


class PhishingClassifier:

    def __init__(self):
        self.model      = None
        self.vectorizer = None
        self.loaded     = False
        self._try_load()

    def _try_load(self):
        try:
            import joblib
            if os.path.isfile(MODEL_PATH):
                data            = joblib.load(MODEL_PATH)
                self.model      = data.get("model")
                self.vectorizer = data.get("vectorizer")
                self.loaded     = self.model is not None and self.vectorizer is not None
        except Exception:
            self.loaded = False

    def predict(self, subject: str, body: str, sender: str = "") -> dict:
        """
        Classify email as Phishing or Legitimate.
        Returns { label, confidence, probability, method }
        """
        text = f"{subject} {sender} {body}"
        if self.loaded:
            return self._ml_predict(text)
        return self._rule_based(subject, body, sender)

    def _ml_predict(self, text: str) -> dict:
        try:
            X     = self.vectorizer.transform([text])
            proba = self.model.predict_proba(X)[0]
            label_idx = self.model.predict(X)[0]
            labels    = ["Legitimate", "Phishing"]
            label     = labels[int(label_idx)]
            conf      = round(float(proba[int(label_idx)]), 3)
            return {
                "label":       label,
                "confidence":  conf,
                "probability": round(float(proba[1]), 3),
                "method":      "RandomForest_TFIDF",
            }
        except Exception:
            return self._rule_based("", text, "")

    def _rule_based(self, subject: str, body: str, sender: str) -> dict:
        """Heuristic rule-based fallback classifier."""
        score = 0
        text  = (subject + " " + body + " " + sender).lower()

        STRONG_SIGNALS = [
            "verify your account", "confirm your identity",
            "click here immediately", "suspended account",
            "update your payment", "your account will be closed",
            "unusual sign-in", "login attempt detected",
        ]
        MEDIUM_SIGNALS = [
            "dear customer", "dear user", "you have won",
            "claim your prize", "free gift", "urgent",
            "act now", "limited time", "click here",
        ]

        score += sum(15 for s in STRONG_SIGNALS if s in text)
        score += sum(8  for s in MEDIUM_SIGNALS if s in text)

        if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", body):
            score += 20

        score = min(score, 100)
        label = "Phishing" if score > 40 else "Legitimate"
        conf  = round(min(0.5 + score / 200, 0.95), 3)

        return {
            "label":       label,
            "confidence":  conf,
            "probability": round(score / 100, 3),
            "method":      "rule_based",
        }


_clf_instance = None

def classify_email(subject: str, body: str, sender: str = "") -> dict:
    """Main entry point."""
    global _clf_instance
    if _clf_instance is None:
        _clf_instance = PhishingClassifier()
    return _clf_instance.predict(subject, body, sender)