# ============================================================
# FILE: src/ml_models/safe_unsafe_classifier.py
# PASTE AS: src/ml_models/safe_unsafe_classifier.py
# ============================================================
"""
Safe vs Unsafe Email Classifier
=================================
Pipeline (3 layers):
  Input Email
    ↓
  1. Rule-based features (keyword scoring)        — always runs
    ↓
  2. BERT embeddings (DistilBERT [CLS] token)     — if models/bert_model/ exists
    ↓
  3. RandomForest classifier                       — if models/rf_model.pkl exists
    ↓
  Output: Safe / Unsafe + confidence + risk_score + signals + method

MODEL LOADING RULES:
  rf_model.pkl was saved in one of two modes by train_safe_unsafe.py:
    Mode A: {"model": clf, "mode": "BERT_RandomForest"}              — no vectorizer key
    Mode B: {"model": clf, "mode": "RandomForest_TFIDF",             — has vectorizer key
              "vectorizer": tfidf_vectorizer}

  This classifier handles BOTH formats automatically:
    - If pkl has "vectorizer" → TF-IDF + RF mode
    - If pkl has no "vectorizer" → BERT + RF mode (needs bert_model/ dir)
    - If pkl missing entirely  → rule-based fallback

WHY YOU SEE "RULE_BASED":
  - models/rf_model.pkl does not exist yet
  - Solution: run  python src/ml_models/train_safe_unsafe.py

Hot-swap aware: reloads rf_model.pkl if background retraining updates it.
"""

import os
import re
import logging
from typing import Optional

log = logging.getLogger("forensiq.safe_unsafe")

_HERE         = os.path.dirname(os.path.abspath(__file__))
# Path: src/ml_models/ -> .. -> src/ -> .. -> AI-Email-Forensics/  (2 levels up)
_PROJECT      = os.path.abspath(os.path.join(_HERE, "..", ".."))
RF_MODEL_PATH = os.path.join(_PROJECT, "models", "rf_model.pkl")
BERT_DIR      = os.path.join(_PROJECT, "models", "bert_model")
MAX_BERT_LEN  = 512


# ─────────────────────────────────────────────────────────────────────────────
# RULE-BASED FEATURE SCORER  (runs regardless of ML model availability)
# ─────────────────────────────────────────────────────────────────────────────

STRONG_SIGNALS = [
    ("verify your account",         20, "⚠ Account verification request"),
    ("confirm your identity",       20, "⚠ Identity confirmation request"),
    ("click here immediately",      20, "⚠ Urgency + click CTA"),
    ("suspended account",           18, "⚠ Account suspension threat"),
    ("update your payment",         18, "⚠ Payment update request"),
    ("your account will be closed", 18, "⚠ Account closure threat"),
    ("unusual sign-in",             15, "⚠ Unusual sign-in alert"),
    ("login attempt detected",      15, "⚠ Login attempt alert"),
    ("reset your password",         15, "⚠ Password reset request"),
    ("you have been selected",      15, "⚠ Prize / selection bait"),
    ("winner",                      12, "⚠ Winner claim"),
    ("claim your reward",           15, "⚠ Reward claim"),
    ("your account has been",       15, "⚠ Account action phrase"),
]
MEDIUM_SIGNALS = [
    ("dear customer",    10, "⚡ Generic greeting"),
    ("dear user",        10, "⚡ Generic greeting"),
    ("you have won",     12, "⚡ Prize claim"),
    ("claim your prize", 12, "⚡ Prize claim"),
    ("free gift",         8, "⚡ Free gift offer"),
    ("urgent",            8, "⚡ Urgency language"),
    ("act now",           8, "⚡ Urgency language"),
    ("limited time",      6, "⚡ Time-limited offer"),
    ("click here",        6, "⚡ Generic click CTA"),
    ("lottery",          10, "⚡ Lottery mention"),
    ("congratulations",   5, "⚡ Congratulatory bait"),
    ("bank account",      8, "⚡ Bank mention"),
    ("credit card",       8, "⚡ Credit card mention"),
    ("social security",   8, "⚡ SSN mention"),
    ("western union",    10, "⚡ Wire transfer service"),
]


def _rule_score(subject: str, body: str, sender: str = "") -> tuple:
    """Returns (score 0–100, signals list)."""
    score   = 0
    signals = []
    full    = (subject + " " + body + " " + sender).lower()

    for phrase, pts, sig in STRONG_SIGNALS:
        if phrase in full:
            score += pts
            signals.append(sig)
    for phrase, pts, sig in MEDIUM_SIGNALS:
        if phrase in full:
            score += pts
            signals.append(sig)

    if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", body):
        score += 20
        signals.append("⚠ Raw IP address in URL — phishing indicator")
    if body.count("!") > 5:
        score += 5
        signals.append("⚡ Excessive exclamation marks")
    if len(re.findall(r"\b[A-Z]{4,}\b", body)) > 3:
        score += 5
        signals.append("⚡ Multiple ALL-CAPS words")
    if re.search(r"(password|pin|otp|cvv|ssn|account number).{0,30}"
                 r"(enter|provide|send|confirm)", full):
        score += 20
        signals.append("⚠ Credential harvesting pattern detected")

    if not signals:
        signals.append("✓ No strong phishing signals detected")

    return min(score, 100), signals


# ─────────────────────────────────────────────────────────────────────────────
# CLASSIFIER
# ─────────────────────────────────────────────────────────────────────────────

class SafeUnsafeClassifier:

    def __init__(self):
        # BERT
        self._bert_model     = None
        self._bert_tokenizer = None
        self._bert_loaded    = False

        # RF — can be either TF-IDF mode or BERT-feature mode
        self._rf_model       = None
        self._rf_vectorizer  = None    # present in TF-IDF mode, None in BERT mode
        self._rf_mode        = None    # "RandomForest_TFIDF" | "BERT_RandomForest" | None
        self._rf_loaded      = False
        self._rf_mtime       = 0.0

        self._load_bert()
        self._load_rf()

    # ── BERT loader ───────────────────────────────────────────────────────────

    def _load_bert(self):
        if not os.path.isdir(BERT_DIR):
            log.info("SafeUnsafe: BERT model not found at %s", BERT_DIR)
            return
        try:
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            import torch
            self._bert_tokenizer = AutoTokenizer.from_pretrained(BERT_DIR)
            self._bert_model = AutoModelForSequenceClassification.from_pretrained(BERT_DIR)
            self._bert_model.eval()
            self._bert_loaded = True
            log.info("SafeUnsafe: BERT loaded ✓ from %s", BERT_DIR)
        except Exception as e:
            log.info("SafeUnsafe: BERT load skipped (%s)", e)

    # ── RF loader (handles both pkl formats) ──────────────────────────────────

    def _load_rf(self):
        if not os.path.isfile(RF_MODEL_PATH):
            log.warning(
                "SafeUnsafe: rf_model.pkl NOT FOUND at %s\n"
                "  → Currently using RULE-BASED fallback only.\n"
                "  → To enable ML: run  python src/ml_models/train_safe_unsafe.py",
                RF_MODEL_PATH)
            self._rf_loaded = False
            return
        try:
            import joblib
            data = joblib.load(RF_MODEL_PATH)

            self._rf_model    = data.get("model")
            self._rf_mode     = data.get("mode", "RandomForest_TFIDF")  # default to TFIDF
            self._rf_vectorizer = data.get("vectorizer")   # None if BERT mode

            if self._rf_model is None:
                log.error("SafeUnsafe: rf_model.pkl has no 'model' key — cannot load")
                self._rf_loaded = False
                return

            self._rf_mtime  = os.path.getmtime(RF_MODEL_PATH)
            self._rf_loaded = True

            if self._rf_vectorizer is not None:
                log.info("SafeUnsafe: RF model loaded ✓  mode=RandomForest_TFIDF")
            else:
                log.info("SafeUnsafe: RF model loaded ✓  mode=BERT_RandomForest "
                         "(no vectorizer — uses BERT embeddings)")

        except Exception as e:
            log.error("SafeUnsafe: RF model load failed: %s", e)
            self._rf_loaded = False

    def _maybe_reload_rf(self):
        """Hot-swap: reload if the model file has been updated by background retrain."""
        try:
            if os.path.isfile(RF_MODEL_PATH):
                mtime = os.path.getmtime(RF_MODEL_PATH)
                if mtime != self._rf_mtime:
                    log.info("SafeUnsafe: rf_model.pkl changed — hot-swapping")
                    self._load_rf()
        except OSError:
            pass

    # ── Public predict entry point ────────────────────────────────────────────

    def predict(self, subject: str, body: str, sender: str = "") -> dict:
        """
        Three-layer pipeline:
          1. Rule-based scoring (always)
          2. BERT embeddings (if bert_model/ present)
          3. RF classifier (if rf_model.pkl present)

        Returns: {label, confidence, risk_score, signals, method}
        """
        self._maybe_reload_rf()

        # Layer 1: rule-based (always computed)
        rule_score, rule_signals = _rule_score(subject, body, sender)

        # No ML model at all → rule-based only
        if not self._rf_loaded:
            return self._rule_only(rule_score, rule_signals)

        # Layer 2+3: decide which RF mode to use
        if self._rf_vectorizer is not None:
            # TF-IDF mode: vectorizer is present → use it directly
            return self._tfidf_rf(subject, body, sender, rule_score, rule_signals)
        else:
            # BERT mode: no vectorizer → need BERT embeddings
            if self._bert_loaded:
                return self._bert_rf(subject, body, sender, rule_score, rule_signals)
            else:
                # BERT model pkl loaded but BERT dir missing — fallback to rule-based
                log.warning(
                    "SafeUnsafe: rf_model.pkl was trained in BERT mode but "
                    "models/bert_model/ is not present. "
                    "Retrain without --bert flag to use TF-IDF mode instead.\n"
                    "  Run: python src/ml_models/train_safe_unsafe.py")
                return self._rule_only(rule_score, rule_signals,
                                       extra_note="⚠ BERT model missing — retrain without --bert")

    # ── TF-IDF + RF ───────────────────────────────────────────────────────────

    def _tfidf_rf(self, subject, body, sender, rule_score, rule_signals) -> dict:
        try:
            text      = f"{subject} {sender} {body}"
            X         = self._rf_vectorizer.transform([text])
            proba     = self._rf_model.predict_proba(X)[0]
            label_idx = int(self._rf_model.predict(X)[0])
            label     = "Safe" if label_idx == 0 else "Unsafe"
            conf      = round(float(proba[label_idx]), 3)
            unsafe_p  = round(float(proba[1]), 3)

            # Blend: 70% RF + 30% rule-based
            blended   = (unsafe_p * 0.7) + (rule_score / 100.0 * 0.3)
            risk      = round(blended * 100, 1)
            label     = "Unsafe" if blended > 0.5 else "Safe"

            signals   = rule_signals.copy()
            signals.insert(0,
                f"📊 ML Model (TF-IDF + RandomForest): {label} "
                f"({round(conf*100,1)}% confidence, risk={risk})")

            return {
                "label":      label,
                "confidence": conf,
                "risk_score": risk,
                "signals":    signals,
                "method":     "RandomForest_TFIDF",
            }
        except Exception as e:
            log.warning("TF-IDF RF predict failed: %s — falling back to rule-based", e)
            return self._rule_only(rule_score, rule_signals)

    # ── BERT + RF ──────────────────────────────────────────────────────────────

    def _bert_rf(self, subject, body, sender, rule_score, rule_signals) -> dict:
        try:
            import torch, numpy as np

            text = (subject + " " + body).strip()
            inputs = self._bert_tokenizer(
                text, return_tensors="pt", truncation=True,
                max_length=MAX_BERT_LEN, padding=True)

            with torch.no_grad():
                outputs = self._bert_model(**inputs, output_hidden_states=True)
                cls_emb = outputs.hidden_states[-1][:, 0, :].squeeze().numpy()

            # Append rule score as extra feature (must match training)
            combined = np.concatenate([cls_emb, [rule_score / 100.0]]).reshape(1, -1)

            expected = self._rf_model.n_features_in_
            if combined.shape[1] != expected:
                log.warning("BERT+RF feature mismatch (%d vs %d) — rule-based fallback",
                            combined.shape[1], expected)
                return self._rule_only(rule_score, rule_signals)

            proba     = self._rf_model.predict_proba(combined)[0]
            label_idx = int(self._rf_model.predict(combined)[0])
            label     = "Safe" if label_idx == 0 else "Unsafe"
            conf      = round(float(proba[label_idx]), 3)
            risk      = round(float(proba[1]) * 100, 1)

            signals   = rule_signals.copy()
            signals.insert(0,
                f"🤖 ML Model (BERT + RandomForest): {label} "
                f"({round(conf*100,1)}% confidence, risk={risk})")

            return {
                "label":      label,
                "confidence": conf,
                "risk_score": risk,
                "signals":    signals,
                "method":     "BERT_RandomForest",
            }
        except Exception as e:
            log.warning("BERT+RF predict failed: %s — rule-based fallback", e)
            return self._rule_only(rule_score, rule_signals)

    # ── Rule-based only ───────────────────────────────────────────────────────

    def _rule_only(self, rule_score, rule_signals, extra_note=None) -> dict:
        label = "Unsafe" if rule_score > 40 else "Safe"
        conf  = round(min(0.5 + abs(rule_score - 50) / 100, 0.95), 3)
        signals = rule_signals.copy()
        if extra_note:
            signals.insert(0, extra_note)
        return {
            "label":      label,
            "confidence": conf,
            "risk_score": float(rule_score),
            "signals":    signals,
            "method":     "rule_based",
        }


# ─────────────────────────────────────────────────────────────────────────────
# SINGLETON
# ─────────────────────────────────────────────────────────────────────────────

_clf_instance: Optional[SafeUnsafeClassifier] = None


def classify_safe_unsafe(subject: str, body: str, sender: str = "") -> dict:
    """
    Main entry point. Only call AFTER human_vs_ai detects "Human".

    If you see method="rule_based" it means rf_model.pkl is missing.
    Fix: python src/ml_models/train_safe_unsafe.py
    """
    global _clf_instance
    if _clf_instance is None:
        _clf_instance = SafeUnsafeClassifier()
    return _clf_instance.predict(subject, body, sender)