# ============================================================
# FILE: src/ml_models/bert_classifier.py
# PASTE AS: src/ml_models/bert_classifier.py
# ============================================================
"""
BERT-based phishing email classifier.
Uses a pre-trained DistilBERT model fine-tuned for phishing detection.
Falls back to keyword-based classification if model is not available.
"""

import os

MODEL_DIR = os.path.join("models", "bert_model")


class BERTPhishingClassifier:

    def __init__(self):
        self.model     = None
        self.tokenizer = None
        self.loaded    = False
        self._try_load()

    def _try_load(self):
        """Try to load fine-tuned BERT model. Silently skip if not available."""
        try:
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            import torch
            if os.path.isdir(MODEL_DIR):
                self.tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
                self.model     = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
                self.model.eval()
                self.loaded    = True
        except Exception:
            self.loaded = False

    def predict(self, text: str, subject: str = "") -> dict:
        """
        Classify email as phishing or legitimate.
        Returns { label, confidence, score, method }
        """
        full_text = (subject + " " + text).strip()[:512]

        if self.loaded:
            return self._bert_predict(full_text)
        return self._keyword_fallback(full_text)

    def _bert_predict(self, text: str) -> dict:
        try:
            import torch
            inputs = self.tokenizer(
                text, return_tensors="pt",
                truncation=True, max_length=512, padding=True
            )
            with torch.no_grad():
                outputs = self.model(**inputs)
                probs   = torch.softmax(outputs.logits, dim=-1)[0]
                label_id= torch.argmax(probs).item()
                labels  = ["Legitimate", "Phishing"]
                label   = labels[label_id]
                conf    = round(float(probs[label_id]), 3)
            return {
                "label":      label,
                "confidence": conf,
                "score":      round(float(probs[1]), 3),   # prob of phishing
                "method":     "BERT",
            }
        except Exception as e:
            return self._keyword_fallback(text)

    def _keyword_fallback(self, text: str) -> dict:
        """Simple keyword scoring when BERT model is unavailable."""
        try:
            from src.features.phishing_keywords import score_keywords
            result = score_keywords(text)
            score  = result.get("score", 0)
            label  = "Phishing" if score > 40 else "Legitimate"
            conf   = min(0.5 + score / 200, 0.95)
            return {
                "label":      label,
                "confidence": round(conf, 3),
                "score":      round(score / 100, 3),
                "method":     "keyword_fallback",
            }
        except Exception:
            return {
                "label":      "Unknown",
                "confidence": 0.0,
                "score":      0.0,
                "method":     "error",
            }


# Singleton instance
_bert_instance = None

def classify_phishing(text: str, subject: str = "") -> dict:
    """Main entry point for BERT phishing classification."""
    global _bert_instance
    if _bert_instance is None:
        _bert_instance = BERTPhishingClassifier()
    return _bert_instance.predict(text, subject)