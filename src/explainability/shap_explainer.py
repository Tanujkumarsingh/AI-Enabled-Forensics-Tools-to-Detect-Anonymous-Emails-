# ============================================================
# FILE: src/explainability/shap_explainer.py
# PASTE AS: src/explainability/shap_explainer.py
# ============================================================
"""
SHAP-based model explainability for the RandomForest phishing classifier.
Shows which features most influenced the prediction.
"""

import os

MODEL_PATH = os.path.join("models", "rf_model.pkl")


def explain_prediction(subject: str, body: str) -> dict:
    """
    Use SHAP to explain why the model classified this email as phishing/legit.
    Returns { top_features, base_value, shap_values, method }
    """
    try:
        import shap
        import joblib
        import numpy as np

        if not os.path.isfile(MODEL_PATH):
            return _fallback_explanation(subject, body)

        data       = joblib.load(MODEL_PATH)
        model      = data.get("model")
        vectorizer = data.get("vectorizer")

        if not model or not vectorizer:
            return _fallback_explanation(subject, body)

        text    = f"{subject} {body}"
        X       = vectorizer.transform([text])
        X_dense = X.toarray()

        explainer   = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X_dense)

        # shap_values[1] = phishing class
        sv        = shap_values[1][0] if isinstance(shap_values, list) else shap_values[0]
        features  = vectorizer.get_feature_names_out()
        top_idx   = sorted(range(len(sv)), key=lambda i: abs(sv[i]), reverse=True)[:15]

        top_features = [
            {
                "feature": features[i],
                "shap_value": round(float(sv[i]), 4),
                "direction": "phishing" if sv[i] > 0 else "legitimate",
            }
            for i in top_idx
        ]

        return {
            "top_features": top_features,
            "base_value":   round(float(explainer.expected_value[1]) if isinstance(explainer.expected_value, list)
                                  else float(explainer.expected_value), 4),
            "method":       "SHAP_TreeExplainer",
        }

    except ImportError:
        return _fallback_explanation(subject, body)
    except Exception as e:
        return {"error": str(e), "top_features": [], "method": "error"}


def _fallback_explanation(subject: str, body: str) -> dict:
    """Rule-based explanation when SHAP is unavailable."""
    try:
        from src.features.phishing_keywords import score_keywords, PHISHING_KEYWORDS
        text    = (subject + " " + body).lower()
        result  = score_keywords(text)
        matches = result.get("matches", {})

        top_features = []
        for level, words in matches.items():
            for w in words[:5]:
                top_features.append({
                    "feature":    w,
                    "shap_value": {"critical":0.8,"high":0.5,"medium":0.3,"low":0.1}.get(level,0.1),
                    "direction":  "phishing",
                })
        return {
            "top_features": top_features[:15],
            "base_value":   0.0,
            "method":       "keyword_fallback",
        }
    except Exception:
        return {"top_features": [], "base_value": 0.0, "method": "unavailable"}