import os
# ============================================================
# FILE: src/ml_models/human_vs_ai.py
# PASTE THIS AS: src/ml_models/human_vs_ai.py
# ============================================================
"""
AI-Generated vs Human-Written Email Detector.

Uses 28 linguistic + structural features:
  - Sentence length variance (humans vary more)
  - Vocabulary richness (AI repeats more)
  - AI phrase patterns ("hope this finds you", "furthermore", etc.)
  - Contractions (humans use them, AI often doesn't)
  - Emotional language (humans express feelings)
  - Text entropy (AI = lower, more predictable)
  - Informal words, filler words, typo indicators

Returns:
  {
    "label":       "AI" or "Human",
    "confidence":  0.0 - 1.0,
    "ai_score":    float,
    "human_score": float,
    "signals":     [list of explanation strings],
    "features":    {raw feature values}
  }
"""

import re
import math
import string
from collections import Counter
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────

class HumanVsAIFeatures:

    # Word lists
    CONTRACTIONS = [
        "don't", "can't", "won't", "it's", "i'm", "i've", "i'll", "i'd",
        "you're", "you've", "you'll", "you'd", "he's", "she's", "we're",
        "they're", "that's", "what's", "let's", "there's", "here's",
        "couldn't", "wouldn't", "shouldn't", "didn't", "doesn't", "isn't",
        "aren't", "wasn't", "weren't", "hadn't", "haven't", "hasn't",
        "they've", "we've", "i'd", "you'd", "he'd", "she'd",
    ]

    AI_PHRASES = [
        "it is important to note", "in conclusion", "furthermore", "moreover",
        "it should be noted", "as mentioned above", "in summary", "to summarize",
        "it is worth noting", "in order to", "with respect to", "in terms of",
        "it is essential", "please be advised", "we would like to inform",
        "we are pleased to inform", "as per our records", "kindly note",
        "rest assured", "at your earliest convenience", "please do not hesitate",
        "should you have any questions", "we look forward to",
        "hope this email finds you well", "i hope this message finds you",
        "pursuant to", "herewith", "attached hereto", "as outlined",
        "going forward", "ensure that", "it is imperative", "it is critical",
        "it is crucial", "it is vital", "please note that", "please be aware",
        "we regret to inform", "we are writing to", "dear valued customer",
        "your immediate attention", "action required", "verify your account",
        "confirm your information", "update your details",
    ]

    TRANSITION_WORDS = [
        "however", "therefore", "furthermore", "consequently", "additionally",
        "nevertheless", "nonetheless", "subsequently", "accordingly",
        "alternatively", "conversely", "henceforth", "thereby", "hence",
        "thus", "in addition", "on the other hand", "as a result",
    ]

    HEDGE_WORDS = [
        "perhaps", "possibly", "may", "might", "could", "generally",
        "typically", "usually", "often", "somewhat", "rather", "quite",
        "relatively", "approximately", "arguably", "seemingly", "apparently",
    ]

    INFORMAL_WORDS = [
        "hey", "yeah", "yep", "nope", "gonna", "wanna", "gotta", "kinda",
        "sorta", "lol", "omg", "btw", "fyi", "asap", "tbh", "imo", "imho",
        "ugh", "hmm", "oops", "wow", "cool", "awesome", "dude", "stuff",
        "okay", "ok", "yikes", "nah", "meh", "super", "totally", "literally",
    ]

    FORMAL_WORDS = [
        "therefore", "hence", "thus", "consequently", "subsequently",
        "pursuant", "herewith", "aforementioned", "notwithstanding",
        "heretofore", "wherein", "whereas", "hereby", "therein",
    ]

    EMOTIONAL_WORDS = [
        "love", "hate", "angry", "frustrated", "excited", "happy", "sad",
        "worried", "scared", "terrified", "amazing", "awful", "terrible",
        "wonderful", "horrible", "fantastic", "disappointed", "thrilled",
        "devastated", "overjoyed", "nervous", "anxious", "upset", "furious",
        "delighted", "heartbroken", "shocked", "surprised", "disgusted",
    ]

    FILLER_WORDS = [
        "like", "just", "basically", "literally", "actually", "honestly",
        "seriously", "totally", "really", "very", "so", "well", "right",
    ]

    PERSONAL_PRONOUNS = ["i", "me", "my", "myself", "we", "our", "us"]

    def extract(self, text: str) -> dict:
        if not text or len(text.strip()) < 5:
            return {k: 0 for k in self._feature_keys()}

        sentences = self._split_sentences(text)
        words     = self._tokenize(text)
        word_freq = Counter(words)

        return {
            # Length / Structure
            "char_count":               len(text),
            "word_count":               len(words),
            "sentence_count":           len(sentences),
            "avg_sentence_length":      self._avg_sentence_len(sentences),
            "sentence_length_variance": self._sentence_len_variance(sentences),
            "avg_word_length":          self._avg_word_len(words),
            # Vocabulary
            "vocabulary_richness":      self._vocab_richness(words),
            "unique_word_ratio":        len(set(words)) / max(len(words), 1),
            "repetition_score":         self._repetition_score(word_freq, words),
            # Linguistic style
            "contraction_count":        self._count_contractions(text),
            "exclamation_count":        text.count("!"),
            "question_count":           text.count("?"),
            "ellipsis_count":           text.count("..."),
            "uppercase_ratio":          self._uppercase_ratio(text),
            "punctuation_density":      self._punctuation_density(text),
            # Formality
            "formal_word_score":        self._score_wordlist(words, self.FORMAL_WORDS),
            "informal_word_score":      self._score_wordlist(words, self.INFORMAL_WORDS),
            "passive_voice_count":      self._passive_voice_count(text),
            # AI signals
            "ai_phrase_score":          self._ai_phrase_score(text),
            "transition_word_ratio":    self._transition_ratio(words),
            "hedge_word_count":         self._count_in_text(text, self.HEDGE_WORDS),
            "list_structure_count":     self._list_structure_count(text),
            # Human signals
            "typo_indicator":           self._typo_indicator(text),
            "personal_pronoun_ratio":   self._personal_pronoun_ratio(words),
            "emotional_word_count":     self._count_in_text(text, self.EMOTIONAL_WORDS),
            "filler_word_count":        self._count_in_words(words, self.FILLER_WORDS),
            # Entropy
            "text_entropy":             self._entropy(words),
            "bigram_entropy":           self._bigram_entropy(words),
        }

    # ── Sentence / Word Helpers ───────────────────────────────────────────────

    def _split_sentences(self, text):
        return [s.strip() for s in re.split(r"[.!?]+", text) if s.strip()]

    def _tokenize(self, text):
        return re.findall(r"\b[a-zA-Z']+\b", text.lower())

    def _avg_sentence_len(self, sentences):
        if not sentences: return 0.0
        lens = [len(s.split()) for s in sentences]
        return sum(lens) / len(lens)

    def _sentence_len_variance(self, sentences):
        if len(sentences) < 2: return 0.0
        lens = [len(s.split()) for s in sentences]
        mean = sum(lens) / len(lens)
        return math.sqrt(sum((l - mean)**2 for l in lens) / len(lens))

    def _avg_word_len(self, words):
        if not words: return 0.0
        return sum(len(w) for w in words) / len(words)

    def _vocab_richness(self, words):
        if not words: return 0.0
        return len(set(words)) / len(words)

    def _repetition_score(self, freq, words):
        if not words: return 0.0
        repeated = sum(1 for w, c in freq.items() if c > 2 and len(w) > 4)
        return repeated / max(len(set(words)), 1)

    def _count_contractions(self, text):
        tl = text.lower()
        return sum(1 for c in self.CONTRACTIONS if c in tl)

    def _uppercase_ratio(self, text):
        letters = [c for c in text if c.isalpha()]
        if not letters: return 0.0
        return sum(1 for c in letters if c.isupper()) / len(letters)

    def _punctuation_density(self, text):
        if not text: return 0.0
        return sum(1 for c in text if c in string.punctuation) / len(text)

    def _passive_voice_count(self, text):
        return len(re.findall(r"\b(is|was|were|are|been|be)\s+\w+ed\b", text, re.IGNORECASE))

    def _ai_phrase_score(self, text):
        tl = text.lower()
        count = sum(1 for p in self.AI_PHRASES if p in tl)
        return min(count / 5.0, 1.0)

    def _transition_ratio(self, words):
        if not words: return 0.0
        count = sum(1 for w in words if w in self.TRANSITION_WORDS)
        return count / len(words)

    def _list_structure_count(self, text):
        return sum(1 for line in text.split("\n")
                   if re.match(r"^\s*(\d+[.)]\s|\-\s|\*\s|•\s)", line))

    def _typo_indicator(self, text):
        score  = len(re.findall(r"  +", text))       # double spaces
        score += len(re.findall(r"[,.!?][A-Za-z]", text))  # no space after punct
        return score

    def _personal_pronoun_ratio(self, words):
        if not words: return 0.0
        return sum(1 for w in words if w in self.PERSONAL_PRONOUNS) / len(words)

    def _score_wordlist(self, words, wordlist):
        if not words: return 0.0
        return sum(1 for w in words if w in wordlist) / len(words)

    def _count_in_text(self, text, wordlist):
        tl = text.lower()
        return sum(1 for w in wordlist if w in tl)

    def _count_in_words(self, words, wordlist):
        return sum(1 for w in words if w in wordlist)

    def _entropy(self, words):
        if not words: return 0.0
        freq  = Counter(words)
        total = len(words)
        return -sum((c/total)*math.log2(c/total) for c in freq.values())

    def _bigram_entropy(self, words):
        if len(words) < 2: return 0.0
        bigrams = [(words[i], words[i+1]) for i in range(len(words)-1)]
        freq    = Counter(bigrams)
        total   = len(bigrams)
        return -sum((c/total)*math.log2(c/total) for c in freq.values())

    def _feature_keys(self):
        return [
            "char_count", "word_count", "sentence_count", "avg_sentence_length",
            "sentence_length_variance", "avg_word_length", "vocabulary_richness",
            "unique_word_ratio", "repetition_score", "contraction_count",
            "exclamation_count", "question_count", "ellipsis_count",
            "uppercase_ratio", "punctuation_density", "formal_word_score",
            "informal_word_score", "passive_voice_count", "ai_phrase_score",
            "transition_word_ratio", "hedge_word_count", "list_structure_count",
            "typo_indicator", "personal_pronoun_ratio", "emotional_word_count",
            "filler_word_count", "text_entropy", "bigram_entropy",
        ]


# ─────────────────────────────────────────────────────────────────────────────
# CLASSIFIER
# ─────────────────────────────────────────────────────────────────────────────

class HumanVsAIClassifier:

    def __init__(self, model_path: Optional[str] = None):
        self.extractor = HumanVsAIFeatures()
        self.model     = None
        if model_path:
            self._load_model(model_path)

    def _load_model(self, path: str):
        """
        Load model from pkl.
        train_ai_human.py saves: {"model": clf, "feature_names": [...], ...}
        We need to extract the "model" key.
        """
        try:
            import joblib
            data = joblib.load(path)
            if isinstance(data, dict):
                # New format: {"model": clf, "feature_names": [...]}
                self.model = data.get("model")
                if self.model is None:
                    import logging
                    logging.getLogger("forensiq.human_vs_ai").error(
                        "ai_human_model.pkl has no 'model' key. "
                        "Re-run: python src/ml_models/train_ai_human.py")
            else:
                # Legacy format: pkl is the model object directly
                self.model = data
            if self.model is not None:
                import logging
                logging.getLogger("forensiq.human_vs_ai").info(
                    "AI/Human ML model loaded ✓ from %s", path)
        except Exception as e:
            import logging
            logging.getLogger("forensiq.human_vs_ai").warning(
                "AI/Human model load failed: %s", e)
            self.model = None

    def predict(self, email_text: str, subject: str = "") -> dict:
        full_text = (subject + " " + email_text).strip()
        features  = self.extractor.extract(full_text)
        if self.model:
            return self._ml_predict(features, full_text)
        return self._rule_based(features, full_text)

    # ── Rule-Based Scoring ────────────────────────────────────────────────────

    def _rule_based(self, features: dict, text: str) -> dict:
        ai_score    = 0.0
        human_score = 0.0
        signals     = []

        # ── AI indicators ──────────────────────────────────────────────────────
        if features["ai_phrase_score"] > 0.15:
            ai_score += 25
            signals.append("⚠ Common AI-generated phrases detected (e.g. 'hope this finds you well')")

        if features["sentence_length_variance"] < 3.0 and features["sentence_count"] > 3:
            ai_score += 18
            signals.append("⚠ Uniform sentence lengths — typical of AI writing")

        if features["vocabulary_richness"] < 0.45:
            ai_score += 12
            signals.append("⚠ Low vocabulary diversity — repetitive word usage")

        if features["transition_word_ratio"] > 0.04:
            ai_score += 10
            signals.append("⚠ High frequency of transition words (furthermore, however, therefore)")

        if features["list_structure_count"] > 2:
            ai_score += 10
            signals.append("⚠ Heavy use of numbered/bulleted lists — common AI formatting")

        if features["passive_voice_count"] > 3:
            ai_score += 8
            signals.append("⚠ Frequent passive voice — common in AI-generated text")

        if features["hedge_word_count"] > 4:
            ai_score += 7
            signals.append("⚠ High hedge word usage (perhaps, possibly, generally)")

        if features["text_entropy"] < 4.0 and features["word_count"] > 50:
            ai_score += 10
            signals.append("⚠ Low text entropy — predictable, AI-like word distribution")

        if features["contraction_count"] == 0 and features["word_count"] > 30:
            ai_score += 8
            signals.append("⚠ Zero contractions in long text — overly formal AI style")

        if features["informal_word_score"] < 0.005:
            ai_score += 7
            signals.append("⚠ No informal language detected")

        if features["formal_word_score"] > 0.03:
            ai_score += 5
            signals.append("⚠ High formal vocabulary usage")

        # ── Human indicators ──────────────────────────────────────────────────
        if features["contraction_count"] >= 3:
            human_score += 22
            signals.append("✓ Natural contractions present (don't, I'm, can't)")

        if features["sentence_length_variance"] > 6.0:
            human_score += 18
            signals.append("✓ Natural variation in sentence lengths")

        if features["typo_indicator"] > 1:
            human_score += 15
            signals.append("✓ Minor formatting inconsistencies — human typing pattern")

        if features["exclamation_count"] > 0:
            human_score += 8
            signals.append("✓ Exclamation marks present — emotional expression")

        if features["question_count"] > 1:
            human_score += 7
            signals.append("✓ Multiple questions — natural conversational tone")

        if features["emotional_word_count"] > 2:
            human_score += 14
            signals.append("✓ Emotional vocabulary detected")

        if features["filler_word_count"] > 2:
            human_score += 10
            signals.append("✓ Casual filler words present (just, like, really)")

        if features["personal_pronoun_ratio"] > 0.05:
            human_score += 10
            signals.append("✓ Personal pronoun-heavy writing")

        if features["informal_word_score"] > 0.015:
            human_score += 10
            signals.append("✓ Informal vocabulary detected")

        if features["bigram_entropy"] > 5.0:
            human_score += 10
            signals.append("✓ High bigram entropy — natural, unpredictable phrasing")

        if features["ellipsis_count"] > 0:
            human_score += 5
            signals.append("✓ Ellipsis usage — casual human writing style")

        # ── Final calculation ─────────────────────────────────────────────────
        total      = (ai_score + human_score) or 1
        ai_pct     = round(ai_score    / total, 3)
        human_pct  = round(human_score / total, 3)
        label      = "AI" if ai_pct > human_pct else "Human"
        confidence = max(ai_pct, human_pct)

        # Add summary signal at top
        signals.insert(0,
            f"📊 Score: AI={round(ai_score,1)} pts  Human={round(human_score,1)} pts"
        )

        return {
            "label":       label,
            "confidence":  round(confidence, 3),
            "ai_score":    round(ai_score,    1),
            "human_score": round(human_score, 1),
            "signals":     signals,
            "features":    features,
        }

    # ── ML Model Predict ──────────────────────────────────────────────────────

    def _ml_predict(self, features: dict, text: str) -> dict:
        try:
            import numpy as np
            X = np.array([[
                features["sentence_length_variance"],
                features["vocabulary_richness"],
                features["ai_phrase_score"],
                features["contraction_count"],
                features["transition_word_ratio"],
                features["informal_word_score"],
                features["text_entropy"],
                features["typo_indicator"],
                features["emotional_word_count"],
                features["personal_pronoun_ratio"],
            ]])
            proba      = self.model.predict_proba(X)[0]
            label_idx  = self.model.predict(X)[0]
            label      = "AI" if label_idx == 1 else "Human"
            confidence = round(float(proba[label_idx]), 3)
            result     = self._rule_based(features, text)
            result["label"]      = label
            result["confidence"] = confidence
            return result
        except Exception:
            return self._rule_based(features, text)


# ─────────────────────────────────────────────────────────────────────────────
# CONVENIENCE FUNCTION — call this from routes.py
# ─────────────────────────────────────────────────────────────────────────────

_classifier_instance = None

# Auto-discover the trained AI/Human model if it exists
# Primary model: trained by train_ai_human.py
# rf_ai_human.pkl kept as legacy name fallback
# rf_model.pkl is NOT used — that belongs to Safe/Unsafe classifier only
_AI_HUMAN_MODEL_PATHS = [
    os.path.join("models", "ai_human_model.pkl"),  # ← primary: train_ai_human.py output
    os.path.join("models", "rf_ai_human.pkl"),      # ← legacy name fallback
]

def _find_model() -> Optional[str]:
    for p in _AI_HUMAN_MODEL_PATHS:
        if os.path.isfile(p) and os.path.getsize(p) > 100:  # skip empty/corrupt files
            return p
    return None


def detect_ai_or_human(email_body: str,
                        subject:    str = "",
                        model_path: Optional[str] = None) -> dict:
    """
    Main entry point.
    
    Usage:
        from src.ml_models.human_vs_ai import detect_ai_or_human
        result = detect_ai_or_human(body_text, subject_line)
    
    Returns:
        {
          "label":       "AI" or "Human",
          "confidence":  0.0 - 1.0,
          "ai_score":    float,
          "human_score": float,
          "signals":     [list of explanation strings],
          "features":    {feature name: value, ...}
        }
    """
    global _classifier_instance
    if _classifier_instance is None:
        # Use provided path, then auto-discover trained model, then rule-based only
        resolved_path = model_path or _find_model()
        _classifier_instance = HumanVsAIClassifier(model_path=resolved_path)
    return _classifier_instance.predict(email_body or "", subject or "")